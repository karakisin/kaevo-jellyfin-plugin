from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any, Awaitable, Callable

import httpx
import websockets

from .cloud_connector import CloudControlPlaneClient
from .playback_tunnel import PlaybackGrantVerifier, PlaybackNonceStore, PlaybackTunnelSession


SAFE_RESPONSE_HEADERS = {"content-type", "content-length", "content-range", "accept-ranges", "cache-control"}
MAX_PLAYLIST_BYTES = 1_048_576
SendText = Callable[[str], Awaitable[None]]
SendBytes = Callable[[bytes], Awaitable[None]]


class RelayRequestHandler:
    def __init__(
        self,
        *,
        verifier: PlaybackGrantVerifier,
        nonces: PlaybackNonceStore,
        jellyfin_base_url: str,
        jellyfin_api_key: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.verifier = verifier
        self.nonces = nonces
        self.jellyfin_base_url = jellyfin_base_url.rstrip("/")
        self.jellyfin_api_key = jellyfin_api_key
        self.transport = transport
        self.sessions: dict[str, PlaybackTunnelSession] = {}

    def session(self, grant_token: str) -> PlaybackTunnelSession:
        key = hashlib.sha256(grant_token.encode()).hexdigest()
        existing = self.sessions.get(key)
        if existing:
            return existing
        grant = self.verifier.verify(grant_token)
        opened = PlaybackTunnelSession.open(grant_token, self.verifier, self.nonces, device_id=grant.device_id)
        self.sessions[key] = opened
        return opened

    async def handle(self, message: dict[str, Any], send_text: SendText, send_bytes: SendBytes) -> None:
        request_id = str(message.get("request_id") or "")
        try:
            grant_token = str(message.get("grant") or "")
            resolved = self.session(grant_token).resolve(
                str(message.get("method") or "GET"),
                str(message.get("path") or ""),
                message.get("query") if isinstance(message.get("query"), dict) else {},
                range_header=str(message.get("range")) if message.get("range") else None,
            )
            headers = {**resolved.headers, "X-Emby-Token": self.jellyfin_api_key, "Accept": "*/*"}
            async with httpx.AsyncClient(transport=self.transport, timeout=None, follow_redirects=False) as client:
                async with client.stream(
                    resolved.method,
                    f"{self.jellyfin_base_url}{resolved.path}",
                    params=resolved.query,
                    headers=headers,
                ) as response:
                    safe_headers = {
                        key: value for key, value in response.headers.items()
                        if key.lower() in SAFE_RESPONSE_HEADERS
                    }
                    is_playlist = resolved.path.endswith(".m3u8")
                    if is_playlist:
                        safe_headers.pop("content-length", None)
                    await send_text(json.dumps({
                        "type": "response_start", "request_id": request_id,
                        "status": response.status_code, "headers": safe_headers,
                    }, separators=(",", ":")))
                    if is_playlist:
                        body = await response.aread()
                        if len(body) > MAX_PLAYLIST_BYTES:
                            raise ValueError("playlistTooLarge")
                        text = body.decode("utf-8")
                        prefix = f"/v1/playback/{grant_token}"
                        rewritten = "\n".join(
                            f"{prefix}{line}" if line.startswith("/Videos/") else line
                            for line in text.splitlines()
                        )
                        await send_bytes(request_id.encode("ascii") + rewritten.encode("utf-8"))
                    else:
                        async for chunk in response.aiter_bytes(256 * 1024):
                            await send_bytes(request_id.encode("ascii") + chunk)
            await send_text(json.dumps({"type": "response_end", "request_id": request_id}, separators=(",", ":")))
        except asyncio.CancelledError:
            raise
        except Exception as error:
            category = str(error) if isinstance(error, ValueError) else "jellyfinPlaybackFailed"
            await send_text(json.dumps({"type": "error", "request_id": request_id, "category": category}, separators=(",", ":")))


class RelayConnectorWorker:
    def __init__(self, *, cloud: CloudControlPlaneClient, relay_websocket_url: str, handler: RelayRequestHandler):
        self.cloud = cloud
        self.relay_websocket_url = relay_websocket_url.rstrip("/")
        self.handler = handler

    async def run_once(self) -> None:
        ticket = await self.cloud.relay_ticket()
        relay_ticket = ticket["relay_ticket"]
        url = f"{self.relay_websocket_url}/v1/connectors/{self.cloud.connector_id}"
        async with websockets.connect(url, extra_headers={"Authorization": f"Bearer {relay_ticket}"}, max_size=1_048_576) as socket:
            tasks: dict[str, asyncio.Task] = {}
            send_lock = asyncio.Lock()

            async def send_text(value: str) -> None:
                async with send_lock:
                    await socket.send(value)

            async def send_bytes(value: bytes) -> None:
                async with send_lock:
                    await socket.send(value)

            async for raw in socket:
                if not isinstance(raw, str):
                    continue
                message = json.loads(raw)
                request_id = str(message.get("request_id") or "")
                if message.get("type") == "request" and request_id:
                    task = asyncio.create_task(self.handler.handle(message, send_text, send_bytes))
                    tasks[request_id] = task
                    task.add_done_callback(lambda _, key=request_id: tasks.pop(key, None))
                elif message.get("type") == "cancel":
                    task = tasks.get(request_id)
                    if task:
                        task.cancel()

    async def run_forever(self) -> None:
        delay = 1
        while True:
            try:
                await self.run_once()
                delay = 1
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)
