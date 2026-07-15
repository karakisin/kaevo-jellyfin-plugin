from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response, StreamingResponse

from .security import verify_signed_token


SIGNING_KEY = os.environ.get("PLAYBACK_GRANT_SIGNING_KEY", "")
MAX_ACTIVE_SECONDS = 12 * 60 * 60
IDLE_SECONDS = 5 * 60
MAX_CHUNK_BYTES = 256 * 1024
MAX_PENDING_PER_CONNECTOR = 16
RESPONSE_QUEUE_MAX_MESSAGES = 8
CONNECTOR_AVAILABILITY_TIMEOUT_SECONDS = 4
RESPONSE_START_TIMEOUT_SECONDS = 25
RESPONSE_BODY_IDLE_TIMEOUT_SECONDS = 60
CONNECTOR_PING_INTERVAL_SECONDS = 20
SAFE_RESPONSE_HEADERS = {"content-type", "content-length", "content-range", "accept-ranges", "cache-control"}
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
SAFE_ITEM_ID = re.compile(r"^[0-9a-f]{32}$")
LOGGER = logging.getLogger("kaevo.relay")


@dataclass
class ActiveGrant:
    payload: dict[str, Any]
    activated_at: float
    last_seen_at: float


class GrantRegistry:
    def __init__(self, signing_key: str, *, clock=time.time):
        self.signing_key = signing_key
        self.clock = clock
        self.active: dict[str, ActiveGrant] = {}

    def resolve(self, token: str) -> dict[str, Any]:
        key = hashlib.sha256(token.encode()).hexdigest()
        now = self.clock()
        active = self.active.get(key)
        if active:
            if now - active.activated_at > MAX_ACTIVE_SECONDS or now - active.last_seen_at > IDLE_SECONDS:
                self.active.pop(key, None)
                raise ValueError("relayPlaybackSessionExpired")
            active.last_seen_at = now
            return active.payload
        payload = verify_signed_token(token, self.signing_key, clock=self.clock)
        if payload.get("mode") not in {"direct_play", "remux", "transcode"}:
            raise ValueError("relayPlaybackGrantRequired")
        identifiers = ("grant_id", "profile_id", "device_id", "connector_id", "media_source_id", "playback_session_id")
        if any(not SAFE_IDENTIFIER.fullmatch(str(payload.get(field) or "")) for field in identifiers):
            raise ValueError("relayPlaybackGrantMalformed")
        if not SAFE_ITEM_ID.fullmatch(str(payload.get("item_id") or "")):
            raise ValueError("relayPlaybackGrantMalformed")
        max_bitrate = payload.get("max_bitrate")
        if isinstance(max_bitrate, bool) or not isinstance(max_bitrate, int) or not 1 <= max_bitrate <= 100_000_000:
            raise ValueError("relayPlaybackGrantMalformed")
        self.active[key] = ActiveGrant(payload=payload, activated_at=now, last_seen_at=now)
        return payload


@dataclass
class ConnectorChannel:
    websocket: WebSocket
    pending: dict[str, asyncio.Queue] = field(default_factory=dict)
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def send_json(self, payload: dict[str, Any]) -> None:
        async with self.send_lock:
            await self.websocket.send_text(json.dumps(payload, separators=(",", ":")))

    async def fail_request(self, request_id: str, category: str, *, notify_connector: bool = True) -> None:
        queue = self.pending.pop(request_id, None)
        if queue is None:
            return
        while not queue.empty():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        queue.put_nowait(("error", {"category": category}))
        if notify_connector:
            try:
                await self.send_json({"type": "cancel", "request_id": request_id})
            except (RuntimeError, WebSocketDisconnect):
                pass

    async def enqueue(self, request_id: str, item: tuple[str, Any], *, acknowledge_body: bool = False) -> None:
        queue = self.pending.get(request_id)
        if queue is None:
            return
        try:
            queue.put_nowait(item)
        except asyncio.QueueFull:
            # Never block the connector reader behind an HTTP viewer that has
            # already gone away. Blocking here prevents every other request,
            # pong, and cancellation on the shared connector socket.
            await self.fail_request(request_id, "connectorBackpressureExceeded")
            return
        if acknowledge_body:
            # New connectors send only one media chunk at a time and wait for
            # this acknowledgement. Older connectors safely fall back to the
            # bounded queue and are cancelled instead of deadlocking it.
            await self.send_json({"type": "body_ack", "request_id": request_id})

    async def reader(self) -> None:
        while True:
            message = await self.websocket.receive()
            if message.get("type") == "websocket.disconnect":
                raise WebSocketDisconnect()
            if message.get("bytes") is not None:
                data = message["bytes"]
                if len(data) < 36 or len(data) - 36 > MAX_CHUNK_BYTES:
                    continue
                request_id = data[:36].decode("ascii", errors="ignore")
                await self.enqueue(request_id, ("body", data[36:]), acknowledge_body=True)
                continue
            raw = message.get("text")
            if not raw:
                continue
            try:
                payload = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if payload.get("type") == "pong":
                continue
            request_id = str(payload.get("request_id") or "")
            await self.enqueue(request_id, (str(payload.get("type") or ""), payload))

    async def heartbeat(self) -> None:
        while True:
            await asyncio.sleep(CONNECTOR_PING_INTERVAL_SECONDS)
            await self.send_json({"type": "ping"})


class ConnectorRegistry:
    def __init__(self):
        self.channels: dict[str, dict[str, ConnectorChannel]] = {}

    def add(self, connector_id: str, channel: ConnectorChannel) -> str:
        channel_id = str(uuid.uuid4())
        self.channels.setdefault(connector_id, {})[channel_id] = channel
        return channel_id

    def remove(self, connector_id: str, channel_id: str) -> None:
        connector_channels = self.channels.get(connector_id)
        if not connector_channels:
            return
        connector_channels.pop(channel_id, None)
        if not connector_channels:
            self.channels.pop(connector_id, None)

    def get(self, connector_id: str) -> ConnectorChannel | None:
        connector_channels = self.channels.get(connector_id)
        if not connector_channels:
            return None
        return min(connector_channels.values(), key=lambda channel: len(channel.pending))

    async def wait_for_available(
        self,
        connector_id: str,
        *,
        timeout: float = CONNECTOR_AVAILABILITY_TIMEOUT_SECONDS,
    ) -> ConnectorChannel | None:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            channel = self.get(connector_id)
            if channel is not None:
                return channel
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            await asyncio.sleep(min(0.05, remaining))

    @property
    def channel_count(self) -> int:
        return sum(len(connector_channels) for connector_channels in self.channels.values())


grants = GrantRegistry(SIGNING_KEY)
connectors = ConnectorRegistry()
app = FastAPI(title="Kaevo Playback Relay", version="0.2.6")


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "state": "ok",
        "service": "kaevo-playback-relay",
        "version": "0.2.6",
        "connectors": len(connectors.channels),
        "channels": connectors.channel_count,
    }


@app.websocket("/v1/connectors/{connector_id}")
async def connector_socket(websocket: WebSocket, connector_id: str) -> None:
    authorization = websocket.headers.get("authorization") or ""
    ticket = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    try:
        payload = verify_signed_token(ticket, SIGNING_KEY)
        if payload.get("type") != "connector_relay" or payload.get("connector_id") != connector_id:
            raise ValueError("relayConnectorTicketMismatch")
    except ValueError:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    channel = ConnectorChannel(websocket)
    channel_id = connectors.add(connector_id, channel)
    try:
        reader = asyncio.create_task(channel.reader())
        heartbeat = asyncio.create_task(channel.heartbeat())
        done, pending = await asyncio.wait({reader, heartbeat}, return_when=asyncio.FIRST_EXCEPTION)
        for task in pending:
            task.cancel()
        for task in done:
            task.result()
    except WebSocketDisconnect as error:
        LOGGER.warning(
            "connector_disconnected connector_id=%s channel_id=%s close_code=%s pending=%s",
            connector_id,
            channel_id,
            getattr(error, "code", None),
            len(channel.pending),
        )
    except asyncio.CancelledError:
        raise
    except Exception as error:
        LOGGER.warning(
            "connector_failed connector_id=%s channel_id=%s category=%s pending=%s",
            connector_id,
            channel_id,
            type(error).__name__,
            len(channel.pending),
        )
    finally:
        connectors.remove(connector_id, channel_id)
        for request_id in list(channel.pending):
            await channel.fail_request(request_id, "connectorDisconnected", notify_connector=False)


@app.api_route("/v1/playback/{grant_token}/Videos/{video_path:path}", methods=["GET", "HEAD"])
async def playback(grant_token: str, video_path: str, request: Request):
    try:
        grant = grants.resolve(grant_token)
    except ValueError as error:
        raise HTTPException(status_code=401, detail=str(error)) from None
    connector_id = str(grant.get("connector_id") or "")
    started_at = time.monotonic()
    channel = await connectors.wait_for_available(connector_id)
    if not channel:
        LOGGER.warning(
            "playback_connector_unavailable connector_id=%s wait_ms=%s",
            connector_id,
            int((time.monotonic() - started_at) * 1000),
        )
        raise HTTPException(status_code=503, detail="connectorUnavailable")
    if len(channel.pending) >= MAX_PENDING_PER_CONNECTOR:
        raise HTTPException(status_code=429, detail="connectorBusy")
    request_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue(maxsize=RESPONSE_QUEUE_MAX_MESSAGES)
    channel.pending[request_id] = queue
    try:
        await channel.send_json({
            "type": "request",
            "request_id": request_id,
            "grant": grant_token,
            "method": request.method,
            "path": f"/Videos/{video_path}",
            "query": dict(request.query_params),
            "range": request.headers.get("range"),
        })
    except (RuntimeError, WebSocketDisconnect):
        channel.pending.pop(request_id, None)
        LOGGER.warning(
            "playback_connector_send_failed connector_id=%s request_id=%s",
            connector_id,
            request_id,
        )
        raise HTTPException(status_code=503, detail="connectorUnavailable") from None
    try:
        kind, start = await asyncio.wait_for(queue.get(), timeout=RESPONSE_START_TIMEOUT_SECONDS)
        if kind != "response_start":
            raise HTTPException(status_code=502, detail="connectorResponseInvalid")
        status = int(start.get("status") or 502)
        LOGGER.info(
            "playback_response_started connector_id=%s request_id=%s status=%s elapsed_ms=%s",
            connector_id,
            request_id,
            status,
            int((time.monotonic() - started_at) * 1000),
        )
        headers = {str(k): str(v) for k, v in (start.get("headers") or {}).items() if str(k).lower() in SAFE_RESPONSE_HEADERS}

        if request.method == "HEAD":
            # ASGI servers suppress HEAD bodies, so a StreamingResponse body
            # iterator may never run. Release the connector slot here instead
            # of relying on the iterator's finally block. AVPlayer performs
            # repeated HEAD probes before its first range request.
            channel.pending.pop(request_id, None)
            try:
                await channel.send_json({"type": "cancel", "request_id": request_id})
            except (RuntimeError, WebSocketDisconnect):
                pass
            return Response(status_code=status, headers=headers)

        async def body() -> AsyncIterator[bytes]:
            try:
                while True:
                    kind, value = await asyncio.wait_for(queue.get(), timeout=RESPONSE_BODY_IDLE_TIMEOUT_SECONDS)
                    if kind == "body":
                        yield value
                    elif kind == "response_end":
                        break
                    elif kind == "error":
                        raise RuntimeError(value.get("category") or "connectorFailed")
            finally:
                channel.pending.pop(request_id, None)
                try:
                    await channel.send_json({"type": "cancel", "request_id": request_id})
                except (RuntimeError, WebSocketDisconnect):
                    pass

        return StreamingResponse(body(), status_code=status, headers=headers)
    except asyncio.TimeoutError:
        channel.pending.pop(request_id, None)
        try:
            await channel.send_json({"type": "cancel", "request_id": request_id})
        except (RuntimeError, WebSocketDisconnect):
            pass
        LOGGER.warning(
            "playback_connector_timed_out connector_id=%s request_id=%s elapsed_ms=%s",
            connector_id,
            request_id,
            int((time.monotonic() - started_at) * 1000),
        )
        raise HTTPException(status_code=504, detail="connectorTimedOut") from None
