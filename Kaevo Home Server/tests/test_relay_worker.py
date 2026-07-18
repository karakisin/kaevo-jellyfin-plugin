import base64
import hashlib
import hmac
import json
from pathlib import Path

import httpx
import pytest

from kaevo_home_server.playback_tunnel import PlaybackGrantVerifier, PlaybackNonceStore
from kaevo_home_server.relay_worker import RelayRequestHandler


KEY = "playback-signing-key-with-at-least-32-characters"
ITEM = "0123456789abcdef0123456789abcdef"


def grant(mode="direct_play"):
    payload = {
        "v": 1, "grant_id": "grant-1", "nonce": f"nonce-{mode}-abcdefghijklmnop", "profile_id": "profile-1",
        "device_id": "device-1", "connector_id": "connector-1", "item_id": ITEM, "media_source_id": "source-1",
        "playback_session_id": "session-1", "mode": mode, "max_bitrate": 10_000_000, "iat": 1000, "nbf": 995, "exp": 1120,
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    payload["home_sig"] = base64.urlsafe_b64encode(hmac.new(KEY.encode(), canonical, hashlib.sha256).digest()).decode().rstrip("=")
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(hmac.new(KEY.encode(), encoded.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    return f"{encoded}.{signature}"


@pytest.mark.asyncio
async def test_direct_stream_keeps_provider_secret_local_and_forwards_range(tmp_path: Path):
    observed = {}

    def provider(request: httpx.Request):
        observed["token"] = request.headers.get("X-Emby-Token")
        observed["range"] = request.headers.get("Range")
        return httpx.Response(206, headers={"Content-Type": "video/mp4", "Content-Range": "bytes 0-3/8"}, content=b"test")

    handler = RelayRequestHandler(
        verifier=PlaybackGrantVerifier(KEY, "connector-1", clock=lambda: 1000),
        nonces=PlaybackNonceStore(tmp_path / "nonce.sqlite3", clock=lambda: 1000),
        jellyfin_base_url="http://jellyfin:8096", jellyfin_api_key="local-secret",
        transport=httpx.MockTransport(provider),
    )
    texts, chunks = [], []
    async def send_text(value): texts.append(value)
    async def send_bytes(value): chunks.append(value)
    await handler.handle({
        "request_id": "00000000-0000-0000-0000-000000000001", "grant": grant(), "method": "GET",
        "path": f"/Videos/{ITEM}/stream", "query": {}, "range": "bytes=0-3",
    }, send_text, send_bytes)
    assert observed == {"token": "local-secret", "range": "bytes=0-3"}
    assert chunks[0][36:] == b"test"
    assert "local-secret" not in "".join(texts)


@pytest.mark.asyncio
async def test_hls_absolute_video_urls_are_rewritten_back_through_relay(tmp_path: Path):
    def provider(_: httpx.Request):
        return httpx.Response(200, headers={"Content-Type": "application/vnd.apple.mpegurl"}, content=f"#EXTM3U\n/Videos/{ITEM}/main.m3u8?x=1\n".encode())

    signed = grant("transcode")
    handler = RelayRequestHandler(
        verifier=PlaybackGrantVerifier(KEY, "connector-1", clock=lambda: 1000),
        nonces=PlaybackNonceStore(tmp_path / "nonce.sqlite3", clock=lambda: 1000),
        jellyfin_base_url="http://jellyfin:8096", jellyfin_api_key="local-secret", transport=httpx.MockTransport(provider),
    )
    texts, chunks = [], []
    async def send_text(value): texts.append(value)
    async def send_bytes(value): chunks.append(value)
    await handler.handle({
        "request_id": "00000000-0000-0000-0000-000000000002", "grant": signed, "method": "GET",
        "path": f"/Videos/{ITEM}/master.m3u8", "query": {},
    }, send_text, send_bytes)
    playlist = chunks[0][36:].decode()
    assert f"/v1/playback/{signed}/Videos/{ITEM}/main.m3u8" in playlist
