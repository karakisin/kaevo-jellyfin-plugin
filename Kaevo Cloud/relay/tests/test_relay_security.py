import asyncio
import base64
import hashlib
import hmac
import json

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.websockets import WebSocketDisconnect

import kaevo_relay.app as relay_module
from kaevo_relay.app import ConnectorChannel, ConnectorRegistry, GrantRegistry
from kaevo_relay.security import verify_signed_token


KEY = "relay-signing-key-with-at-least-thirty-two-characters"


def token(payload):
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(hmac.new(KEY.encode(), encoded.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    return f"{encoded}.{signature}"


def playback_payload():
    return {
        "v": 1,
        "grant_id": "grant-1",
        "profile_id": "profile-1",
        "device_id": "device-1",
        "connector_id": "connector-1",
        "item_id": "0123456789abcdef0123456789abcdef",
        "media_source_id": "source-1",
        "playback_session_id": "session-1",
        "mode": "transcode",
        "max_bitrate": 8_000_000,
        "nbf": 995,
        "exp": 1120,
    }


def test_relay_verifies_signature_and_expiry():
    assert verify_signed_token(token(playback_payload()), KEY, clock=lambda: 1000)["connector_id"] == "connector-1"
    with pytest.raises(ValueError, match="relayTokenExpired"):
        verify_signed_token(token(playback_payload()), KEY, clock=lambda: 1121)
    with pytest.raises(ValueError, match="relayTokenSignatureInvalid"):
        verify_signed_token(token(playback_payload()) + "x", KEY, clock=lambda: 1000)


def test_activated_playback_session_survives_grant_expiry_but_not_idle_limit():
    now = [1000.0]
    registry = GrantRegistry(KEY, clock=lambda: now[0])
    signed = token(playback_payload())
    assert registry.resolve(signed)["mode"] == "transcode"
    now[0] = 1200.0
    assert registry.resolve(signed)["mode"] == "transcode"
    now[0] = 1501.0
    with pytest.raises(ValueError, match="relayPlaybackSessionExpired"):
        registry.resolve(signed)


def test_connector_ticket_cannot_be_used_as_playback_grant():
    registry = GrantRegistry(KEY, clock=lambda: 1000)
    signed = token({"v": 1, "type": "connector_relay", "connector_id": "connector-1", "nbf": 995, "exp": 1100})
    with pytest.raises(ValueError, match="relayPlaybackGrantRequired"):
        registry.resolve(signed)


def test_connector_registry_keeps_parallel_authenticated_channels_stable():
    registry = ConnectorRegistry()
    first = ConnectorChannel(websocket=object())
    second = ConnectorChannel(websocket=object())

    first_id = registry.add("connector-1", first)
    second_id = registry.add("connector-1", second)

    assert registry.channel_count == 2
    selected = registry.get("connector-1")
    assert selected is first or selected is second

    registry.remove("connector-1", first_id)
    assert registry.get("connector-1") is second
    registry.remove("connector-1", second_id)
    assert registry.get("connector-1") is None


def test_connector_registry_prefers_the_least_busy_channel():
    registry = ConnectorRegistry()
    busy = ConnectorChannel(websocket=object(), pending={"request-1": object()})
    available = ConnectorChannel(websocket=object())
    registry.add("connector-1", busy)
    registry.add("connector-1", available)

    assert registry.get("connector-1") is available


class FakeWebSocket:
    def __init__(self, messages):
        self.messages = list(messages)
        self.sent = []

    async def receive(self):
        if self.messages:
            return self.messages.pop(0)
        return {"type": "websocket.disconnect"}

    async def send_text(self, payload):
        self.sent.append(json.loads(payload))


class PlaybackWebSocket:
    def __init__(self):
        self.channel = None
        self.sent = []

    async def send_text(self, payload):
        message = json.loads(payload)
        self.sent.append(message)
        if message.get("type") != "request":
            return
        await self.channel.enqueue(message["request_id"], (
            "response_start",
            {
                "status": 200,
                "headers": {
                    "content-type": "video/mp4",
                    "content-length": "1024",
                    "accept-ranges": "bytes",
                },
            },
        ))


@pytest.mark.asyncio
async def test_connector_reader_acknowledges_an_enqueued_media_chunk():
    request_id = "12345678-1234-1234-1234-123456789012"
    websocket = FakeWebSocket([
        {"type": "websocket.receive", "bytes": request_id.encode() + b"media"},
    ])
    queue = asyncio.Queue(maxsize=1)
    channel = ConnectorChannel(websocket=websocket, pending={request_id: queue})

    with pytest.raises(WebSocketDisconnect):
        await channel.reader()

    assert await queue.get() == ("body", b"media")
    assert websocket.sent == [{"type": "body_ack", "request_id": request_id}]


@pytest.mark.asyncio
async def test_abandoned_full_response_queue_cannot_block_connector_reader():
    request_id = "12345678-1234-1234-1234-123456789012"
    websocket = FakeWebSocket([
        {"type": "websocket.receive", "bytes": request_id.encode() + b"second"},
    ])
    queue = asyncio.Queue(maxsize=1)
    queue.put_nowait(("body", b"first"))
    channel = ConnectorChannel(websocket=websocket, pending={request_id: queue})

    with pytest.raises(WebSocketDisconnect):
        await asyncio.wait_for(channel.reader(), timeout=0.5)

    assert request_id not in channel.pending
    assert await queue.get() == ("error", {"category": "connectorBackpressureExceeded"})
    assert websocket.sent == [{"type": "cancel", "request_id": request_id}]


@pytest.mark.asyncio
async def test_repeated_head_playback_requests_release_connector_slots(monkeypatch):
    websocket = PlaybackWebSocket()
    channel = ConnectorChannel(websocket=websocket)
    websocket.channel = channel
    registry = ConnectorRegistry()
    registry.add("connector-1", channel)

    class StaticGrantRegistry:
        def resolve(self, _token):
            return {"connector_id": "connector-1"}

    monkeypatch.setattr(relay_module, "grants", StaticGrantRegistry())
    monkeypatch.setattr(relay_module, "connectors", registry)

    transport = ASGITransport(app=relay_module.app)
    async with AsyncClient(transport=transport, base_url="https://relay.test") as client:
        for _ in range(20):
            response = await client.head(
                "/v1/playback/grant-token/Videos/0123456789abcdef0123456789abcdef/stream?static=true"
            )
            assert response.status_code == 200
            assert channel.pending == {}

    request_count = sum(message.get("type") == "request" for message in websocket.sent)
    cancel_count = sum(message.get("type") == "cancel" for message in websocket.sent)
    assert request_count == 20
    assert cancel_count == 20


@pytest.mark.asyncio
async def test_connector_wait_allows_a_brief_plugin_reconnect():
    registry = ConnectorRegistry()
    channel = ConnectorChannel(websocket=object())

    async def reconnect():
        await asyncio.sleep(0.02)
        registry.add("connector-1", channel)

    reconnect_task = asyncio.create_task(reconnect())
    selected = await registry.wait_for_available("connector-1", timeout=0.2)
    await reconnect_task

    assert selected is channel


@pytest.mark.asyncio
async def test_connector_wait_remains_bounded_when_plugin_is_offline():
    registry = ConnectorRegistry()
    started = asyncio.get_running_loop().time()

    selected = await registry.wait_for_available("connector-1", timeout=0.03)

    assert selected is None
    assert asyncio.get_running_loop().time() - started < 0.2


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("connector_id", ""),
        ("item_id", "not-a-jellyfin-id"),
        ("max_bitrate", 0),
        ("max_bitrate", 100_000_001),
    ],
)
def test_playback_grant_rejects_missing_or_unbounded_fields(field, value):
    payload = playback_payload()
    payload[field] = value
    registry = GrantRegistry(KEY, clock=lambda: 1000)
    with pytest.raises(ValueError, match="relayPlaybackGrantMalformed"):
        registry.resolve(token(payload))
