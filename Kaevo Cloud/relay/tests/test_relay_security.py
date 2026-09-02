import asyncio
import base64
import hashlib
import hmac
import json
import time

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.websockets import WebSocketDisconnect

import kaevo_relay.app as relay_module
from kaevo_relay.app import (
    ConnectorChannel,
    ConnectorRegistry,
    FamilySyncChannel,
    FamilySyncRegistry,
    GrantRegistry,
    MAX_CHUNK_BYTES,
    authorize_playback_video_path,
    grant_token_from_path,
    rewrite_hls_playlist,
    split_grant_token,
    validate_family_sync_ticket,
)
from kaevo_relay.security import verify_signed_token


KEY = "relay-signing-key-with-at-least-thirty-two-characters"
ORIGIN_KEY = "cloudfront-origin-secret-with-at-least-thirty-two-characters"
ORIGIN_HEADERS = {"X-Kaevo-Origin-Auth": ORIGIN_KEY}


@pytest.fixture(autouse=True)
def configured_origin_secret(monkeypatch):
    monkeypatch.setattr(relay_module, "ORIGIN_AUTH_SECRET", ORIGIN_KEY)


def token(payload):
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(hmac.new(KEY.encode(), encoded.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    return f"{encoded}.{signature}"


@pytest.mark.asyncio
async def test_direct_http_origin_is_denied_and_health_is_minimal():
    transport = ASGITransport(app=relay_module.app)
    async with AsyncClient(transport=transport, base_url="https://relay.test") as client:
        denied = await client.get("/v1/playback/not-a-grant/Videos/not-an-item/stream")
        health = await client.get("/health")

    assert denied.status_code == 403
    assert denied.headers["cache-control"] == "no-store"
    assert health.status_code == 200
    assert set(health.json()) == {"state", "service", "version"}


@pytest.mark.asyncio
async def test_valid_origin_header_reaches_grant_authorization():
    transport = ASGITransport(app=relay_module.app)
    async with AsyncClient(transport=transport, base_url="https://relay.test") as client:
        response = await client.get(
            "/v1/playback/not-a-grant/Videos/not-an-item/stream",
            headers=ORIGIN_HEADERS,
        )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_direct_connector_websocket_origin_is_denied_before_ticket_validation():
    class DirectWebSocket:
        headers = {}

        def __init__(self):
            self.close_code = None

        async def close(self, code):
            self.close_code = code

    websocket = DirectWebSocket()
    await relay_module.connector_socket(websocket, "connector-1")
    assert websocket.close_code == 4403


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
        "trickplay": {
            "width": 320,
            "height": 180,
            "tile_width": 10,
            "tile_height": 10,
            "thumbnail_count": 40,
            "interval": 10000,
        },
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


def test_guest_hard_stop_remains_enforced_after_grant_activation():
    now = [1000.0]
    registry = GrantRegistry(KEY, clock=lambda: now[0])
    payload = playback_payload()
    payload["active_until"] = 1060
    signed = token(payload)
    assert registry.resolve(signed)["mode"] == "transcode"
    now[0] = 1059.0
    assert registry.touch(signed)["mode"] == "transcode"
    now[0] = 1060.0
    with pytest.raises(ValueError, match="relayPlaybackSessionExpired"):
        registry.touch(signed)


def test_active_direct_stream_touch_keeps_trickplay_authorization_alive():
    now = [1000.0]
    registry = GrantRegistry(KEY, clock=lambda: now[0])
    payload = playback_payload()
    payload["mode"] = "direct_play"
    signed = token(payload)
    assert registry.resolve(signed)["mode"] == "direct_play"

    for timestamp in (1200.0, 1400.0, 1600.0):
        now[0] = timestamp
        assert registry.touch(signed)["mode"] == "direct_play"

    now[0] = 1601.0
    assert registry.resolve(signed)["mode"] == "direct_play"


def test_connector_ticket_cannot_be_used_as_playback_grant():
    registry = GrantRegistry(KEY, clock=lambda: 1000)
    signed = token({"v": 1, "type": "connector_relay", "connector_id": "connector-1", "nbf": 995, "exp": 1100})
    with pytest.raises(ValueError, match="relayPlaybackGrantRequired"):
        registry.resolve(signed)


def test_playback_path_is_bound_to_exact_item_and_sprite_geometry():
    grant = playback_payload()
    item_id = grant["item_id"]
    authorize_playback_video_path(grant, f"{item_id}/master.m3u8")
    authorize_playback_video_path(grant, f"{item_id}/Trickplay/320/tiles.m3u8")
    authorize_playback_video_path(grant, f"{item_id}/Trickplay/320/0.jpg")
    with pytest.raises(ValueError, match="playbackItemMismatch"):
        authorize_playback_video_path(grant, f"{'f' * 32}/master.m3u8")
    with pytest.raises(ValueError, match="playbackTrickplayNotAuthorized"):
        authorize_playback_video_path(grant, f"{item_id}/Trickplay/640/0.jpg")
    with pytest.raises(ValueError, match="playbackTrickplayNotAuthorized"):
        authorize_playback_video_path(grant, f"{item_id}/Trickplay/320/video.ts")
    with pytest.raises(ValueError, match="playbackTrickplayNotAuthorized"):
        authorize_playback_video_path(grant, f"{item_id}/Trickplay/320/1.jpg")


def family_sync_claims(*, role, profile_id="profile-1"):
    claims = {
        "v": 1,
        "type": "family_sync_live",
        "role": role,
        "profile_id": profile_id,
        "household_id": "household-1",
        "installation_id": f"installation-{profile_id}",
        "nbf": 995,
        "exp": 1120,
    }
    if role == "publisher":
        claims.update({
            "provider": "jellyfin",
            "item_id": "0123456789abcdef0123456789abcdef",
            "media_type": "movie",
            "session_id": "session-1",
            "session_started_at_epoch_milliseconds": 1_000_000,
            "allowed_profile_ids": ["profile-1", "profile-2"],
            "audience_profile_ids": ["profile-1", "profile-2"],
        })
    return claims


def test_family_sync_ticket_is_distinct_from_connector_and_playback_grants(monkeypatch):
    monkeypatch.setattr(relay_module, "SIGNING_KEY", KEY)
    current = int(time.time())
    live_claims = {**family_sync_claims(role="publisher"), "nbf": current - 5, "exp": current + 120}
    claims = validate_family_sync_ticket(token(live_claims))
    assert claims["role"] == "publisher"
    with pytest.raises(ValueError, match="familySyncLiveTicketRequired"):
        validate_family_sync_ticket(token({**playback_payload(), "nbf": current - 5, "exp": current + 120}))


class LiveObserverWebSocket:
    def __init__(self):
        self.sent = []

    async def send_text(self, payload):
        self.sent.append(json.loads(payload))


@pytest.mark.asyncio
async def test_family_sync_fanout_filters_exact_audience_and_rejects_old_owner():
    now = [1000.0]
    registry = FamilySyncRegistry(clock=lambda: now[0])
    publisher = FamilySyncChannel(websocket=LiveObserverWebSocket(), claims=family_sync_claims(role="publisher"))
    first_socket = LiveObserverWebSocket()
    second_socket = LiveObserverWebSocket()
    unrelated_socket = LiveObserverWebSocket()
    registry.add(FamilySyncChannel(websocket=first_socket, claims=family_sync_claims(role="observer", profile_id="profile-1")))
    registry.add(FamilySyncChannel(websocket=second_socket, claims=family_sync_claims(role="observer", profile_id="profile-2")))
    registry.add(FamilySyncChannel(websocket=unrelated_socket, claims={
        **family_sync_claims(role="observer", profile_id="profile-3"),
        "household_id": "household-2",
    }))
    message = {
        "type": "progress",
        "sequence": 2,
        "position_seconds": 12.5,
        "runtime_seconds": 7200,
        "selected_viewer_profile_ids": ["profile-1", "profile-2"],
        "departed_viewer_profile_ids": [],
        "playback_state": "active",
    }

    assert await registry.publish(publisher, message) == 2
    assert first_socket.sent[0]["source_profile_id"] == "profile-1"
    assert second_socket.sent[0]["viewer_profile_ids"] == ["profile-1", "profile-2"]
    assert unrelated_socket.sent == []

    # Same-session and older-session packets cannot roll either observer back.
    assert await registry.publish(publisher, {**message, "sequence": 1}) == 0
    older = FamilySyncChannel(websocket=LiveObserverWebSocket(), claims={
        **family_sync_claims(role="publisher"),
        "session_started_at_epoch_milliseconds": 999_999,
        "session_id": "older-session",
    })
    assert await registry.publish(older, {**message, "sequence": 99}) == 0
    assert len(first_socket.sent) == 1
    assert len(second_socket.sent) == 1


@pytest.mark.asyncio
async def test_family_sync_ordering_is_independent_for_each_source_profile():
    registry = FamilySyncRegistry(clock=lambda: 1000.0)
    first_socket = LiveObserverWebSocket()
    second_socket = LiveObserverWebSocket()
    registry.add(FamilySyncChannel(
        websocket=first_socket,
        claims=family_sync_claims(role="observer", profile_id="profile-1"),
    ))
    registry.add(FamilySyncChannel(
        websocket=second_socket,
        claims=family_sync_claims(role="observer", profile_id="profile-2"),
    ))
    message = {
        "type": "progress",
        "sequence": 4,
        "position_seconds": 12.5,
        "runtime_seconds": 7200,
        "selected_viewer_profile_ids": ["profile-1", "profile-2"],
        "departed_viewer_profile_ids": [],
        "playback_state": "active",
    }
    first_source = FamilySyncChannel(
        websocket=LiveObserverWebSocket(),
        claims={
            **family_sync_claims(role="publisher", profile_id="profile-1"),
            "session_started_at_epoch_milliseconds": 2_000_000,
        },
    )
    second_source = FamilySyncChannel(
        websocket=LiveObserverWebSocket(),
        claims={
            **family_sync_claims(role="publisher", profile_id="profile-2"),
            "session_id": "profile-2-session",
            "session_started_at_epoch_milliseconds": 1_000_000,
        },
    )

    assert await registry.publish(first_source, message) == 2
    assert await registry.publish(second_source, {**message, "sequence": 50}) == 2
    assert [event["source_profile_id"] for event in first_socket.sent] == ["profile-1", "profile-2"]
    assert [event["source_profile_id"] for event in second_socket.sent] == ["profile-1", "profile-2"]


@pytest.mark.asyncio
async def test_family_sync_publisher_cannot_widen_signed_audience():
    registry = FamilySyncRegistry(clock=lambda: 1000.0)
    publisher = FamilySyncChannel(websocket=LiveObserverWebSocket(), claims=family_sync_claims(role="publisher"))
    with pytest.raises(ValueError, match="familySyncLiveSelectionUnauthorized"):
        await registry.publish(publisher, {
            "type": "progress",
            "sequence": 1,
            "position_seconds": 1,
            "runtime_seconds": 100,
            "selected_viewer_profile_ids": ["profile-1", "profile-3"],
            "departed_viewer_profile_ids": [],
            "playback_state": "active",
        })


@pytest.mark.asyncio
async def test_family_sync_controller_may_publish_for_another_exact_viewer():
    registry = FamilySyncRegistry(clock=lambda: 1000.0)
    controller_socket = LiveObserverWebSocket()
    viewer_socket = LiveObserverWebSocket()
    registry.add(FamilySyncChannel(
        websocket=controller_socket,
        claims=family_sync_claims(role="observer", profile_id="profile-1"),
    ))
    registry.add(FamilySyncChannel(
        websocket=viewer_socket,
        claims=family_sync_claims(role="observer", profile_id="profile-2"),
    ))
    publisher = FamilySyncChannel(
        websocket=LiveObserverWebSocket(),
        claims=family_sync_claims(role="publisher", profile_id="profile-1"),
    )

    assert await registry.publish(publisher, {
        "type": "progress",
        "sequence": 1,
        "position_seconds": 12.5,
        "runtime_seconds": 100,
        "selected_viewer_profile_ids": ["profile-2"],
        "departed_viewer_profile_ids": [],
        "playback_state": "active",
    }) == 2
    assert viewer_socket.sent[0]["source_profile_id"] == "profile-1"
    assert viewer_socket.sent[0]["selected_viewer_profile_ids"] == ["profile-2"]


def test_avfoundation_safe_grant_path_round_trips_and_rewrites_playlists():
    signed = token(playback_payload())
    split = split_grant_token(signed)
    assert grant_token_from_path(split) == signed
    assert max(map(len, split.split("/"))) <= 180
    playlist = f"#EXTM3U\n/v1/playback/{signed}/Videos/item/main.m3u8\n".encode()
    rewritten = rewrite_hls_playlist(playlist, signed)
    assert f"/v1/playback/{split}/Videos/".encode() in rewritten
    assert f"/v1/playback/{signed}/Videos/".encode() not in rewritten


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
async def test_connector_reader_enqueues_media_chunk_without_ack_round_trip():
    request_id = "12345678-1234-1234-1234-123456789012"
    websocket = FakeWebSocket([
        {"type": "websocket.receive", "bytes": request_id.encode() + b"media"},
    ])
    queue = asyncio.Queue(maxsize=1)
    channel = ConnectorChannel(websocket=websocket, pending={request_id: queue})

    with pytest.raises(WebSocketDisconnect):
        await channel.reader()

    assert await queue.get() == ("body", b"media")
    assert websocket.sent == []


@pytest.mark.asyncio
async def test_connector_reader_accepts_bounded_large_hls_playlist_frame():
    request_id = "12345678-1234-1234-1234-123456789012"
    playlist = b"#EXTM3U\n" + b"x" * (MAX_CHUNK_BYTES + 1)
    websocket = FakeWebSocket([
        {"type": "websocket.receive", "text": json.dumps({
            "type": "response_start",
            "request_id": request_id,
            "status": 200,
            "headers": {"content-type": "application/vnd.apple.mpegurl"},
        })},
        {"type": "websocket.receive", "bytes": request_id.encode() + playlist},
        {"type": "websocket.disconnect"},
    ])
    queue = asyncio.Queue(maxsize=3)
    channel = ConnectorChannel(websocket=websocket, pending={request_id: queue})

    with pytest.raises(WebSocketDisconnect):
        await channel.reader()

    assert (await queue.get())[0] == "response_start"
    assert await queue.get() == ("body", playlist)


@pytest.mark.asyncio
async def test_playback_streams_media_chunk_without_body_ack(monkeypatch):
    class StreamingPlaybackWebSocket:
        def __init__(self):
            self.received = asyncio.Queue()
            self.sent = []

        async def receive(self):
            return await self.received.get()

        async def send_text(self, payload):
            message = json.loads(payload)
            self.sent.append(message)
            if message.get("type") != "request":
                return
            request_id = message["request_id"]
            await self.received.put({
                "type": "websocket.receive",
                "text": json.dumps({
                    "type": "response_start",
                    "request_id": request_id,
                    "status": 200,
                    "headers": {"content-type": "video/mp2t"},
                }),
            })
            await self.received.put({
                "type": "websocket.receive",
                "bytes": request_id.encode() + b"media",
            })
            await self.received.put({
                "type": "websocket.receive",
                "text": json.dumps({"type": "response_end", "request_id": request_id}),
            })

    websocket = StreamingPlaybackWebSocket()
    channel = ConnectorChannel(websocket=websocket)
    registry = ConnectorRegistry()
    registry.add("connector-1", channel)

    class StaticGrantRegistry:
        def resolve(self, _token):
            return playback_payload()

        def touch(self, _token):
            return playback_payload()

    monkeypatch.setattr(relay_module, "grants", StaticGrantRegistry())
    monkeypatch.setattr(relay_module, "connectors", registry)

    reader = asyncio.create_task(channel.reader())
    transport = ASGITransport(app=relay_module.app)
    try:
        async with AsyncClient(transport=transport, base_url="https://relay.test") as client:
            response = await client.get(
                "/v1/playback/grant-token/Videos/0123456789abcdef0123456789abcdef/hls1/main/0.ts",
                headers=ORIGIN_HEADERS,
            )
    finally:
        reader.cancel()
        with pytest.raises(asyncio.CancelledError):
            await reader

    assert response.status_code == 200
    assert response.content == b"media"
    assert sum(message.get("type") == "body_ack" for message in websocket.sent) == 0
    assert channel.pending == {}


@pytest.mark.asyncio
async def test_split_grant_route_rewrites_hls_response_for_avfoundation(monkeypatch):
    signed = "a" * 360 + "." + "b" * 43
    legacy_playlist = f"#EXTM3U\n/v1/playback/{signed}/Videos/0123456789abcdef0123456789abcdef/main.m3u8\n".encode()

    class PlaylistWebSocket:
        def __init__(self):
            self.channel = None

        async def send_text(self, payload):
            message = json.loads(payload)
            if message.get("type") != "request":
                return
            request_id = message["request_id"]
            await self.channel.enqueue(request_id, (
                "response_start",
                {"status": 200, "headers": {"content-type": "application/vnd.apple.mpegurl"}},
            ))
            await self.channel.enqueue(request_id, ("body", legacy_playlist))
            await self.channel.enqueue(request_id, ("response_end", {}))

    websocket = PlaylistWebSocket()
    channel = ConnectorChannel(websocket=websocket)
    websocket.channel = channel
    registry = ConnectorRegistry()
    registry.add("connector-1", channel)

    class StaticGrantRegistry:
        def resolve(self, candidate):
            assert candidate == signed
            return playback_payload()

        def touch(self, candidate):
            assert candidate == signed
            return playback_payload()

    monkeypatch.setattr(relay_module, "grants", StaticGrantRegistry())
    monkeypatch.setattr(relay_module, "connectors", registry)

    transport = ASGITransport(app=relay_module.app)
    async with AsyncClient(transport=transport, base_url="https://relay.test") as client:
        response = await client.get(
            f"/v1/playback/{split_grant_token(signed)}/Videos/0123456789abcdef0123456789abcdef/master.m3u8",
            headers=ORIGIN_HEADERS,
        )

    assert response.status_code == 200
    assert f"/v1/playback/{split_grant_token(signed)}/Videos/".encode() in response.content
    assert channel.pending == {}


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
            return playback_payload()

        def touch(self, _token):
            return playback_payload()

    monkeypatch.setattr(relay_module, "grants", StaticGrantRegistry())
    monkeypatch.setattr(relay_module, "connectors", registry)

    transport = ASGITransport(app=relay_module.app)
    async with AsyncClient(transport=transport, base_url="https://relay.test") as client:
        for _ in range(20):
            response = await client.head(
                "/v1/playback/grant-token/Videos/0123456789abcdef0123456789abcdef/stream?static=true",
                headers=ORIGIN_HEADERS,
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


@pytest.mark.asyncio
async def test_connector_capacity_prunes_expired_hls_requests_before_rejecting_playback():
    websocket = FakeWebSocket([])
    channel = ConnectorChannel(websocket=websocket)
    for index in range(relay_module.MAX_PENDING_PER_CONNECTOR):
        request_id = f"expired-{index}"
        channel.register_request(request_id, asyncio.Queue(), deadline=time.monotonic() - 1)
    registry = ConnectorRegistry()
    registry.add("connector-1", channel)

    selected = await registry.wait_for_capacity("connector-1", timeout=0.1)

    assert selected is channel
    assert channel.pending == {}
    assert len(websocket.sent) == relay_module.MAX_PENDING_PER_CONNECTOR
    assert all(message["type"] == "cancel" for message in websocket.sent)


@pytest.mark.asyncio
async def test_connector_capacity_waits_briefly_instead_of_immediately_returning_busy():
    channel = ConnectorChannel(websocket=object())
    for index in range(relay_module.MAX_PENDING_PER_CONNECTOR):
        channel.register_request(f"active-{index}", asyncio.Queue(), deadline=None)
    registry = ConnectorRegistry()
    registry.add("connector-1", channel)

    async def release_one():
        await asyncio.sleep(0.02)
        channel.release_request("active-0")

    release_task = asyncio.create_task(release_one())
    selected = await registry.wait_for_capacity("connector-1", timeout=0.2)
    await release_task

    assert selected is channel


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
