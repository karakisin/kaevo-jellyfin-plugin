import base64
import hashlib
import hmac
import json
from pathlib import Path

import pytest

from kaevo_home_server.playback_tunnel import PlaybackGrantVerifier, PlaybackNonceStore, PlaybackTunnelSession


KEY = "playback-signing-key-with-at-least-32-characters"
ITEM = "0123456789abcdef0123456789abcdef"


def token(payload: dict) -> str:
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    home_sig = base64.urlsafe_b64encode(hmac.new(KEY.encode(), canonical, hashlib.sha256).digest()).decode().rstrip("=")
    payload = {**payload, "home_sig": home_sig}
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(hmac.new(KEY.encode(), encoded.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    return f"{encoded}.{signature}"


def payload(mode="direct_play"):
    return {
        "v": 1, "grant_id": "grant-1", "nonce": "nonce-abcdefghijklmnopqrstuvwxyz", "profile_id": "profile-1",
        "device_id": "device-1", "connector_id": "connector-1", "item_id": ITEM,
        "media_source_id": "source-1", "playback_session_id": "session-1", "mode": mode,
        "max_bitrate": 10_000_000, "iat": 1000, "nbf": 995, "exp": 1120,
    }


def open_session(tmp_path: Path, mode="direct_play"):
    verifier = PlaybackGrantVerifier(KEY, "connector-1", clock=lambda: 1001)
    return PlaybackTunnelSession.open(token(payload(mode)), verifier, PlaybackNonceStore(tmp_path / f"{mode}.sqlite3"), device_id="device-1")


def test_direct_play_is_item_bound_and_preserves_bounded_range(tmp_path: Path):
    session = open_session(tmp_path)
    result = session.resolve("GET", f"/Videos/{ITEM}/stream", {}, range_header="bytes=0-1048575")
    assert result.query == {"mediaSourceId": "source-1", "playSessionId": "session-1", "deviceId": "device-1"}
    assert result.headers == {"Range": "bytes=0-1048575"}


def test_hls_transcode_accepts_only_bound_playlist_and_segments(tmp_path: Path):
    session = open_session(tmp_path, "transcode")
    master = session.resolve("GET", f"/Videos/{ITEM}/master.m3u8", {"videoBitRate": "8000000", "audioBitRate": "192000"})
    assert master.query["playSessionId"] == "session-1"
    segment = session.resolve("GET", f"/Videos/{ITEM}/hls1/main/3.ts", {"runtimeTicks": "30000000", "actualSegmentLengthTicks": "10000000"})
    assert segment.path.endswith("/3.ts")


def test_arbitrary_lan_paths_sessions_and_excess_bitrate_are_rejected(tmp_path: Path):
    session = open_session(tmp_path, "transcode")
    with pytest.raises(ValueError, match="playbackRouteNotAllowed"):
        session.resolve("GET", "/System/Info", {})
    with pytest.raises(ValueError, match="playbackSessionBindingMismatch"):
        session.resolve("GET", f"/Videos/{ITEM}/master.m3u8", {"playSessionId": "another-session"})
    with pytest.raises(ValueError, match="playbackBitrateExceeded"):
        session.resolve("GET", f"/Videos/{ITEM}/master.m3u8", {"videoBitRate": "11000000"})


def test_grant_is_device_connector_expiry_and_replay_bound(tmp_path: Path):
    verifier = PlaybackGrantVerifier(KEY, "connector-1", clock=lambda: 1001)
    nonces = PlaybackNonceStore(tmp_path / "nonces.sqlite3", clock=lambda: 1001)
    grant = token(payload())
    PlaybackTunnelSession.open(grant, verifier, nonces, device_id="device-1")
    with pytest.raises(ValueError, match="playbackGrantReplay"):
        PlaybackTunnelSession.open(grant, verifier, nonces, device_id="device-1")
    with pytest.raises(ValueError, match="playbackGrantDeviceMismatch"):
        PlaybackTunnelSession.open(token({**payload(), "nonce": "another-nonce-abcdefghijklmnop"}), verifier, nonces, device_id="other")
    expired = PlaybackGrantVerifier(KEY, "connector-1", clock=lambda: 1121)
    with pytest.raises(ValueError, match="playbackGrantExpired"):
        expired.verify(token({**payload(), "nonce": "expired-nonce-abcdefghijklmnop"}))
