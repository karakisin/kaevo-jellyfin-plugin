from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


ITEM_ID = re.compile(r"^[0-9a-fA-F]{32}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SEGMENT_PATH = re.compile(r"^/Videos/([0-9a-fA-F]{32})/hls1/main/(\d+)\.(ts|mp4|m4s)$")
STATIC_PATH = re.compile(r"^/Videos/([0-9a-fA-F]{32})/(stream|master\.m3u8|main\.m3u8)$")
ALLOWED_QUERY_KEYS = {
    "mediaSourceId", "playSessionId", "deviceId", "static", "container",
    "segmentContainer", "segmentLength", "minSegments", "audioCodec",
    "videoCodec", "subtitleCodec", "audioBitRate", "videoBitRate",
    "maxWidth", "maxHeight", "audioStreamIndex", "subtitleStreamIndex",
    "enableAutoStreamCopy", "allowVideoStreamCopy", "allowAudioStreamCopy",
    "enableAdaptiveBitrateStreaming", "runtimeTicks", "actualSegmentLengthTicks",
}
BOOL_VALUES = {"true", "false"}
CODECS = {"h264", "hevc", "av1", "aac", "ac3", "eac3", "opus", "copy", "none"}


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class PlaybackGrant:
    grant_id: str
    nonce: str
    profile_id: str
    device_id: str
    connector_id: str
    item_id: str
    media_source_id: str
    playback_session_id: str
    mode: str
    max_bitrate: int
    expires_at: int


class PlaybackGrantVerifier:
    def __init__(self, connector_grant_key: str, connector_id: str, *, clock=time.time):
        if len(connector_grant_key) < 32:
            raise ValueError("playbackConnectorGrantKeyTooShort")
        self.key = connector_grant_key.encode("utf-8")
        self.connector_id = connector_id
        self.clock = clock

    def verify(self, token: str, *, expected_device_id: str | None = None) -> PlaybackGrant:
        try:
            encoded, _outer_signature = token.split(".", 1)
            payload = json.loads(_b64decode(encoded))
            supplied_signature = str(payload.pop("home_sig", ""))
            canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            expected = hmac.new(self.key, canonical, hashlib.sha256).digest()
            if not supplied_signature or not hmac.compare_digest(_b64decode(supplied_signature), expected):
                raise ValueError("playbackGrantSignatureInvalid")
        except ValueError:
            raise
        except Exception:
            raise ValueError("playbackGrantMalformed") from None
        now = int(self.clock())
        if int(payload.get("v") or 0) != 1:
            raise ValueError("playbackGrantVersionUnsupported")
        if now < int(payload.get("nbf") or 0) or now >= int(payload.get("exp") or 0):
            raise ValueError("playbackGrantExpired")
        if payload.get("connector_id") != self.connector_id:
            raise ValueError("playbackGrantConnectorMismatch")
        if expected_device_id and payload.get("device_id") != expected_device_id:
            raise ValueError("playbackGrantDeviceMismatch")
        if payload.get("mode") not in {"direct_play", "remux", "transcode"}:
            raise ValueError("playbackGrantModeInvalid")
        if not ITEM_ID.fullmatch(str(payload.get("item_id") or "")):
            raise ValueError("playbackGrantItemInvalid")
        for key in ("grant_id", "nonce", "profile_id", "device_id", "media_source_id", "playback_session_id"):
            if not SAFE_ID.fullmatch(str(payload.get(key) or "")):
                raise ValueError("playbackGrantIdentifierInvalid")
        return PlaybackGrant(
            grant_id=payload["grant_id"], nonce=payload["nonce"], profile_id=payload["profile_id"],
            device_id=payload["device_id"], connector_id=payload["connector_id"], item_id=payload["item_id"].lower(),
            media_source_id=payload["media_source_id"], playback_session_id=payload["playback_session_id"],
            mode=payload["mode"], max_bitrate=int(payload["max_bitrate"]), expires_at=int(payload["exp"]),
        )


class PlaybackNonceStore:
    def __init__(self, path: Path, *, clock=time.time):
        self.path = path
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS playback_nonces (nonce_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)")

    def redeem(self, nonce: str, expires_at: int) -> None:
        nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM playback_nonces WHERE expires_at < ?", (int(self.clock()),))
            try:
                db.execute("INSERT INTO playback_nonces(nonce_hash, expires_at) VALUES (?, ?)", (nonce_hash, expires_at))
            except sqlite3.IntegrityError:
                raise ValueError("playbackGrantReplay") from None


@dataclass(frozen=True)
class ResolvedPlaybackRequest:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]


class PlaybackTunnelSession:
    def __init__(self, grant: PlaybackGrant):
        self.grant = grant

    @classmethod
    def open(cls, token: str, verifier: PlaybackGrantVerifier, nonces: PlaybackNonceStore, *, device_id: str):
        grant = verifier.verify(token, expected_device_id=device_id)
        nonces.redeem(grant.nonce, grant.expires_at)
        return cls(grant)

    def resolve(
        self,
        method: str,
        path: str,
        query: Mapping[str, str],
        *,
        range_header: str | None = None,
    ) -> ResolvedPlaybackRequest:
        method = method.upper()
        static_match = STATIC_PATH.fullmatch(path)
        segment_match = SEGMENT_PATH.fullmatch(path)
        match = static_match or segment_match
        if method not in {"GET", "HEAD"} or not match or match.group(1).lower() != self.grant.item_id:
            raise ValueError("playbackRouteNotAllowed")
        route_kind = static_match.group(2) if static_match else "segment"
        if self.grant.mode == "direct_play" and route_kind != "stream":
            raise ValueError("playbackModeRouteMismatch")
        if self.grant.mode in {"remux", "transcode"} and route_kind == "stream":
            raise ValueError("playbackModeRouteMismatch")
        if set(query) - ALLOWED_QUERY_KEYS:
            raise ValueError("playbackQueryNotAllowed")
        normalized = {str(key): str(value) for key, value in query.items()}
        for key, expected in {
            "mediaSourceId": self.grant.media_source_id,
            "playSessionId": self.grant.playback_session_id,
            "deviceId": self.grant.device_id,
        }.items():
            if key in normalized and normalized[key] != expected:
                raise ValueError("playbackSessionBindingMismatch")
            normalized[key] = expected
        for key in ("static", "enableAutoStreamCopy", "allowVideoStreamCopy", "allowAudioStreamCopy", "enableAdaptiveBitrateStreaming"):
            if key in normalized and normalized[key].lower() not in BOOL_VALUES:
                raise ValueError("playbackBooleanInvalid")
        for key in ("audioCodec", "videoCodec", "subtitleCodec"):
            if key in normalized:
                codecs = {value.strip().lower() for value in normalized[key].split(",")}
                if not codecs or codecs - CODECS:
                    raise ValueError("playbackCodecInvalid")
        total_bitrate = 0
        for key in ("audioBitRate", "videoBitRate"):
            if key in normalized:
                try:
                    value = int(normalized[key])
                except ValueError:
                    raise ValueError("playbackBitrateInvalid") from None
                if value < 0:
                    raise ValueError("playbackBitrateInvalid")
                total_bitrate += value
        if total_bitrate > self.grant.max_bitrate:
            raise ValueError("playbackBitrateExceeded")
        headers = {}
        if range_header:
            if self.grant.mode != "direct_play" or not re.fullmatch(r"bytes=\d*-\d*", range_header):
                raise ValueError("playbackRangeInvalid")
            headers["Range"] = range_header
        return ResolvedPlaybackRequest(method=method, path=path, query=normalized, headers=headers)
