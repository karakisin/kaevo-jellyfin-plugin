from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx
from pydantic import BaseModel, Field, model_validator


ITEM_ID = re.compile(r"^[0-9a-fA-F]{32}$")
APPROVAL_TOKEN = re.compile(r"^[A-Za-z0-9_-]{24,128}$")
ALLOWED_OPERATIONS = {
    "jellyfin.mark_played",
    "jellyfin.mark_unplayed",
    "jellyfin.favorite",
    "jellyfin.unfavorite",
    "jellyfin.prepare_playback",
    "seerr.create_request",
    "seerr.cancel_request",
    "optimizer.scan",
    "optimizer.plan_remux",
    "optimizer.execute_remux",
}


class CloudCommand(BaseModel):
    requestId: str = Field(min_length=8, max_length=128)
    operation: str
    parameters: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_command(self) -> "CloudCommand":
        if self.operation not in ALLOWED_OPERATIONS:
            raise ValueError("operationNotAllowed")
        parameters = self.parameters
        if self.operation == "jellyfin.prepare_playback":
            item_id = str(parameters.get("item_id") or "")
            device_id = str(parameters.get("device_id") or "")
            max_bitrate = parameters.get("max_bitrate", 40_000_000)
            if not ITEM_ID.fullmatch(item_id) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", device_id):
                raise ValueError("invalidPlaybackPreparationIdentifiers")
            if set(parameters) - {"item_id", "device_id", "max_bitrate"}:
                raise ValueError("unexpectedPlaybackPreparationParameters")
            if not isinstance(max_bitrate, int) or isinstance(max_bitrate, bool) or not 1 <= max_bitrate <= 100_000_000:
                raise ValueError("invalidPlaybackPreparationBitrate")
        elif self.operation.startswith("jellyfin."):
            item_id = str(parameters.get("item_id") or "")
            if not ITEM_ID.fullmatch(item_id):
                raise ValueError("invalidJellyfinItemId")
            if set(parameters) != {"item_id"}:
                raise ValueError("unexpectedJellyfinParameters")
        elif self.operation == "seerr.create_request":
            media_type = parameters.get("media_type")
            if media_type not in {"movie", "tv"}:
                raise ValueError("invalidMediaType")
            media_id = parameters.get("media_id")
            if not isinstance(media_id, int) or isinstance(media_id, bool) or media_id <= 0:
                raise ValueError("invalidMediaId")
            allowed = {"media_type", "media_id", "seasons", "is_4k"}
            if set(parameters) - allowed:
                raise ValueError("unexpectedSeerrParameters")
            seasons = parameters.get("seasons", [])
            if media_type == "tv" and (
                not isinstance(seasons, list)
                or len(seasons) > 100
                or any(not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 100 for value in seasons)
            ):
                raise ValueError("invalidSeasons")
        elif self.operation == "seerr.cancel_request":
            request_id = parameters.get("request_id")
            if not isinstance(request_id, int) or isinstance(request_id, bool) or request_id <= 0:
                raise ValueError("invalidRequestId")
            if set(parameters) != {"request_id"}:
                raise ValueError("unexpectedSeerrParameters")
        elif self.operation == "optimizer.scan":
            limit = parameters.get("limit", 50)
            if set(parameters) - {"limit"} or not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
                raise ValueError("invalidOptimizerScanParameters")
        elif self.operation == "optimizer.plan_remux":
            item_id = str(parameters.get("item_id") or "")
            if not ITEM_ID.fullmatch(item_id) or set(parameters) != {"item_id"}:
                raise ValueError("invalidRemuxPlanParameters")
        elif self.operation == "optimizer.execute_remux":
            if set(parameters) != {"plan_id", "approval_token", "confirmation"}:
                raise ValueError("invalidRemuxExecutionParameters")
            if parameters.get("confirmation") != "YES_REMUX_ONE_FILE":
                raise ValueError("remuxConfirmationMissing")
            try:
                uuid.UUID(str(parameters.get("plan_id") or ""))
            except (ValueError, TypeError, AttributeError):
                raise ValueError("invalidPlanId") from None
            token = str(parameters.get("approval_token") or "")
            if not APPROVAL_TOKEN.fullmatch(token):
                raise ValueError("invalidApprovalToken")
        return self


class CommandResult(BaseModel):
    requestId: str
    state: str
    operation: str
    result: dict[str, Any] = Field(default_factory=dict)
    sanitizedErrorCategory: str | None = None


class CommandReceiptStore:
    """Stores sanitized receipts so a claimed Cloud command cannot run twice."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS cloud_command_receipts (
                    request_id TEXT PRIMARY KEY,
                    payload_hash TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def payload_hash(command: CloudCommand) -> str:
        encoded = json.dumps(command.model_dump(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def get(self, command: CloudCommand) -> CommandResult | None:
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT payload_hash, result_json FROM cloud_command_receipts WHERE request_id=?",
                (command.requestId,),
            ).fetchone()
        if not row:
            return None
        if row[0] != self.payload_hash(command):
            return CommandResult(
                requestId=command.requestId,
                state="blocked",
                operation=command.operation,
                sanitizedErrorCategory="requestIdPayloadMismatch",
            )
        return CommandResult.model_validate_json(row[1])

    def put(self, command: CloudCommand, result: CommandResult) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT OR IGNORE INTO cloud_command_receipts(request_id, payload_hash, result_json) VALUES (?, ?, ?)",
                (command.requestId, self.payload_hash(command), result.model_dump_json()),
            )


@dataclass(frozen=True)
class LocalProvider:
    base_url: str
    api_key: str


OptimizerHandler = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


class CloudCommandExecutor:
    def __init__(
        self,
        *,
        receipts: CommandReceiptStore,
        jellyfin: LocalProvider | None = None,
        jellyfin_user_id: str | None = None,
        seerr: LocalProvider | None = None,
        optimizer: OptimizerHandler | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.receipts = receipts
        self.jellyfin = jellyfin
        self.jellyfin_user_id = jellyfin_user_id
        self.seerr = seerr
        self.optimizer = optimizer
        self.transport = transport

    async def execute(self, command: CloudCommand) -> CommandResult:
        existing = self.receipts.get(command)
        if existing:
            return existing
        try:
            if command.operation.startswith("jellyfin."):
                result = await self._execute_jellyfin(command)
            elif command.operation.startswith("seerr."):
                result = await self._execute_seerr(command)
            else:
                result = await self._execute_optimizer(command)
            receipt = CommandResult(
                requestId=command.requestId,
                state="complete",
                operation=command.operation,
                result=result,
            )
        except RuntimeError as error:
            receipt = CommandResult(
                requestId=command.requestId,
                state="blocked",
                operation=command.operation,
                sanitizedErrorCategory=str(error),
            )
        except httpx.HTTPStatusError as error:
            receipt = CommandResult(
                requestId=command.requestId,
                state="failed",
                operation=command.operation,
                sanitizedErrorCategory=f"providerHttp{error.response.status_code}",
            )
        except (httpx.ConnectError, httpx.TimeoutException):
            receipt = CommandResult(
                requestId=command.requestId,
                state="failed",
                operation=command.operation,
                sanitizedErrorCategory="providerUnavailable",
            )
        self.receipts.put(command, receipt)
        return receipt

    async def _execute_jellyfin(self, command: CloudCommand) -> dict[str, Any]:
        if not self.jellyfin or not self.jellyfin_user_id:
            raise RuntimeError("jellyfinNotConfigured")
        if command.operation == "jellyfin.prepare_playback":
            return await self._prepare_jellyfin_playback(command)
        routes = {
            "jellyfin.mark_played": ("POST", "UserPlayedItems"),
            "jellyfin.mark_unplayed": ("DELETE", "UserPlayedItems"),
            "jellyfin.favorite": ("POST", "UserFavoriteItems"),
            "jellyfin.unfavorite": ("DELETE", "UserFavoriteItems"),
        }
        method, route = routes[command.operation]
        item_id = command.parameters["item_id"]
        async with httpx.AsyncClient(transport=self.transport, timeout=15.0, follow_redirects=False) as client:
            response = await client.request(
                method,
                f"{self.jellyfin.base_url.rstrip('/')}/{route}/{item_id}",
                params={"userId": self.jellyfin_user_id},
                headers={"X-Emby-Token": self.jellyfin.api_key, "Accept": "application/json"},
            )
        response.raise_for_status()
        return {"item_id": item_id, "applied": True}

    async def _prepare_jellyfin_playback(self, command: CloudCommand) -> dict[str, Any]:
        parameters = command.parameters
        item_id = parameters["item_id"]
        body = {
            "UserId": self.jellyfin_user_id,
            "MaxStreamingBitrate": parameters.get("max_bitrate", 40_000_000),
            "EnableDirectPlay": True,
            "EnableDirectStream": True,
            "EnableTranscoding": True,
            "AllowVideoStreamCopy": True,
            "AllowAudioStreamCopy": True,
            "DeviceProfile": {
                "Name": "Kaevo Apple HLS",
                "MaxStreamingBitrate": parameters.get("max_bitrate", 40_000_000),
                "DirectPlayProfiles": [{"Container": "mp4,m4v,mov", "Type": "Video", "VideoCodec": "h264,hevc", "AudioCodec": "aac,ac3,eac3"}],
                "TranscodingProfiles": [{"Container": "ts", "Type": "Video", "VideoCodec": "h264", "AudioCodec": "aac", "Protocol": "hls", "Context": "Streaming"}],
            },
        }
        async with httpx.AsyncClient(transport=self.transport, timeout=15.0, follow_redirects=False) as client:
            response = await client.post(
                f"{self.jellyfin.base_url.rstrip('/')}/Items/{item_id}/PlaybackInfo",
                headers={"X-Emby-Token": self.jellyfin.api_key, "Accept": "application/json"},
                json=body,
            )
        response.raise_for_status()
        payload = response.json()
        sources = payload.get("MediaSources") or []
        if not sources:
            raise RuntimeError("jellyfinMediaSourceUnavailable")
        source = sorted(
            sources,
            key=lambda value: (bool(value.get("SupportsDirectPlay")), bool(value.get("SupportsDirectStream")), bool(value.get("SupportsTranscoding"))),
            reverse=True,
        )[0]
        if source.get("SupportsDirectPlay"):
            mode = "direct_play"
        elif source.get("SupportsDirectStream"):
            mode = "remux"
        elif source.get("SupportsTranscoding"):
            mode = "transcode"
        else:
            raise RuntimeError("jellyfinPlaybackUnsupported")
        media_source_id = str(source.get("Id") or "")
        play_session_id = str(payload.get("PlaySessionId") or "")
        if not media_source_id or len(media_source_id) > 128 or not play_session_id or len(play_session_id) > 128:
            raise RuntimeError("jellyfinPlaybackIdentifiersInvalid")
        return {
            "item_id": item_id,
            "media_source_id": media_source_id,
            "playback_session_id": play_session_id,
            "mode": mode,
            "max_bitrate": parameters.get("max_bitrate", 40_000_000),
        }

    async def _execute_seerr(self, command: CloudCommand) -> dict[str, Any]:
        if not self.seerr:
            raise RuntimeError("seerrNotConfigured")
        headers = {"X-Api-Key": self.seerr.api_key, "Accept": "application/json"}
        async with httpx.AsyncClient(transport=self.transport, timeout=15.0, follow_redirects=False) as client:
            if command.operation == "seerr.create_request":
                parameters = command.parameters
                body: dict[str, Any] = {
                    "mediaType": parameters["media_type"],
                    "mediaId": parameters["media_id"],
                    "is4k": bool(parameters.get("is_4k", False)),
                }
                if parameters["media_type"] == "tv":
                    body["seasons"] = [{"seasonNumber": value} for value in parameters.get("seasons", [])]
                response = await client.post(f"{self.seerr.base_url.rstrip('/')}/api/v1/request", headers=headers, json=body)
                response.raise_for_status()
                payload = response.json()
                return {"request_id": int(payload["id"]), "created": True}
            request_id = command.parameters["request_id"]
            response = await client.delete(f"{self.seerr.base_url.rstrip('/')}/api/v1/request/{request_id}", headers=headers)
            response.raise_for_status()
            return {"request_id": request_id, "cancelled": True}

    async def _execute_optimizer(self, command: CloudCommand) -> dict[str, Any]:
        if not self.optimizer:
            raise RuntimeError("optimizerNotConfigured")
        return await self.optimizer(command.operation, command.parameters)
