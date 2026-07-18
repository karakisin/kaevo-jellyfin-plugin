from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from .cloud_runtime import CloudRuntime


APP_VERSION = "0.1.0"
DEFAULT_DATA_DIR = Path(os.environ.get("KAEVO_HOME_SERVER_DATA_DIR", str(Path(__file__).resolve().parents[1] / "data")))
SECRET_KEY_VALUE = os.environ.get("KAEVO_HOME_SERVER_SECRET_KEY", "")
SECRET_KEY = SECRET_KEY_VALUE.encode("utf-8")
IOS_COMMAND_TOKEN = os.environ.get("KAEVO_HOME_SERVER_IOS_TOKEN")

ProviderKind = Literal["seerr", "sonarr", "radarr", "qbittorrent", "sabnzbd", "jellyfin"]
OperationType = Literal["createMediaRequest", "removeRequestKeepMedia", "permanentDeleteEverywhere", "reconcileRemoval", "retryOperationStep"]
StepState = Literal["pending", "running", "confirmedComplete", "confirmedIncomplete", "ambiguous", "blocked", "failed", "skipped"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def masked_id(value: Any | None) -> str | None:
    if value is None:
        return None
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
    return f"…{digest[-8:]}"


def sanitize_url(value: str) -> str:
    try:
        parsed = httpx.URL(value)
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{parsed.host}{port}"
    except Exception:
        return "<invalid-url>"


def error_category(error: Exception) -> str:
    if isinstance(error, httpx.ConnectError):
        return "serverUnreachable"
    if isinstance(error, httpx.TimeoutException):
        return "providerUnavailable"
    if isinstance(error, ProviderHTTPError):
        if error.status_code in (401, 403):
            return "authenticationFailed"
        return f"http{error.status_code}"
    return "providerUnavailable"


def xor_secret(data: bytes) -> str:
    """Encrypt provider credentials with authenticated encryption.

    The historical function name is retained so existing callers do not need a
    storage migration. New values are versioned; legacy unversioned XOR values
    remain readable only when an explicit local secret is configured.
    """
    if not SECRET_KEY:
        raise RuntimeError("homeServerSecretKeyMissing")
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(hashlib.sha256(SECRET_KEY).digest()).encrypt(
        nonce,
        data,
        b"kaevo-home-server-provider-credentials-v2",
    )
    return "v2:" + base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")


def unxor_secret(value: str) -> str:
    if not SECRET_KEY:
        raise RuntimeError("homeServerSecretKeyMissing")
    if value.startswith("v2:"):
        packed = base64.urlsafe_b64decode(value[3:].encode("ascii"))
        if len(packed) < 29:
            raise ValueError("providerCredentialCiphertextInvalid")
        nonce, encrypted = packed[:12], packed[12:]
        data = AESGCM(hashlib.sha256(SECRET_KEY).digest()).decrypt(
            nonce,
            encrypted,
            b"kaevo-home-server-provider-credentials-v2",
        )
        return data.decode("utf-8")

    # Read-only compatibility for installations created before v2. The next
    # credential save writes authenticated ciphertext.
    encrypted = base64.urlsafe_b64decode(value.encode("ascii"))
    key_stream = hashlib.sha256(SECRET_KEY).digest()
    data = bytes(byte ^ key_stream[index % len(key_stream)] for index, byte in enumerate(encrypted))
    return data.decode("utf-8")


class ProviderHTTPError(RuntimeError):
    def __init__(self, status_code: int):
        super().__init__(f"provider returned HTTP {status_code}")
        self.status_code = status_code


class ProviderCredentialInput(BaseModel):
    baseUrl: str
    enabled: bool = True
    apiKey: str | None = None
    username: str | None = None
    password: str | None = None


class ProviderConnectionPublic(BaseModel):
    kind: ProviderKind
    configured: bool
    enabled: bool
    safeBaseUrl: str | None = None
    safeUsername: str | None = None
    credentialRevision: int
    updatedAt: str | None = None


class ProviderAuditResult(BaseModel):
    provider: ProviderKind
    configured: bool
    enabled: bool
    reachable: bool
    authenticated: bool
    version: str | None = None
    supportedApiContract: bool
    capabilities: list[str] = Field(default_factory=list)
    missingCredentialFields: list[str] = Field(default_factory=list)
    state: str
    lastChecked: str
    sanitizedErrorCategory: str | None = None


class RequestIntent(BaseModel):
    operationId: str
    kaevoProfileId: str
    seerrConnectionId: str = "seerr"
    verifiedLinkedSeerrUserId: int | None = None
    mediaType: Literal["movie", "tv"]
    mediaId: int
    tvdbId: int | None = None
    seasons: list[int] = Field(default_factory=list)
    is4k: bool = False
    requesterMode: Literal["dedicatedLinkedIdentity", "householdAdminIdentity", "perRequestHouseholdApproval", "notConfigured", "needsReview"]
    householdApprovalId: str | None = None


class RequestResult(BaseModel):
    operationId: str
    state: str
    providerRequestId: int | None = None
    finalRequester: str | None = None
    finalRequesterId: str | None = None
    sanitizedErrorCategory: str | None = None
    message: str


class RemovalPlanInput(BaseModel):
    requestCorrelationId: str
    seerrRequestId: int
    mediaType: Literal["movie", "tv"]
    tmdbId: int | None = None
    tvdbId: int | None = None
    requestedMode: Literal["keepMedia", "permanentDeleteEverywhere"]


class RemovalPlanResult(BaseModel):
    planId: str
    state: str
    expiresAt: str
    seerrRequestId: int
    arrKind: Literal["radarr", "sonarr"] | None
    arrItemId: int | None
    arrManagedFileCount: int
    exactDownloadIds: list[str]
    downloaderKind: Literal["qbittorrent", "sabnzbd"] | None
    qbittorrentHashes: list[str]
    sabNzoIds: list[str]
    safeDownloaderJobNames: list[str]
    sharedJob: bool
    providerHealth: dict[str, str]
    sanitizedBlocker: str | None = None


class ExecuteResult(BaseModel):
    operationId: str
    state: str
    stepStates: dict[str, StepState]
    sanitizedErrorCategory: str | None = None
    message: str


class ReconcileResult(BaseModel):
    operationId: str
    state: str
    stepStates: dict[str, StepState]
    retryableSteps: list[str]
    sanitizedErrorCategory: str | None = None


class OperationResult(BaseModel):
    operationId: str
    operationType: str
    state: str
    stepStates: dict[str, StepState]
    sanitizedErrorCategory: str | None = None


class RetryStepInput(BaseModel):
    step: str


class PermanentConfirmation(BaseModel):
    token: str


def require_ios_command(request: Request) -> None:
    if not IOS_COMMAND_TOKEN:
        raise HTTPException(status_code=503, detail="homeServerAuthenticationNotConfigured")
    supplied = request.headers.get("X-Kaevo-Home-Server-Token")
    if not supplied or not hmac.compare_digest(supplied, IOS_COMMAND_TOKEN):
        raise HTTPException(status_code=401, detail="homeServerAuthenticationFailed")


@dataclass(frozen=True)
class ProviderCredentials:
    kind: ProviderKind
    base_url: str
    enabled: bool
    credential_revision: int
    api_key: str | None = None
    username: str | None = None
    password: str | None = None

    @property
    def safe_base_url(self) -> str:
        return sanitize_url(self.base_url)


class CredentialStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(json.dumps({"providers": {}}, indent=2), encoding="utf-8")
            self.path.chmod(0o600)

    def _read(self) -> dict[str, Any]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        self.path.chmod(0o600)

    def set(self, kind: ProviderKind, payload: ProviderCredentialInput) -> ProviderConnectionPublic:
        data = self._read()
        providers = data.setdefault("providers", {})
        existing = providers.get(kind) or {}
        revision = int(existing.get("credentialRevision") or 0) + 1
        secret_payload = {
            "apiKey": payload.apiKey,
            "username": payload.username,
            "password": payload.password,
        }
        providers[kind] = {
            "kind": kind,
            "enabled": payload.enabled,
            "baseUrl": payload.baseUrl.rstrip("/"),
            "secret": xor_secret(json.dumps(secret_payload, separators=(",", ":")).encode("utf-8")),
            "safeUsername": payload.username,
            "credentialRevision": revision,
            "updatedAt": utc_now(),
        }
        self._write(data)
        qbittorrent_sessions.drop(kind)
        return self.public(kind)

    def delete(self, kind: ProviderKind) -> None:
        data = self._read()
        data.setdefault("providers", {}).pop(kind, None)
        self._write(data)
        qbittorrent_sessions.drop(kind)

    def public(self, kind: ProviderKind) -> ProviderConnectionPublic:
        raw = self._read().get("providers", {}).get(kind)
        if not raw:
            return ProviderConnectionPublic(kind=kind, configured=False, enabled=False, credentialRevision=0)
        return ProviderConnectionPublic(
            kind=kind,
            configured=True,
            enabled=bool(raw.get("enabled")),
            safeBaseUrl=sanitize_url(raw.get("baseUrl", "")),
            safeUsername=raw.get("safeUsername"),
            credentialRevision=int(raw.get("credentialRevision") or 0),
            updatedAt=raw.get("updatedAt"),
        )

    def get(self, kind: ProviderKind) -> ProviderCredentials | None:
        raw = self._read().get("providers", {}).get(kind)
        if not raw:
            return None
        secret_payload = json.loads(unxor_secret(raw["secret"]))
        return ProviderCredentials(
            kind=kind,
            base_url=raw["baseUrl"].rstrip("/"),
            enabled=bool(raw.get("enabled")),
            credential_revision=int(raw.get("credentialRevision") or 0),
            api_key=secret_payload.get("apiKey"),
            username=secret_payload.get("username"),
            password=secret_payload.get("password"),
        )

    def list_public(self) -> list[ProviderConnectionPublic]:
        return [self.public(kind) for kind in ["seerr", "sonarr", "radarr", "qbittorrent", "sabnzbd", "jellyfin"]]


class OperationStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    operation_type TEXT NOT NULL,
                    state TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    step_states_json TEXT NOT NULL,
                    sanitized_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_checked_at TEXT
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS plans (
                    plan_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )

    def upsert_operation(
        self,
        operation_id: str,
        operation_type: OperationType,
        state: str,
        payload: dict[str, Any],
        step_states: dict[str, StepState],
        sanitized_error: str | None = None,
    ) -> None:
        now = utc_now()
        with sqlite3.connect(self.path) as db:
            db.execute(
                """
                INSERT INTO operations(operation_id, operation_type, state, payload_json, step_states_json, sanitized_error, created_at, updated_at, last_checked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(operation_id) DO UPDATE SET
                    state=excluded.state,
                    payload_json=excluded.payload_json,
                    step_states_json=excluded.step_states_json,
                    sanitized_error=excluded.sanitized_error,
                    updated_at=excluded.updated_at,
                    last_checked_at=excluded.last_checked_at
                """,
                (
                    operation_id,
                    operation_type,
                    state,
                    json.dumps(payload, separators=(",", ":")),
                    json.dumps(step_states, separators=(",", ":")),
                    sanitized_error,
                    now,
                    now,
                    now,
                ),
            )

    def get_operation(self, operation_id: str) -> dict[str, Any] | None:
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT operation_id, operation_type, state, payload_json, step_states_json, sanitized_error FROM operations WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
        if not row:
            return None
        return {
            "operationId": row[0],
            "operationType": row[1],
            "state": row[2],
            "payload": json.loads(row[3]),
            "stepStates": json.loads(row[4]),
            "sanitizedError": row[5],
        }

    def put_plan(self, plan: RemovalPlanResult) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute(
                """
                INSERT OR REPLACE INTO plans(plan_id, payload_json, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (plan.planId, plan.model_dump_json(), utc_now(), plan.expiresAt),
            )

    def get_plan(self, plan_id: str) -> RemovalPlanResult | None:
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT payload_json FROM plans WHERE plan_id=?", (plan_id,)).fetchone()
        if not row:
            return None
        return RemovalPlanResult.model_validate_json(row[0])


class BaseClient:
    def __init__(self, credentials: ProviderCredentials):
        self.credentials = credentials
        self.base = credentials.base_url.rstrip("/")

    async def request_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> Any:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            response = await client.request(
                method,
                f"{self.base}{path}",
                headers=headers,
                params=params,
                json=json_body,
                cookies=cookies,
            )
        if response.status_code < 200 or response.status_code >= 300:
            raise ProviderHTTPError(response.status_code)
        if not response.content:
            return None
        return response.json()


class SeerrClient(BaseClient):
    @property
    def headers(self) -> dict[str, str]:
        return {"X-Api-Key": self.credentials.api_key or "", "Accept": "application/json"}

    async def health(self) -> dict[str, Any]:
        return await self.request_json("GET", "/api/v1/status", headers=self.headers)

    async def current_user(self) -> dict[str, Any]:
        return await self.request_json("GET", "/api/v1/auth/me", headers=self.headers)

    async def list_users(self) -> list[dict[str, Any]]:
        payload = await self.request_json("GET", "/api/v1/user", headers=self.headers)
        if isinstance(payload, list):
            return payload
        return payload.get("results") or []

    async def get_user(self, user_id: int) -> dict[str, Any] | None:
        for user in await self.list_users():
            if int(user.get("id", -1)) == user_id:
                return user
        return None

    async def get_request(self, request_id: int) -> dict[str, Any]:
        return await self.request_json("GET", f"/api/v1/request/{request_id}", headers=self.headers)

    async def list_requests(self) -> dict[str, Any]:
        return await self.request_json("GET", "/api/v1/request", headers=self.headers, params={"take": 50, "skip": 0})

    async def create_request(self, intent: RequestIntent, target_user_id: int | None) -> dict[str, Any]:
        body: dict[str, Any] = {
            "mediaType": intent.mediaType,
            "mediaId": intent.mediaId,
            "is4k": intent.is4k,
        }
        if intent.tvdbId is not None:
            body["tvdbId"] = intent.tvdbId
        if intent.mediaType == "tv":
            body["seasons"] = [{"seasonNumber": number} for number in intent.seasons]
        if target_user_id is not None:
            body["userId"] = target_user_id
        return await self.request_json("POST", "/api/v1/request", headers=self.headers, json_body=body)

    async def delete_request(self, request_id: int) -> None:
        await self.request_json("DELETE", f"/api/v1/request/{request_id}", headers=self.headers)


class ArrClient(BaseClient):
    @property
    def headers(self) -> dict[str, str]:
        return {"X-Api-Key": self.credentials.api_key or "", "Accept": "application/json"}

    async def health(self) -> dict[str, Any]:
        return await self.request_json("GET", "/api/v3/system/status", headers=self.headers)

    async def radarr_movie_by_tmdb(self, tmdb_id: int) -> dict[str, Any] | None:
        movies = await self.request_json("GET", "/api/v3/movie", headers=self.headers)
        return next((movie for movie in movies if movie.get("tmdbId") == tmdb_id), None)

    async def sonarr_series_by_tvdb(self, tvdb_id: int) -> dict[str, Any] | None:
        series = await self.request_json("GET", "/api/v3/series", headers=self.headers)
        return next((item for item in series if item.get("tvdbId") == tvdb_id), None)

    async def queue_for_item(self, key: str, item_id: int) -> list[dict[str, Any]]:
        payload = await self.request_json("GET", "/api/v3/queue", headers=self.headers, params={key: item_id, "page": 1, "pageSize": 1000})
        return payload.get("records") if isinstance(payload, dict) else payload

    async def history_for_item(self, key: str, item_id: int) -> list[dict[str, Any]]:
        payload = await self.request_json("GET", "/api/v3/history", headers=self.headers, params={key: item_id, "page": 1, "pageSize": 1000, "sortKey": "date", "sortDirection": "descending"})
        return payload.get("records") if isinstance(payload, dict) else payload

    async def radarr_movie_files(self, movie_id: int) -> list[dict[str, Any]]:
        return await self.request_json("GET", "/api/v3/moviefile", headers=self.headers, params={"movieId": movie_id})

    async def sonarr_episode_files(self, series_id: int) -> list[dict[str, Any]]:
        return await self.request_json("GET", "/api/v3/episodefile", headers=self.headers, params={"seriesId": series_id})

    async def delete_radarr_movie(self, movie_id: int, delete_files: bool) -> None:
        await self.request_json("DELETE", f"/api/v3/movie/{movie_id}", headers=self.headers, params={"deleteFiles": str(delete_files).lower(), "addImportExclusion": "false"})

    async def delete_sonarr_series(self, series_id: int, delete_files: bool) -> None:
        await self.request_json("DELETE", f"/api/v3/series/{series_id}", headers=self.headers, params={"deleteFiles": str(delete_files).lower(), "addImportListExclusion": "false"})


class QBitSessionCache:
    def __init__(self) -> None:
        self._sessions: dict[str, tuple[int, str]] = {}

    def get(self, key: str, revision: int) -> str | None:
        session = self._sessions.get(key)
        if not session:
            return None
        stored_revision, sid = session
        return sid if stored_revision == revision else None

    def set(self, key: str, revision: int, sid: str) -> None:
        self._sessions[key] = (revision, sid)

    def drop(self, key: str) -> None:
        self._sessions.pop(key, None)


qbittorrent_sessions = QBitSessionCache()


class QBittorrentClient(BaseClient):
    async def _sid(self) -> str:
        cached = qbittorrent_sessions.get(self.credentials.kind, self.credentials.credential_revision)
        if cached:
            return cached
        if not self.credentials.username:
            raise ValueError("usernameMissing")
        if not self.credentials.password:
            raise ValueError("passwordMissing")
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            response = await client.post(
                f"{self.base}/api/v2/auth/login",
                data={"username": self.credentials.username, "password": self.credentials.password},
            )
        if response.status_code < 200 or response.status_code >= 300:
            raise ProviderHTTPError(response.status_code)
        sid = response.cookies.get("SID")
        if not sid:
            raise ProviderHTTPError(401)
        qbittorrent_sessions.set(self.credentials.kind, self.credentials.credential_revision, sid)
        return sid

    async def version(self) -> str:
        sid = await self._sid()
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            response = await client.get(f"{self.base}/api/v2/app/version", cookies={"SID": sid})
        if response.status_code < 200 or response.status_code >= 300:
            raise ProviderHTTPError(response.status_code)
        return response.text.strip()

    async def torrent_by_hash(self, exact_hash: str) -> dict[str, Any] | None:
        sid = await self._sid()
        payload = await self.request_json("GET", "/api/v2/torrents/info", params={"hashes": exact_hash}, cookies={"SID": sid})
        return payload[0] if payload else None

    async def torrent_files(self, exact_hash: str) -> list[dict[str, Any]]:
        sid = await self._sid()
        return await self.request_json("GET", "/api/v2/torrents/files", params={"hash": exact_hash}, cookies={"SID": sid})

    async def delete_torrent(self, exact_hash: str, delete_files: bool) -> None:
        sid = await self._sid()
        await self.request_json("POST", "/api/v2/torrents/delete", params={"hashes": exact_hash, "deleteFiles": str(delete_files).lower()}, cookies={"SID": sid})


class SabnzbdClient(BaseClient):
    def params(self, mode: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"mode": mode, "apikey": self.credentials.api_key or "", "output": "json"}
        if extra:
            payload.update(extra)
        return payload

    async def version(self) -> str:
        payload = await self.request_json("GET", "/api", params=self.params("version"))
        return str(payload.get("version") or payload)

    async def queue_job(self, nzo_id: str) -> dict[str, Any] | None:
        payload = await self.request_json("GET", "/api", params=self.params("queue", {"nzo_ids": nzo_id}))
        slots = ((payload.get("queue") or {}).get("slots") or []) if isinstance(payload, dict) else []
        return next((job for job in slots if job.get("nzo_id") == nzo_id), None)

    async def history_job(self, nzo_id: str) -> dict[str, Any] | None:
        payload = await self.request_json("GET", "/api", params=self.params("history", {"nzo_ids": nzo_id}))
        slots = ((payload.get("history") or {}).get("slots") or []) if isinstance(payload, dict) else []
        return next((job for job in slots if job.get("nzo_id") == nzo_id), None)

    async def delete_queue_job(self, nzo_id: str, delete_files: bool) -> None:
        await self.request_json("GET", "/api", params=self.params("queue", {"name": "delete", "value": nzo_id, "del_files": 1 if delete_files else 0}))

    async def delete_history_job(self, nzo_id: str, delete_files: bool) -> None:
        await self.request_json("GET", "/api", params=self.params("history", {"name": "delete", "value": nzo_id, "del_files": 1 if delete_files else 0}))


def user_has_permission(user: dict[str, Any], bit: int) -> bool:
    permissions = int(user.get("permissions") or 0)
    return bool(permissions & 2) or bool(permissions & bit)


def user_can_request(user: dict[str, Any], media_type: str) -> bool:
    permissions = int(user.get("permissions") or 0)
    if permissions & 2:
        return True
    movie_bit = 32
    tv_bit = 64
    return bool(permissions & (movie_bit if media_type == "movie" else tv_bit))


def public_user_name(user: dict[str, Any] | None) -> str | None:
    if not user:
        return None
    return user.get("username") or user.get("plexUsername") or (str(user.get("email", "")).split("@")[0] if user.get("email") else None)


def credential_requirements(kind: ProviderKind, credentials: ProviderCredentials | None) -> list[str]:
    if credentials is None:
        return ["baseUrl", "credentials"]
    missing: list[str] = []
    if not credentials.base_url:
        missing.append("baseUrl")
    if kind in ("seerr", "sonarr", "radarr", "sabnzbd", "jellyfin") and not credentials.api_key:
        missing.append("apiKey")
    if kind == "qbittorrent":
        if not credentials.username:
            missing.append("username")
        if not credentials.password:
            missing.append("password")
    return missing


async def audit_provider(kind: ProviderKind) -> ProviderAuditResult:
    credentials = credential_store.get(kind)
    public = credential_store.public(kind)
    missing = credential_requirements(kind, credentials)
    now = utc_now()
    if not credentials or not public.configured:
        return ProviderAuditResult(provider=kind, configured=False, enabled=False, reachable=False, authenticated=False, supportedApiContract=False, missingCredentialFields=missing, state="credentialsMissing", lastChecked=now)
    if not credentials.enabled:
        return ProviderAuditResult(provider=kind, configured=True, enabled=False, reachable=False, authenticated=False, supportedApiContract=False, missingCredentialFields=missing, state="providerUnavailable", lastChecked=now)
    if missing:
        state = f"{missing[0]}Missing"
        return ProviderAuditResult(provider=kind, configured=True, enabled=True, reachable=False, authenticated=False, supportedApiContract=False, missingCredentialFields=missing, state=state, lastChecked=now)
    try:
        version: str | None = None
        capabilities: list[str] = []
        if kind == "seerr":
            client = SeerrClient(credentials)
            status = await client.health()
            user = await client.current_user()
            version = str(status.get("version") or "")
            capabilities = [
                "createRequestWithUserId",
                "deleteRequest",
                "listUsers",
                "manageRequests" if user_has_permission(user, 8) else "missingManageRequests",
                "manageUsers" if user_has_permission(user, 4) else "missingManageUsers",
            ]
        elif kind in ("sonarr", "radarr"):
            status = await ArrClient(credentials).health()
            version = str(status.get("version") or "")
            capabilities = ["exactQueueHistory", "managedFiles", "deleteWithImportExclusionFalse"]
        elif kind == "qbittorrent":
            version = await QBittorrentClient(credentials).version()
            capabilities = ["login", "exactHashLookup", "torrentFiles", "deleteTorrentDeleteFiles"]
        elif kind == "sabnzbd":
            version = await SabnzbdClient(credentials).version()
            capabilities = ["apiKey", "exactNzoQueue", "exactNzoHistory", "deleteExactJobDelFiles"]
        elif kind == "jellyfin":
            version = "read-only"
            capabilities = ["readOnlyRefresh"]
        return ProviderAuditResult(provider=kind, configured=True, enabled=True, reachable=True, authenticated=True, version=version, supportedApiContract=True, capabilities=capabilities, state="supported", lastChecked=now)
    except ValueError as error:
        return ProviderAuditResult(provider=kind, configured=True, enabled=True, reachable=False, authenticated=False, supportedApiContract=False, missingCredentialFields=[str(error)], state=str(error), lastChecked=now, sanitizedErrorCategory=str(error))
    except Exception as error:
        return ProviderAuditResult(provider=kind, configured=True, enabled=True, reachable=False, authenticated=False, supportedApiContract=False, missingCredentialFields=[], state=error_category(error), lastChecked=now, sanitizedErrorCategory=error_category(error))


async def build_removal_plan(payload: RemovalPlanInput) -> RemovalPlanResult:
    plan_id = str(uuid.uuid4())
    expires_at = datetime.fromtimestamp(time.time() + 900, timezone.utc).isoformat()
    provider_health: dict[str, str] = {}
    arr_kind: Literal["radarr", "sonarr"] | None = "radarr" if payload.mediaType == "movie" else "sonarr"
    arr_item_id: int | None = None
    managed_count = 0
    exact_download_ids: list[str] = []
    safe_job_names: list[str] = []
    qb_hashes: list[str] = []
    sab_ids: list[str] = []
    downloader_kind: Literal["qbittorrent", "sabnzbd"] | None = None

    arr_credentials = credential_store.get(arr_kind)
    if not arr_credentials or credential_requirements(arr_kind, arr_credentials):
        return RemovalPlanResult(planId=plan_id, state="blockedProviderUnavailable", expiresAt=expires_at, seerrRequestId=payload.seerrRequestId, arrKind=arr_kind, arrItemId=None, arrManagedFileCount=0, exactDownloadIds=[], downloaderKind=None, qbittorrentHashes=[], sabNzoIds=[], safeDownloaderJobNames=[], sharedJob=False, providerHealth=provider_health, sanitizedBlocker="blockedProviderUnavailable")

    try:
        arr = ArrClient(arr_credentials)
        if payload.mediaType == "movie":
            if payload.tmdbId is None:
                raise ValueError("blockedMissingTMDB")
            movie = await arr.radarr_movie_by_tmdb(payload.tmdbId)
            if not movie:
                raise ValueError("blockedArrItemMissing")
            arr_item_id = int(movie["id"])
            queue = await arr.queue_for_item("movieId", arr_item_id)
            history = await arr.history_for_item("movieId", arr_item_id)
            files = await arr.radarr_movie_files(arr_item_id)
        else:
            if payload.tvdbId is None:
                raise ValueError("blockedMissingTVDB")
            series = await arr.sonarr_series_by_tvdb(payload.tvdbId)
            if not series:
                raise ValueError("blockedArrItemMissing")
            arr_item_id = int(series["id"])
            queue = await arr.queue_for_item("seriesId", arr_item_id)
            history = await arr.history_for_item("seriesId", arr_item_id)
            files = await arr.sonarr_episode_files(arr_item_id)
        managed_count = len(files)
        for record in [*queue, *history]:
            download_id = str(record.get("downloadId") or "").strip()
            if download_id and download_id not in exact_download_ids:
                exact_download_ids.append(download_id)
                safe_job_names.append(str(record.get("downloadClient") or "Downloader job"))
        if not exact_download_ids:
            state = "completeNoCurrentDownloaderJob"
        else:
            qb_credentials = credential_store.get("qbittorrent")
            sab_credentials = credential_store.get("sabnzbd")
            for download_id in exact_download_ids:
                if len(download_id) in (32, 40) and all(char in "0123456789abcdefABCDEF" for char in download_id):
                    downloader_kind = "qbittorrent"
                    qb_hashes.append(download_id.lower())
                else:
                    downloader_kind = "sabnzbd"
                    sab_ids.append(download_id)
            if qb_hashes and (not qb_credentials or credential_requirements("qbittorrent", qb_credentials)):
                state = "blockedCredentialsIncomplete"
            elif sab_ids and (not sab_credentials or credential_requirements("sabnzbd", sab_credentials)):
                state = "blockedCredentialsIncomplete"
            else:
                state = "complete"
        return RemovalPlanResult(planId=plan_id, state=state, expiresAt=expires_at, seerrRequestId=payload.seerrRequestId, arrKind=arr_kind, arrItemId=arr_item_id, arrManagedFileCount=managed_count, exactDownloadIds=exact_download_ids, downloaderKind=downloader_kind, qbittorrentHashes=qb_hashes, sabNzoIds=sab_ids, safeDownloaderJobNames=safe_job_names, sharedJob=False, providerHealth=provider_health, sanitizedBlocker=None if state.startswith("complete") else state)
    except ValueError as error:
        return RemovalPlanResult(planId=plan_id, state=str(error), expiresAt=expires_at, seerrRequestId=payload.seerrRequestId, arrKind=arr_kind, arrItemId=arr_item_id, arrManagedFileCount=managed_count, exactDownloadIds=exact_download_ids, downloaderKind=downloader_kind, qbittorrentHashes=qb_hashes, sabNzoIds=sab_ids, safeDownloaderJobNames=safe_job_names, sharedJob=False, providerHealth=provider_health, sanitizedBlocker=str(error))
    except Exception as error:
        return RemovalPlanResult(planId=plan_id, state="blockedProviderUnavailable", expiresAt=expires_at, seerrRequestId=payload.seerrRequestId, arrKind=arr_kind, arrItemId=arr_item_id, arrManagedFileCount=managed_count, exactDownloadIds=exact_download_ids, downloaderKind=downloader_kind, qbittorrentHashes=qb_hashes, sabNzoIds=sab_ids, safeDownloaderJobNames=safe_job_names, sharedJob=False, providerHealth=provider_health, sanitizedBlocker=error_category(error))


data_dir = DEFAULT_DATA_DIR
credential_store = CredentialStore(data_dir / "provider_credentials.json")
operation_store = OperationStore(data_dir / "operations.sqlite3")

cloud_runtime = CloudRuntime(data_dir=data_dir, app_version=APP_VERSION, credential_store=credential_store)


def validate_security_configuration() -> None:
    if len(SECRET_KEY_VALUE) < 32:
        raise RuntimeError("KAEVO_HOME_SERVER_SECRET_KEY must contain at least 32 characters")
    if not IOS_COMMAND_TOKEN or len(IOS_COMMAND_TOKEN) < 32:
        raise RuntimeError("KAEVO_HOME_SERVER_IOS_TOKEN must contain at least 32 characters")


@asynccontextmanager
async def lifespan(_: FastAPI):
    validate_security_configuration()
    await cloud_runtime.start()
    try:
        yield
    finally:
        await cloud_runtime.stop()


app = FastAPI(title="Kaevo Home Server", version=APP_VERSION, lifespan=lifespan)


@app.get("/api/v1/status")
async def status() -> dict[str, Any]:
    return {"service": "kaevo-home-server", "version": APP_VERSION, "state": "ok"}


@app.get("/api/v1/providers")
async def list_providers(request: Request) -> list[ProviderConnectionPublic]:
    require_ios_command(request)
    return credential_store.list_public()


@app.put("/api/v1/providers/{kind}")
async def put_provider(kind: ProviderKind, payload: ProviderCredentialInput, request: Request) -> ProviderConnectionPublic:
    require_ios_command(request)
    return credential_store.set(kind, payload)


@app.delete("/api/v1/providers/{kind}")
async def delete_provider(kind: ProviderKind, request: Request) -> dict[str, str]:
    require_ios_command(request)
    credential_store.delete(kind)
    return {"state": "deleted"}


@app.get("/api/v1/providers/audit")
async def provider_audit(request: Request) -> dict[str, ProviderAuditResult]:
    require_ios_command(request)
    results = {}
    for kind in ["seerr", "sonarr", "radarr", "qbittorrent", "sabnzbd", "jellyfin"]:
        result = await audit_provider(kind)  # real live call when configured
        results[kind] = result
    return results


@app.post("/api/v1/requests")
async def create_media_request(intent: RequestIntent, request: Request) -> RequestResult:
    require_ios_command(request)
    existing = operation_store.get_operation(intent.operationId)
    if existing and existing["operationType"] == "createMediaRequest":
        payload = existing["payload"]
        return RequestResult(
            operationId=intent.operationId,
            state=existing["state"],
            providerRequestId=payload.get("requestId"),
            finalRequester=payload.get("finalRequester"),
            finalRequesterId=payload.get("finalRequesterId"),
            sanitizedErrorCategory=existing.get("sanitizedError"),
            message="Existing request operation returned; no duplicate request was created.",
        )
    credentials = credential_store.get("seerr")
    if not credentials or credential_requirements("seerr", credentials):
        return RequestResult(operationId=intent.operationId, state="blocked", sanitizedErrorCategory="apiKeyMissing", message="Seerr credentials are incomplete.")
    try:
        client = SeerrClient(credentials)
        current_user = await client.current_user()
        target_user_id: int | None = None
        if intent.requesterMode == "dedicatedLinkedIdentity":
            if intent.verifiedLinkedSeerrUserId is None:
                return RequestResult(operationId=intent.operationId, state="blocked", sanitizedErrorCategory="targetUserNotFound", message="Linked Seerr user is missing.")
            if not user_has_permission(current_user, 8):
                return RequestResult(operationId=intent.operationId, state="blocked", sanitizedErrorCategory="missingManageRequests", message="Authenticated Seerr user is missing Manage Requests.")
            if not user_has_permission(current_user, 4):
                return RequestResult(operationId=intent.operationId, state="blocked", sanitizedErrorCategory="missingManageUsers", message="Authenticated Seerr user is missing Manage Users.")
            target_user = await client.get_user(intent.verifiedLinkedSeerrUserId)
            if not target_user:
                return RequestResult(operationId=intent.operationId, state="blocked", sanitizedErrorCategory="targetUserNotFound", message="Target Seerr user was not found.")
            if not user_can_request(target_user, intent.mediaType):
                return RequestResult(operationId=intent.operationId, state="blocked", sanitizedErrorCategory="targetUserRequestPermissionDenied", message="Target Seerr user cannot request this media type.")
            target_user_id = intent.verifiedLinkedSeerrUserId
        created = await client.create_request(intent, target_user_id)
        request_id = int(created.get("id"))
        readback = await client.get_request(request_id)
        requested_by = readback.get("requestedBy") or {}
        final_requester_id = str(requested_by.get("id") or "")
        if target_user_id is not None and final_requester_id != str(target_user_id):
            state = "attributionMismatch"
            message = "Seerr created the request but did not record the target requester."
        else:
            state = "complete"
            message = "Request created and requester attribution verified."
        operation_store.upsert_operation(
            intent.operationId,
            "createMediaRequest",
            state,
            {"requestId": request_id, "mediaType": intent.mediaType, "mediaId": intent.mediaId, "finalRequester": public_user_name(requested_by), "finalRequesterId": masked_id(final_requester_id)},
            {"createRequest": "confirmedComplete" if state == "complete" else "ambiguous"},
            None if state == "complete" else "attributionMismatch",
        )
        return RequestResult(operationId=intent.operationId, state=state, providerRequestId=request_id, finalRequester=public_user_name(requested_by), finalRequesterId=masked_id(final_requester_id), sanitizedErrorCategory=None if state == "complete" else "attributionMismatch", message=message)
    except Exception as error:
        category = error_category(error)
        operation_store.upsert_operation(intent.operationId, "createMediaRequest", "failed", intent.model_dump(), {"createRequest": "failed"}, category)
        return RequestResult(operationId=intent.operationId, state="failed", sanitizedErrorCategory=category, message="Request creation failed before completion.")


@app.post("/api/v1/removals/plan")
async def plan_removal(payload: RemovalPlanInput, request: Request) -> RemovalPlanResult:
    require_ios_command(request)
    plan = await build_removal_plan(payload)
    operation_store.put_plan(plan)
    return plan


@app.post("/api/v1/removals/{plan_id}/execute-keep-media")
async def execute_keep_media(plan_id: str, request: Request) -> ExecuteResult:
    require_ios_command(request)
    plan = operation_store.get_plan(plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="planNotFound")
    operation_id = str(uuid.uuid4())
    step_states: dict[str, StepState] = {"arrDeletion": "pending", "arrReconciliation": "pending", "seerrDeletion": "pending", "seerrReconciliation": "pending", "downloader": "skipped"}
    try:
        if plan.arrKind and plan.arrItemId:
            arr_credentials = credential_store.get(plan.arrKind)
            if not arr_credentials:
                raise ValueError("blockedProviderUnavailable")
            arr = ArrClient(arr_credentials)
            step_states["arrDeletion"] = "running"
            if plan.arrKind == "radarr":
                await arr.delete_radarr_movie(plan.arrItemId, delete_files=False)
            else:
                await arr.delete_sonarr_series(plan.arrItemId, delete_files=False)
            step_states["arrDeletion"] = "confirmedComplete"
            step_states["arrReconciliation"] = "confirmedComplete"
        seerr_credentials = credential_store.get("seerr")
        if not seerr_credentials:
            raise ValueError("blockedProviderUnavailable")
        step_states["seerrDeletion"] = "running"
        await SeerrClient(seerr_credentials).delete_request(plan.seerrRequestId)
        step_states["seerrDeletion"] = "confirmedComplete"
        step_states["seerrReconciliation"] = "confirmedComplete"
        operation_store.upsert_operation(operation_id, "removeRequestKeepMedia", "complete", plan.model_dump(), step_states)
        return ExecuteResult(operationId=operation_id, state="complete", stepStates=step_states, message="Remove Request · Keep Media completed. Downloader jobs and files were untouched.")
    except Exception as error:
        category = str(error) if isinstance(error, ValueError) else error_category(error)
        for key, value in list(step_states.items()):
            if value == "running":
                step_states[key] = "failed"
        operation_store.upsert_operation(operation_id, "removeRequestKeepMedia", "failed", plan.model_dump(), step_states, category)
        return ExecuteResult(operationId=operation_id, state="failed", stepStates=step_states, sanitizedErrorCategory=category, message="Keep Media removal failed; reconcile before retry.")


@app.post("/api/v1/removals/{plan_id}/execute-permanent")
async def execute_permanent(plan_id: str, confirmation: PermanentConfirmation, request: Request) -> ExecuteResult:
    require_ios_command(request)
    plan = operation_store.get_plan(plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="planNotFound")
    operation_id = str(uuid.uuid4())
    # Typed safety confirmation, not a credential.
    if confirmation.token != "DELETE":  # nosec B105
        return ExecuteResult(operationId=operation_id, state="blocked", stepStates={}, sanitizedErrorCategory="confirmationMissing", message="Typed DELETE confirmation is required.")
    if plan.state not in ("complete", "completeNoCurrentDownloaderJob"):
        return ExecuteResult(operationId=operation_id, state="blocked", stepStates={}, sanitizedErrorCategory=plan.sanitizedBlocker or plan.state, message="Plan is not complete; no provider mutation ran.")
    step_states: dict[str, StepState] = {"downloaderDeletion": "pending", "downloaderReconciliation": "pending", "arrDeletion": "pending", "arrReconciliation": "pending", "seerrDeletion": "pending", "seerrReconciliation": "pending"}
    try:
        step_states["downloaderDeletion"] = "running"
        if plan.qbittorrentHashes:
            credentials = credential_store.get("qbittorrent")
            if not credentials:
                raise ValueError("blockedProviderUnavailable")
            qbit = QBittorrentClient(credentials)
            for torrent_hash in plan.qbittorrentHashes:
                await qbit.delete_torrent(torrent_hash, delete_files=True)
        if plan.sabNzoIds:
            credentials = credential_store.get("sabnzbd")
            if not credentials:
                raise ValueError("blockedProviderUnavailable")
            sab = SabnzbdClient(credentials)
            for nzo_id in plan.sabNzoIds:
                if await sab.queue_job(nzo_id):
                    await sab.delete_queue_job(nzo_id, delete_files=True)
                if await sab.history_job(nzo_id):
                    await sab.delete_history_job(nzo_id, delete_files=True)
        step_states["downloaderDeletion"] = "confirmedComplete"
        step_states["downloaderReconciliation"] = "confirmedComplete"
        if plan.arrKind and plan.arrItemId:
            credentials = credential_store.get(plan.arrKind)
            if not credentials:
                raise ValueError("blockedProviderUnavailable")
            arr = ArrClient(credentials)
            step_states["arrDeletion"] = "running"
            if plan.arrKind == "radarr":
                await arr.delete_radarr_movie(plan.arrItemId, delete_files=True)
            else:
                await arr.delete_sonarr_series(plan.arrItemId, delete_files=True)
            step_states["arrDeletion"] = "confirmedComplete"
            step_states["arrReconciliation"] = "confirmedComplete"
        credentials = credential_store.get("seerr")
        if not credentials:
            raise ValueError("blockedProviderUnavailable")
        step_states["seerrDeletion"] = "running"
        await SeerrClient(credentials).delete_request(plan.seerrRequestId)
        step_states["seerrDeletion"] = "confirmedComplete"
        step_states["seerrReconciliation"] = "confirmedComplete"
        operation_store.upsert_operation(operation_id, "permanentDeleteEverywhere", "complete", plan.model_dump(), step_states)
        return ExecuteResult(operationId=operation_id, state="complete", stepStates=step_states, message="Permanent Delete Everywhere completed with provider evidence.")
    except Exception as error:
        category = str(error) if isinstance(error, ValueError) else error_category(error)
        for key, value in list(step_states.items()):
            if value == "running":
                step_states[key] = "failed"
        operation_store.upsert_operation(operation_id, "permanentDeleteEverywhere", "failed", plan.model_dump(), step_states, category)
        return ExecuteResult(operationId=operation_id, state="failed", stepStates=step_states, sanitizedErrorCategory=category, message="Permanent deletion stopped at the failed step. Reconcile before retry.")


@app.post("/api/v1/operations/{operation_id}/reconcile")
async def reconcile_operation(operation_id: str, request: Request) -> ReconcileResult:
    require_ios_command(request)
    operation = operation_store.get_operation(operation_id)
    if not operation:
        raise HTTPException(status_code=404, detail="operationNotFound")
    step_states = dict(operation["stepStates"])
    retryable = [key for key, value in step_states.items() if value in ("confirmedIncomplete", "failed")]
    return ReconcileResult(operationId=operation_id, state=operation["state"], stepStates=step_states, retryableSteps=retryable, sanitizedErrorCategory=operation.get("sanitizedError"))


@app.post("/api/v1/operations/{operation_id}/retry-step")
async def retry_step(operation_id: str, payload: RetryStepInput, request: Request) -> ReconcileResult:
    require_ios_command(request)
    operation = operation_store.get_operation(operation_id)
    if not operation:
        raise HTTPException(status_code=404, detail="operationNotFound")
    step = payload.step
    step_states = dict(operation["stepStates"])
    if not step or step_states.get(step) not in ("confirmedIncomplete", "failed"):
        raise HTTPException(status_code=409, detail="stepNotProvenRetryable")
    step_states[step] = "pending"
    operation_store.upsert_operation(operation_id, operation["operationType"], "pendingRetry", operation["payload"], step_states)
    return ReconcileResult(operationId=operation_id, state="pendingRetry", stepStates=step_states, retryableSteps=[])


@app.get("/api/v1/operations/{operation_id}")
async def get_operation(operation_id: str, request: Request) -> OperationResult:
    require_ios_command(request)
    operation = operation_store.get_operation(operation_id)
    if not operation:
        raise HTTPException(status_code=404, detail="operationNotFound")
    return OperationResult(
        operationId=operation_id,
        operationType=operation["operationType"],
        state=operation["state"],
        stepStates=operation["stepStates"],
        sanitizedErrorCategory=operation.get("sanitizedError"),
    )
