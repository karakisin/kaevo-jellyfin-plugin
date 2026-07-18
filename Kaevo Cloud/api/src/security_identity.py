"""Production identity and sender-constrained session primitives for Kaevo Cloud.

JWT authenticity is established by the API Gateway Cognito authorizer. This
module validates the resulting claims against authoritative Kaevo records and
verifies RFC 9449 DPoP proofs for installation-bound sessions. It deliberately
contains no development-key fallback.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping

import jwt
from cryptography.hazmat.primitives.asymmetric import ec


ACCESS_TOKEN_TTL_SECONDS = 15 * 60
REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60
RECENT_AUTH_MAX_AGE_SECONDS = 5 * 60
DPOP_MAX_AGE_SECONDS = 60


class IdentityError(Exception):
    """Fail-closed identity error with a non-sensitive public reason."""

    def __init__(self, reason: str, status_code: int = 403):
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


class Role(str, Enum):
    OWNER = "owner"
    ADULT = "adult"
    CHILD = "child"
    DEVICE = "device"
    CONNECTOR = "connector"
    SUPPORT = "support"


CAPABILITIES: dict[Role, frozenset[str]] = {
    Role.CHILD: frozenset({"browse", "playback", "request_child_safe"}),
    Role.ADULT: frozenset({"browse", "playback", "request_media", "manage_lists"}),
    Role.OWNER: frozenset({
        "browse", "playback", "request_media", "manage_lists",
        "manage_household", "manage_parental_policy", "configure_providers",
        "pair_connector", "revoke_connector", "revoke_device", "delete_media",
        "run_optimizer", "delete_download", "recover_account", "register_device",
    }),
    Role.DEVICE: frozenset({"register_device", "refresh_device_session"}),
    Role.CONNECTOR: frozenset({"connector_heartbeat", "connector_claim", "connector_complete"}),
    Role.SUPPORT: frozenset({"read_security_audit", "disable_compromised_session"}),
}

RECENT_AUTH_CAPABILITIES = frozenset({
    "manage_household", "manage_parental_policy", "configure_providers",
    "pair_connector", "revoke_connector", "revoke_device", "delete_media",
    "run_optimizer", "delete_download", "recover_account",
    "register_device",
})


def _claim(claims: Mapping[str, Any], name: str) -> str:
    value = claims.get(name)
    if value is None:
        value = claims.get(f"custom:{name}")
    return str(value or "").strip()


def gateway_jwt_claims(event: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return only claims produced by API Gateway's verified JWT authorizer."""
    authorizer = (((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {})
    claims = authorizer.get("claims")
    return claims if isinstance(claims, Mapping) else {}


@dataclass(frozen=True)
class IdentityContext:
    subject: str
    account_id: str
    household_id: str
    profile_id: str
    role: Role
    authz_version: int
    authentication_time: int

    @classmethod
    def from_gateway_event(cls, event: Mapping[str, Any]) -> "IdentityContext":
        claims = gateway_jwt_claims(event)
        try:
            role = Role(_claim(claims, "role"))
            authz_version = int(_claim(claims, "authz_version"))
            authentication_time = int(_claim(claims, "auth_time"))
        except (TypeError, ValueError):
            raise IdentityError("invalid_identity_claims", 401)
        context = cls(
            subject=_claim(claims, "sub"),
            account_id=_claim(claims, "account_id"),
            household_id=_claim(claims, "household_id"),
            profile_id=_claim(claims, "profile_id"),
            role=role,
            authz_version=authz_version,
            authentication_time=authentication_time,
        )
        if not all((context.subject, context.account_id, context.household_id)):
            raise IdentityError("invalid_identity_claims", 401)
        return context


def authorize(
    context: IdentityContext,
    authoritative_principal: Mapping[str, Any],
    capability: str,
    *,
    target: Mapping[str, Any] | None = None,
    now: int | None = None,
) -> None:
    """Authorize from server records; client identifiers are never authority."""
    if authoritative_principal.get("revoked") or authoritative_principal.get("state") != "active":
        raise IdentityError("identity_revoked", 401)
    expected = {
        "principal_id": context.subject,
        "account_id": context.account_id,
        "household_id": context.household_id,
        "role": context.role.value,
    }
    for key, value in expected.items():
        if not hmac.compare_digest(str(authoritative_principal.get(key) or ""), value):
            raise IdentityError("identity_relationship_mismatch", 403)
    if int(authoritative_principal.get("authz_version") or -1) != context.authz_version:
        raise IdentityError("stale_authorization", 401)
    permitted_profiles = {str(value) for value in authoritative_principal.get("profile_ids") or []}
    if context.profile_id and context.profile_id not in permitted_profiles:
        raise IdentityError("target_not_found", 404)
    if capability not in CAPABILITIES[context.role]:
        raise IdentityError("capability_denied", 403)
    if capability in RECENT_AUTH_CAPABILITIES:
        current = int(time.time()) if now is None else now
        if context.role is not Role.OWNER or current - context.authentication_time > RECENT_AUTH_MAX_AGE_SECONDS:
            raise IdentityError("recent_auth_required", 401)
    if target:
        for key, expected_value in (("account_id", context.account_id), ("household_id", context.household_id)):
            actual = str(target.get(key) or "")
            if not actual or not hmac.compare_digest(actual, expected_value):
                # Do not reveal whether a cross-tenant target exists.
                raise IdentityError("target_not_found", 404)
        target_profile = str(target.get("profile_id") or "")
        if target_profile and target_profile not in permitted_profiles:
            raise IdentityError("target_not_found", 404)


def base64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def validate_public_jwk(jwk: Mapping[str, Any]) -> dict[str, str]:
    allowed = {key: str(jwk.get(key) or "") for key in ("kty", "crv", "x", "y")}
    if allowed["kty"] != "EC" or allowed["crv"] != "P-256":
        raise IdentityError("unsupported_installation_key", 400)
    try:
        x = int.from_bytes(base64url_decode(allowed["x"]), "big")
        y = int.from_bytes(base64url_decode(allowed["y"]), "big")
        ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except Exception as error:
        raise IdentityError("invalid_installation_key", 400) from error
    return allowed


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    canonical = validate_public_jwk(jwk)
    encoded = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64url_encode(hashlib.sha256(encoded).digest())


def verify_dpop(
    proof: str,
    *,
    method: str,
    url: str,
    expected_thumbprint: str,
    access_token: str | None = None,
    replay_guard: Callable[[str, int], bool] | None = None,
    now: int | None = None,
) -> Mapping[str, Any]:
    """Verify an ES256 RFC 9449 proof and reject replay."""
    try:
        header = jwt.get_unverified_header(proof)
        if header.get("typ", "").lower() != "dpop+jwt" or header.get("alg") != "ES256":
            raise IdentityError("invalid_dpop", 401)
        public_jwk = validate_public_jwk(header.get("jwk") or {})
        if not hmac.compare_digest(jwk_thumbprint(public_jwk), expected_thumbprint):
            raise IdentityError("installation_key_mismatch", 401)
        public_key = jwt.PyJWK.from_dict(public_jwk).key
        claims = jwt.decode(
            proof,
            public_key,
            algorithms=["ES256"],
            options={"require": ["htm", "htu", "iat", "jti"], "verify_aud": False},
        )
    except IdentityError:
        raise
    except Exception as error:
        raise IdentityError("invalid_dpop", 401) from error
    current = int(time.time()) if now is None else now
    if str(claims.get("htm") or "").upper() != method.upper():
        raise IdentityError("dpop_method_mismatch", 401)
    if not hmac.compare_digest(str(claims.get("htu") or ""), url):
        raise IdentityError("dpop_url_mismatch", 401)
    if abs(current - int(claims.get("iat") or 0)) > DPOP_MAX_AGE_SECONDS:
        raise IdentityError("stale_dpop", 401)
    if access_token is not None:
        expected_ath = base64url_encode(hashlib.sha256(access_token.encode("ascii")).digest())
        if not hmac.compare_digest(str(claims.get("ath") or ""), expected_ath):
            raise IdentityError("dpop_access_token_mismatch", 401)
    jti = str(claims.get("jti") or "")
    if not jti or (replay_guard is not None and not replay_guard(jti, current + DPOP_MAX_AGE_SECONDS)):
        raise IdentityError("dpop_replay", 401)
    return claims


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def new_session_material(
    identity: IdentityContext,
    installation: Mapping[str, Any],
    *,
    connector_id: str = "",
    now: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    current = int(time.time()) if now is None else now
    family_id = secrets.token_urlsafe(24)
    access_token = secrets.token_urlsafe(48)
    refresh_token = secrets.token_urlsafe(64)
    common = {
        "family_id": family_id,
        "principal_id": identity.subject,
        "account_id": identity.account_id,
        "household_id": identity.household_id,
        "profile_id": identity.profile_id,
        "role": identity.role.value,
        "authz_version": identity.authz_version,
        "installation_id": str(installation.get("installation_id") or ""),
        "device_id": str(installation.get("device_id") or ""),
        "connector_id": connector_id,
        "key_thumbprint": str(installation.get("key_thumbprint") or ""),
        "state": "active",
        "created_at_epoch": current,
    }
    access = {**common, "token_hash": f"access#{token_hash(access_token)}", "record_type": "access", "expires_at": current + ACCESS_TOKEN_TTL_SECONDS}
    refresh = {**common, "token_hash": f"refresh#{token_hash(refresh_token)}", "record_type": "refresh", "expires_at": current + REFRESH_TOKEN_TTL_SECONDS}
    return access, refresh, access_token, refresh_token


def rotate_refresh_record(record: Mapping[str, Any], *, now: int | None = None) -> tuple[dict[str, Any], dict[str, Any], str, str, dict[str, Any]]:
    current = int(time.time()) if now is None else now
    if record.get("record_type") != "refresh" or record.get("state") != "active" or int(record.get("expires_at") or 0) < current:
        raise IdentityError("refresh_reuse_or_expired", 401)
    access_token = secrets.token_urlsafe(48)
    refresh_token = secrets.token_urlsafe(64)
    common = {key: value for key, value in record.items() if key not in {"token_hash", "record_type", "expires_at", "state", "rotated_at_epoch", "replacement_hash"}}
    access = {**common, "token_hash": f"access#{token_hash(access_token)}", "record_type": "access", "state": "active", "expires_at": current + ACCESS_TOKEN_TTL_SECONDS}
    refresh = {**common, "token_hash": f"refresh#{token_hash(refresh_token)}", "record_type": "refresh", "state": "active", "expires_at": min(int(record.get("expires_at") or 0), current + REFRESH_TOKEN_TTL_SECONDS)}
    consumed = {**record, "state": "consumed", "rotated_at_epoch": current, "replacement_hash": refresh["token_hash"]}
    return access, refresh, access_token, refresh_token, consumed
