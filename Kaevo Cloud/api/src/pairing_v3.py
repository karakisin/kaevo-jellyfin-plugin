"""Pure cryptographic primitives for Kaevo Pairing Protocol V3.

This module deliberately has no AWS, HTTP, or logging dependency.  The same
fixed vectors can be reproduced by Swift CryptoKit and .NET cryptography code.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL = "kaevo-pairing-v3"
CHALLENGE_KEY_SALT = b"kaevo-pairing-v3/challenge-signing-salt"
CHALLENGE_KEY_INFO = b"kaevo-pairing-v3/challenge-signing-key"
TRANSCRIPT_PREFIX = b"KAEVO-PAIRING-V3\x00"
AUTHORIZATION_AUDIENCE = "kaevo-home-connectors-pairing-v3"
AUTHORIZATION_TYPE = "kaevo-pairing-authorization+jwt"
CANONICAL_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CANONICAL_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class PairingV3CryptoError(ValueError):
    """A malformed or invalid V3 cryptographic value."""


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        raise PairingV3CryptoError("invalid base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise PairingV3CryptoError("invalid base64url") from error


def sha256_b64url(value: bytes) -> str:
    return b64url_encode(hashlib.sha256(value).digest())


def canonical_uuid(value: str) -> str:
    if not isinstance(value, str) or not CANONICAL_UUID.fullmatch(value):
        raise PairingV3CryptoError("invalid canonical uuid")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise PairingV3CryptoError("invalid canonical uuid") from error
    if str(parsed) != value:
        raise PairingV3CryptoError("invalid canonical uuid")
    return value


def canonical_timestamp(value: str) -> str:
    if not isinstance(value, str) or not CANONICAL_TIMESTAMP.fullmatch(value):
        raise PairingV3CryptoError("invalid canonical timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise PairingV3CryptoError("invalid canonical timestamp") from error
    return value


def utc_timestamp(epoch_seconds: int) -> str:
    return datetime.fromtimestamp(int(epoch_seconds), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def derive_challenge_signing_seed(ticket_secret: bytes, ticket_id: str) -> bytes:
    if not isinstance(ticket_secret, bytes) or len(ticket_secret) != 32:
        raise PairingV3CryptoError("ticket secret must be 32 bytes")
    if not isinstance(ticket_id, str) or not ticket_id or len(ticket_id.encode("utf-8")) > 256:
        raise PairingV3CryptoError("invalid ticket id")
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=CHALLENGE_KEY_SALT,
        info=CHALLENGE_KEY_INFO + ticket_id.encode("utf-8"),
    ).derive(ticket_secret)


def ed25519_public_key_from_seed(seed: bytes) -> bytes:
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise PairingV3CryptoError("ed25519 seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def plugin_fingerprint(public_key: bytes) -> str:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise PairingV3CryptoError("ed25519 public key must be 32 bytes")
    return f"sha256:{sha256_b64url(public_key)}"


def _field(name: str, value: str) -> bytes:
    if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*", name):
        raise PairingV3CryptoError("invalid transcript field name")
    if not isinstance(value, str) or "\x00" in value:
        raise PairingV3CryptoError("invalid transcript field value")
    encoded_name = name.encode("utf-8")
    encoded_value = value.encode("utf-8")
    if len(encoded_value) > 65535:
        raise PairingV3CryptoError("transcript field is too large")
    return encoded_name + b"\x00" + len(encoded_value).to_bytes(4, "big") + encoded_value


def canonical_transcript(operation: str, fields: Iterable[tuple[str, str]]) -> bytes:
    if operation not in {"challenge-response", "challenge-response-issued", "redemption", "attempt-status", "connector-request"}:
        raise PairingV3CryptoError("unsupported transcript operation")
    output = bytearray(TRANSCRIPT_PREFIX)
    output.extend(_field("protocol", PROTOCOL))
    output.extend(_field("operation", operation))
    for name, value in fields:
        output.extend(_field(name, value))
    return bytes(output)


def challenge_transcript(*, ticket_id: str, challenge_id: str, challenge_nonce: str,
                         pairing_attempt_id: str, plugin_instance_id: str,
                         plugin_public_key_fingerprint: str, jellyfin_server_id: str,
                         issued_at: str, expires_at: str, local_completion_route: str,
                         pairing_authorization_hash: str) -> bytes:
    canonical_uuid(pairing_attempt_id)
    canonical_timestamp(issued_at)
    canonical_timestamp(expires_at)
    return canonical_transcript("challenge-response", (
        ("ticketId", ticket_id), ("challengeId", challenge_id), ("challengeNonce", challenge_nonce),
        ("pairingAttemptId", pairing_attempt_id), ("pluginInstanceId", plugin_instance_id),
        ("pluginPublicKeyFingerprint", plugin_public_key_fingerprint),
        ("jellyfinServerId", jellyfin_server_id), ("challengeIssuedAt", issued_at),
        ("challengeExpiresAt", expires_at), ("localCompletionRoute", local_completion_route),
        ("pairingAuthorizationHash", pairing_authorization_hash),
    ))


def redemption_transcript(*, method: str, route: str, body_digest: str, timestamp: str,
                           nonce: str, pairing_attempt_id: str, authorization_jti: str,
                           plugin_instance_id: str, plugin_public_key_fingerprint: str,
                           jellyfin_server_id: str) -> bytes:
    canonical_uuid(pairing_attempt_id)
    return canonical_transcript("redemption", (
        ("httpMethod", method.upper()), ("canonicalRoute", route), ("bodyDigest", body_digest),
        ("timestamp", timestamp), ("nonce", nonce), ("pairingAttemptId", pairing_attempt_id),
        ("authorizationJti", authorization_jti), ("pluginInstanceId", plugin_instance_id),
        ("pluginPublicKeyFingerprint", plugin_public_key_fingerprint), ("jellyfinServerId", jellyfin_server_id),
    ))


def sign_ed25519(seed: bytes, message: bytes) -> str:
    if not isinstance(message, bytes):
        raise PairingV3CryptoError("message must be bytes")
    return b64url_encode(Ed25519PrivateKey.from_private_bytes(seed).sign(message))


def verify_ed25519(public_key: bytes, message: bytes, signature: str) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(b64url_decode(signature), message)
    except (ValueError, TypeError) as error:
        raise PairingV3CryptoError("invalid ed25519 signature") from error
    except Exception as error:  # InvalidSignature intentionally becomes an opaque protocol error.
        raise PairingV3CryptoError("invalid ed25519 signature") from error


def canonical_json_digest(value: object) -> str:
    return sha256_b64url(json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8"))


class _RawJsonNumber:
    """A validated JSON number token whose original spelling must be retained."""

    def __init__(self, token: str):
        self.token = token


def _reject_json_constant(value: str):
    raise PairingV3CryptoError(f"non-standard JSON number: {value}")


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PairingV3CryptoError("duplicate JSON object key")
        result[key] = value
    return result


def _utf16_ordinal_key(value: str) -> bytes:
    """Match .NET StringComparer.Ordinal's UTF-16 code-unit ordering."""
    return value.encode("utf-16-be", errors="surrogatepass")


def _dotnet_unsafe_relaxed_json_string(value: str) -> str:
    """Match Utf8JsonWriter with UnsafeRelaxedJsonEscaping for strings."""
    output = ['"']
    short_escapes = {
        '"': '\\"',
        "\\": "\\\\",
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
    }
    for character in value:
        escaped = short_escapes.get(character)
        if escaped is not None:
            output.append(escaped)
            continue
        codepoint = ord(character)
        category = unicodedata.category(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise PairingV3CryptoError("unpaired JSON string surrogate")
        if codepoint > 0xFFFF:
            scalar = codepoint - 0x10000
            output.append(f"\\u{0xD800 + (scalar >> 10):04X}\\u{0xDC00 + (scalar & 0x3FF):04X}")
        elif (
            category in {"Cc", "Co", "Cn", "Zl", "Zp"}
            or (category == "Zs" and codepoint != 0x20)
        ):
            output.append(f"\\u{codepoint:04X}")
        else:
            output.append(character)
    output.append('"')
    return "".join(output)


def _canonical_raw_json(value: object, output: list[str]) -> None:
    if value is None:
        output.append("null")
    elif value is True:
        output.append("true")
    elif value is False:
        output.append("false")
    elif isinstance(value, _RawJsonNumber):
        output.append(value.token)
    elif isinstance(value, str):
        output.append(_dotnet_unsafe_relaxed_json_string(value))
    elif isinstance(value, list):
        output.append("[")
        for index, item in enumerate(value):
            if index:
                output.append(",")
            _canonical_raw_json(item, output)
        output.append("]")
    elif isinstance(value, dict):
        output.append("{")
        for index, key in enumerate(sorted(value, key=_utf16_ordinal_key)):
            if index:
                output.append(",")
            output.append(_dotnet_unsafe_relaxed_json_string(key))
            output.append(":")
            _canonical_raw_json(value[key], output)
        output.append("}")
    else:
        raise PairingV3CryptoError("unsupported JSON value")


def canonical_json_digest_preserving_number_lexemes(raw_json: str) -> str:
    """Canonicalize exact JSON while retaining the sender's number lexemes.

    System.Text.Json preserves provider number spellings and applies
    UnsafeRelaxedJsonEscaping when a JsonElement is written to the plugin's
    canonical stream.  Python's normal json.loads then json.dumps path does not
    match either behavior.  This strict parser retains only validated number
    tokens, rejects duplicate keys and non-standard constants, and reproduces
    the plugin's string escaping and recursive key ordering.
    """
    if not isinstance(raw_json, str):
        raise PairingV3CryptoError("JSON body must be text")
    try:
        parsed = json.loads(
            raw_json,
            parse_int=_RawJsonNumber,
            parse_float=_RawJsonNumber,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_json_object,
        )
        output: list[str] = []
        _canonical_raw_json(parsed, output)
        return sha256_b64url("".join(output).encode("utf-8"))
    except PairingV3CryptoError:
        raise
    except (json.JSONDecodeError, TypeError, UnicodeError, ValueError) as error:
        raise PairingV3CryptoError("invalid JSON body") from error


def sign_authorization(seed: bytes, key_id: str, claims: dict) -> str:
    header = {"alg": "EdDSA", "kid": key_id, "typ": AUTHORIZATION_TYPE}
    encoded_header = b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    encoded_claims = b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = sign_ed25519(seed, f"{encoded_header}.{encoded_claims}".encode("ascii"))
    return f"{encoded_header}.{encoded_claims}.{signature}"


@dataclass(frozen=True)
class VerifiedAuthorization:
    header: dict
    claims: dict
    token_hash: str


def verify_authorization(token: str, public_key: bytes) -> VerifiedAuthorization:
    if not isinstance(token, str) or token.count(".") != 2 or len(token) > 8192:
        raise PairingV3CryptoError("invalid authorization")
    header_part, claim_part, signature = token.split(".")
    try:
        header = json.loads(b64url_decode(header_part))
        claims = json.loads(b64url_decode(claim_part))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PairingV3CryptoError("invalid authorization") from error
    if header.get("alg") != "EdDSA" or header.get("typ") != AUTHORIZATION_TYPE or not isinstance(claims, dict):
        raise PairingV3CryptoError("invalid authorization")
    verify_ed25519(public_key, f"{header_part}.{claim_part}".encode("ascii"), signature)
    return VerifiedAuthorization(header=header, claims=claims, token_hash=sha256_b64url(token.encode("ascii")))


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(str(left), str(right))
