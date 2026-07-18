from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class ConnectorIdentity:
    """Installation identity whose P-256 private key never leaves the server."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self._private_key = private_key

    @classmethod
    def load_or_create(cls, path: str | Path) -> "ConnectorIdentity":
        key_path = Path(path)
        key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if key_path.exists():
            private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
                raise ValueError("connectorIdentityKeyTypeInvalid")
            os.chmod(key_path, 0o600)
            return cls(private_key)
        private_key = ec.generate_private_key(ec.SECP256R1())
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, pem)
        finally:
            os.close(descriptor)
        return cls(private_key)

    @property
    def public_jwk(self) -> dict[str, str]:
        numbers = self._private_key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        }

    @property
    def thumbprint(self) -> str:
        canonical = json.dumps(self.public_jwk, separators=(",", ":"), sort_keys=True).encode()
        return _b64url(hashlib.sha256(canonical).digest())

    def proof(self, method: str, url: str, *, now: int | None = None) -> str:
        return jwt.encode(
            {
                "htm": method.upper(),
                "htu": url,
                "iat": int(time.time()) if now is None else now,
                "jti": str(uuid.uuid4()),
            },
            self._private_key,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": self.public_jwk},
        )
