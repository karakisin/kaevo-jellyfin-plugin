"""Deterministic negative coverage for the Household Join DPoP boundary.

These checks exercise the verifier directly so they remain executable without
AWS credentials, a fixture, or DynamoDB Local.  The route layer separately
maps the resulting reasons to privacy-safe API responses.
"""

import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from security_identity import (
    DPOP_MAX_AGE_SECONDS,
    IdentityError,
    base64url_encode,
    jwk_thumbprint,
    verify_dpop,
)


METHOD = "POST"
URL = "https://api.example/v3/identity/household-joins/complete"


def key_and_jwk():
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(numbers.x.to_bytes(32, "big")),
        "y": base64url_encode(numbers.y.to_bytes(32, "big")),
    }
    return key, jwk


def signed_proof(key, jwk, *, method=METHOD, url=URL, iat=1_000, ath=None):
    claims = {"htm": method, "htu": url, "iat": iat, "jti": str(uuid.uuid4())}
    if ath is not None:
        claims["ath"] = ath
    return jwt.encode(claims, key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": jwk})


@pytest.mark.parametrize(
    ("proof_factory", "reason"),
    [
        (lambda key, jwk: "not-a-jwt", "invalid_dpop"),
        (lambda key, jwk: signed_proof(key, jwk, method="GET"), "dpop_method_mismatch"),
        (lambda key, jwk: signed_proof(key, jwk, url=URL + "/other"), "dpop_url_mismatch"),
        (lambda key, jwk: signed_proof(key, jwk, iat=1_000 - DPOP_MAX_AGE_SECONDS - 1), "stale_dpop"),
        (lambda key, jwk: signed_proof(key, jwk, iat=1_000 + DPOP_MAX_AGE_SECONDS + 1), "stale_dpop"),
    ],
)
def test_household_join_dpop_negative_proofs_fail_closed(proof_factory, reason):
    key, jwk = key_and_jwk()
    with pytest.raises(IdentityError, match=reason):
        verify_dpop(
            proof_factory(key, jwk),
            method=METHOD,
            url=URL,
            expected_thumbprint=jwk_thumbprint(jwk),
            now=1_000,
        )


def test_household_join_dpop_rejects_access_token_key_binding_mismatch():
    key, jwk = key_and_jwk()
    with pytest.raises(IdentityError, match="dpop_access_token_mismatch"):
        verify_dpop(
            signed_proof(key, jwk, ath="not-the-token-hash"),
            method=METHOD,
            url=URL,
            expected_thumbprint=jwk_thumbprint(jwk),
            access_token="fixture-access-token",
            now=1_000,
        )
