from __future__ import annotations

import pathlib
import os
import sys
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec


os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

import handler
from security_identity import base64url_encode, jwk_thumbprint, verify_dpop


@pytest.fixture(autouse=True)
def reset_public_api_base_url(monkeypatch):
    monkeypatch.setattr(handler, "PUBLIC_API_BASE_URL", "")


def key_and_jwk():
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    size = 32
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(numbers.x.to_bytes(size, "big")),
        "y": base64url_encode(numbers.y.to_bytes(size, "big")),
    }
    return key, jwk


def dpop_proof(key, jwk, *, url):
    return jwt.encode(
        {
            "htm": "POST",
            "htu": url,
            "iat": 1_000,
            "jti": str(uuid.uuid4()),
        },
        key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


def test_custom_domain_from_gateway_context_is_the_dpop_url():
    event = {
        "rawPath": "/v2/installations",
        "headers": {
            "host": "aneohx5ff6.execute-api.us-west-2.amazonaws.com",
            "x-forwarded-host": "attacker.example",
            "x-forwarded-proto": "http",
        },
        "requestContext": {
            "domainName": "api.kaevo.watch",
            "http": {"method": "POST"},
        },
    }

    assert handler.request_absolute_url(event) == "https://api.kaevo.watch/v2/installations"


def test_custom_domain_dpop_proof_verifies_against_reconstructed_url():
    event = {
        "rawPath": "/v2/installations",
        "headers": {"host": "aneohx5ff6.execute-api.us-west-2.amazonaws.com"},
        "requestContext": {
            "domainName": "api.kaevo.watch",
            "http": {"method": "POST"},
        },
    }
    key, jwk = key_and_jwk()
    signed_url = "https://api.kaevo.watch/v2/installations"

    claims = verify_dpop(
        dpop_proof(key, jwk, url=signed_url),
        method=handler.method_for(event),
        url=handler.request_absolute_url(event),
        expected_thumbprint=jwk_thumbprint(jwk),
        now=1_000,
    )

    assert claims["htu"] == signed_url


def test_execute_api_domain_remains_supported():
    event = {
        "rawPath": "/dev/v2/installations",
        "headers": {"host": "unexpected.example"},
        "requestContext": {
            "domainName": "aneohx5ff6.execute-api.us-west-2.amazonaws.com",
            "stage": "dev",
        },
    }

    assert handler.request_absolute_url(event) == (
        "https://aneohx5ff6.execute-api.us-west-2.amazonaws.com/dev/v2/installations"
    )


def test_gateway_domain_cannot_be_overridden_by_forwarded_host_injection():
    event = {
        "rawPath": "/v2/installations",
        "headers": {
            "x-forwarded-host": "api.kaevo.watch\nforged-log-entry.example",
            "host": "attacker.example",
        },
        "requestContext": {"domainName": "api.kaevo.watch"},
    }

    reconstructed = handler.request_absolute_url(event)

    assert reconstructed == "https://api.kaevo.watch/v2/installations"
    assert "\n" not in reconstructed


def test_local_event_without_gateway_context_keeps_header_fallback():
    event = {
        "path": "/v2/installations",
        "headers": {
            "x-forwarded-proto": "http",
            "x-forwarded-host": "127.0.0.1:3000",
        },
    }

    assert handler.request_absolute_url(event) == "http://127.0.0.1:3000/v2/installations"


def test_configured_public_origin_wins_over_gateway_execution_domain(monkeypatch):
    monkeypatch.setattr(handler, "PUBLIC_API_BASE_URL", "https://api.kaevo.watch")
    event = {
        "rawPath": "/v2/installations",
        "headers": {
            "host": "aneohx5ff6.execute-api.us-west-2.amazonaws.com",
            "x-forwarded-host": "aneohx5ff6.execute-api.us-west-2.amazonaws.com",
        },
        "requestContext": {
            "domainName": "aneohx5ff6.execute-api.us-west-2.amazonaws.com",
            "stage": "dev",
            "http": {"method": "POST"},
        },
    }

    assert handler.request_absolute_url(event) == "https://api.kaevo.watch/v2/installations"


def test_configured_public_origin_removes_gateway_stage_prefix(monkeypatch):
    monkeypatch.setattr(handler, "PUBLIC_API_BASE_URL", "https://api.kaevo.watch")
    event = {
        "rawPath": "/dev/v2/installations",
        "requestContext": {
            "domainName": "aneohx5ff6.execute-api.us-west-2.amazonaws.com",
            "stage": "dev",
        },
    }

    assert handler.request_absolute_url(event) == "https://api.kaevo.watch/v2/installations"


def test_configured_public_origin_verifies_the_ios_dpop_target(monkeypatch):
    monkeypatch.setattr(handler, "PUBLIC_API_BASE_URL", "https://api.kaevo.watch")
    event = {
        "rawPath": "/dev/v2/installations",
        "requestContext": {
            "domainName": "aneohx5ff6.execute-api.us-west-2.amazonaws.com",
            "stage": "dev",
            "http": {"method": "POST"},
        },
    }
    key, jwk = key_and_jwk()
    signed_url = "https://api.kaevo.watch/v2/installations"

    claims = verify_dpop(
        dpop_proof(key, jwk, url=signed_url),
        method=handler.method_for(event),
        url=handler.request_absolute_url(event),
        expected_thumbprint=jwk_thumbprint(jwk),
        now=1_000,
    )

    assert claims["htu"] == signed_url


def test_malformed_configured_public_origin_fails_closed(monkeypatch):
    monkeypatch.setattr(
        handler,
        "PUBLIC_API_BASE_URL",
        "https://api.kaevo.watch?redirect=attacker.example",
    )

    try:
        handler.request_absolute_url({"rawPath": "/v2/installations"})
    except handler.IdentityError as error:
        assert error.reason == "invalid_public_api_origin"
        assert error.status_code == 503
    else:
        raise AssertionError("malformed public API origin must fail closed")
