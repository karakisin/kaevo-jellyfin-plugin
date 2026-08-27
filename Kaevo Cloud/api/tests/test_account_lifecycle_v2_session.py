from __future__ import annotations

import hashlib
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from account_lifecycle_v2_session import (
    ProtectedLifecycleV2SessionAuthenticator,
    lifecycle_request_path,
)
from security_identity import base64url_encode, jwk_thumbprint, token_hash


NOW = int(time.time())
TOKEN = "opaque-access-token"
INSTALLATION_ID = "installation-1"
PUBLIC_BASE_URL = "https://example.execute-api.us-west-2.amazonaws.com/production"
ROUTE = "/v4/account-lifecycle/deletion-preflights"


class Table:
    def __init__(self, items):
        self.items = items
        self.replays = set()

    def get_item(self, *, Key, **_kwargs):
        key = next(iter(Key.values()))
        return {"Item": self.items.get(key)} if key in self.items else {}

    def put_item(self, *, Item, ConditionExpression=None):
        key = Item["token_hash"]
        if ConditionExpression and key in self.replays:
            error = RuntimeError("ConditionalCheckFailedException")
            error.response = {"Error": {"Code": "ConditionalCheckFailedException"}}
            raise error
        self.replays.add(key)


def key_and_jwk():
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    return key, {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(numbers.x.to_bytes(32, "big")),
        "y": base64url_encode(numbers.y.to_bytes(32, "big")),
    }


def proof(key, jwk, *, url):
    return jwt.encode(
        {
            "htm": "POST",
            "htu": url,
            "iat": NOW,
            "jti": str(uuid.uuid4()),
            "ath": base64url_encode(hashlib.sha256(TOKEN.encode("ascii")).digest()),
        },
        key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


def production_event(dpop):
    return {
        "rawPath": "/production" + ROUTE,
        "headers": {"authorization": f"Bearer {TOKEN}", "dpop": dpop},
        "requestContext": {
            "stage": "production",
            "http": {"method": "POST"},
        },
    }


def test_named_stage_is_removed_once_for_routing_and_dpop():
    assert lifecycle_request_path(production_event("proof")) == ROUTE


def test_production_shaped_event_authenticates_against_ios_dpop_url():
    key, jwk = key_and_jwk()
    signed_url = PUBLIC_BASE_URL + ROUTE
    sessions = Table({
        f"access#{token_hash(TOKEN)}": {
            "record_type": "access",
            "state": "active",
            "expires_at": NOW + 900,
            "account_id": "acct_1",
            "principal_id": "principal_1",
            "installation_id": INSTALLATION_ID,
            "family_id": "family_1",
            "key_thumbprint": jwk_thumbprint(jwk),
        },
    })
    installations = Table({
        INSTALLATION_ID: {"state": "active", "revoked": False},
    })
    authenticator = ProtectedLifecycleV2SessionAuthenticator(
        app_sessions_table=sessions,
        installations_table=installations,
        public_base_url=PUBLIC_BASE_URL,
        clock=lambda: NOW,
    )

    session = authenticator.authenticate(
        production_event(proof(key, jwk, url=signed_url)),
    )

    assert session["account_id"] == "acct_1"
