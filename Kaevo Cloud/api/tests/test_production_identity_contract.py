import json
import pathlib
import sys
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from security_identity import (
    IdentityContext, IdentityError, Role, authorize, base64url_encode,
    jwk_thumbprint, new_session_material, rotate_refresh_record, token_hash,
    verify_dpop,
)


def identity(role=Role.OWNER, auth_time=1_000):
    return IdentityContext("user-1", "account-1", "household-1", "profile-1", role, 7, auth_time)


def principal(role=Role.OWNER):
    return {"state": "active", "principal_id": "user-1", "account_id": "account-1", "household_id": "household-1", "role": role.value, "authz_version": 7, "profile_ids": ["profile-1"]}


def gateway_event(*, now=1_000, token_use="access", issuer="https://issuer.example/pool", client_id="main-client", schema="1"):
    return {"requestContext": {"authorizer": {"jwt": {"claims": {
        "sub": "user-1", "iss": issuer, "client_id": client_id, "token_use": token_use,
        "iat": str(now), "exp": str(now + 900), "auth_time": str(now),
        "account_id": "account-1", "household_id": "household-1", "profile_id": "profile-1",
        "role": "owner", "authz_version": "7", "identity_schema_version": schema,
    }}}}}


def key_and_jwk():
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    size = 32
    jwk = {"kty": "EC", "crv": "P-256", "x": base64url_encode(numbers.x.to_bytes(size, "big")), "y": base64url_encode(numbers.y.to_bytes(size, "big"))}
    return key, jwk


def proof(key, jwk, *, method="POST", url="https://api.example/v1/sessions/refresh", access_token=None, now=1_000, jti=None):
    claims = {"htm": method, "htu": url, "iat": now, "jti": jti or str(uuid.uuid4())}
    if access_token:
        import hashlib
        claims["ath"] = base64url_encode(hashlib.sha256(access_token.encode("ascii")).digest())
    return jwt.encode(claims, key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": jwk})


def test_child_cannot_perform_owner_operation():
    with pytest.raises(IdentityError, match="capability_denied"):
        authorize(identity(Role.CHILD), principal(Role.CHILD), "configure_providers", now=1_050)


def test_adult_cannot_escalate_by_changing_role_claim():
    with pytest.raises(IdentityError, match="identity_relationship_mismatch"):
        authorize(identity(Role.OWNER), principal(Role.ADULT), "manage_household", now=1_050)


def test_cross_household_target_does_not_leak_existence():
    with pytest.raises(IdentityError) as error:
        authorize(identity(), principal(), "browse", target={"account_id": "account-2", "household_id": "household-2"}, now=1_050)
    assert error.value.status_code == 404
    assert error.value.reason == "target_not_found"


def test_recent_auth_is_required_for_sensitive_owner_action():
    with pytest.raises(IdentityError, match="recent_auth_required"):
        authorize(identity(auth_time=1_000), principal(), "pair_connector", now=1_301)


def test_installation_registration_requires_recent_owner_authentication():
    with pytest.raises(IdentityError, match="recent_auth_required"):
        authorize(identity(auth_time=1_000), principal(), "register_device", now=1_301)


def test_role_version_change_immediately_invalidates_stale_claim():
    changed = {**principal(), "authz_version": 8}
    with pytest.raises(IdentityError, match="stale_authorization"):
        authorize(identity(), changed, "browse", now=1_050)


def test_role_change_and_membership_removal_invalidate_issued_token():
    changed_role = {**principal(Role.ADULT), "role": "adult"}
    with pytest.raises(IdentityError, match="identity_relationship_mismatch"):
        authorize(identity(Role.OWNER), changed_role, "browse", now=1_050)
    removed_profile = {**principal(), "profile_ids": []}
    with pytest.raises(IdentityError, match="target_not_found"):
        authorize(identity(), removed_profile, "browse", now=1_050)


def test_gateway_context_requires_verified_access_token_standard_claims():
    context = IdentityContext.from_gateway_event(
        gateway_event(), expected_issuer="https://issuer.example/pool", expected_client_id="main-client", now=1_000,
    )
    assert context.token_use == "access"
    assert context.identity_schema_version == 1


def test_configured_native_client_is_accepted_without_weakening_explicit_client_checks(monkeypatch):
    monkeypatch.setenv("EXPECTED_COGNITO_ISSUER", "https://issuer.example/pool")
    monkeypatch.setenv("EXPECTED_MAIN_CLIENT_ID", "main-client")
    monkeypatch.setenv("EXPECTED_NATIVE_CLIENT_ID", "native-client")
    native = IdentityContext.from_gateway_event(gateway_event(client_id="native-client"), now=1_000)
    assert native.client_id == "native-client"
    with pytest.raises(IdentityError, match="invalid_identity_claims"):
        IdentityContext.from_gateway_event(
            gateway_event(client_id="native-client"),
            expected_issuer="https://issuer.example/pool",
            expected_client_id="enrollment-client",
            now=1_000,
        )


@pytest.mark.parametrize("client_id", ["unknown-client", "production-client", "development-client"])
def test_unconfigured_clients_remain_rejected(monkeypatch, client_id):
    monkeypatch.setenv("EXPECTED_COGNITO_ISSUER", "https://issuer.example/pool")
    monkeypatch.setenv("EXPECTED_MAIN_CLIENT_ID", "main-client")
    monkeypatch.setenv("EXPECTED_NATIVE_CLIENT_ID", "native-client")
    with pytest.raises(IdentityError, match="invalid_identity_claims"):
        IdentityContext.from_gateway_event(gateway_event(client_id=client_id), now=1_000)


@pytest.mark.parametrize("change", [
    {"token_use": "id"}, {"issuer": "https://attacker.example/pool"},
    {"client_id": "enrollment-client"}, {"schema": "2"},
])
def test_id_token_wrong_issuer_client_and_schema_are_rejected(change):
    with pytest.raises(IdentityError, match="invalid_identity_claims"):
        IdentityContext.from_gateway_event(
            gateway_event(**change), expected_issuer="https://issuer.example/pool", expected_client_id="main-client", now=1_000,
        )


def test_expired_and_future_access_tokens_are_rejected():
    expired = gateway_event(now=1_000)
    with pytest.raises(IdentityError, match="invalid_identity_claims"):
        IdentityContext.from_gateway_event(
            expired, expected_issuer="https://issuer.example/pool", expected_client_id="main-client", now=2_000,
        )


def test_stolen_access_token_fails_with_another_installation_key():
    key, jwk = key_and_jwk()
    wrong_key, wrong_jwk = key_and_jwk()
    token = "access-token"
    expected = jwk_thumbprint(jwk)
    stolen_proof = proof(wrong_key, wrong_jwk, access_token=token)
    with pytest.raises(IdentityError, match="installation_key_mismatch"):
        verify_dpop(stolen_proof, method="POST", url="https://api.example/v1/sessions/refresh", expected_thumbprint=expected, access_token=token, now=1_000)


def test_dpop_replay_is_rejected():
    key, jwk = key_and_jwk()
    seen = set()
    def guard(jti, _expires):
        if jti in seen:
            return False
        seen.add(jti)
        return True
    signed = proof(key, jwk, jti="same-proof")
    verify_dpop(signed, method="POST", url="https://api.example/v1/sessions/refresh", expected_thumbprint=jwk_thumbprint(jwk), replay_guard=guard, now=1_000)
    with pytest.raises(IdentityError, match="dpop_replay"):
        verify_dpop(signed, method="POST", url="https://api.example/v1/sessions/refresh", expected_thumbprint=jwk_thumbprint(jwk), replay_guard=guard, now=1_000)


def test_refresh_rotation_reuse_signal_preserves_family_for_revocation():
    _, jwk = key_and_jwk()
    installation = {"installation_id": "install-1", "device_id": "device-1", "key_thumbprint": jwk_thumbprint(jwk)}
    _, refresh, _, refresh_token = new_session_material(identity(), installation, now=1_000)
    _, next_refresh, _, _, consumed = rotate_refresh_record(refresh, now=1_010)
    assert consumed["state"] == "consumed"
    assert next_refresh["family_id"] == refresh["family_id"]
    assert refresh["token_hash"] == f"refresh#{token_hash(refresh_token)}"
    with pytest.raises(IdentityError, match="refresh_reuse_or_expired"):
        rotate_refresh_record(consumed, now=1_011)
