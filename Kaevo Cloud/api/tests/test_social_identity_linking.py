from __future__ import annotations

import json
import pathlib
import sys

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "social_identity_guard"))

import social_identity
import social_identity_guard


def credentials(provider="google"):
    if provider == "google":
        return {"client_id": "google-client", "client_secret": "not-logged"}
    return {
        "client_id": "apple-client", "team_id": "TEAM", "key_id": "KID",
        "private_key": "not-used-by-token-validation",
    }


def token(provider="google", *, subject="provider-subject", nonce="nonce", email="owner@example.invalid", verified=True, now=1_000):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    issuer = social_identity.APPLE_ISSUER if provider == "apple" else "https://accounts.google.com"
    claims = {
        "sub": subject, "iss": issuer, "aud": credentials(provider)["client_id"],
        "iat": now, "exp": now + 300, "nonce": nonce,
    }
    if email is not None:
        claims.update({"email": email, "email_verified": verified})
    signed = jwt.encode(claims, private, algorithm="RS256", headers={"kid": "provider-kid"})
    return signed, public


def owner_session():
    return {
        "principal_id": "owner-subject", "account_id": "account-1",
        "household_id": "household-1", "installation_id": "install-1",
    }


def test_new_attempt_is_bound_and_stores_only_hash_of_oauth_state(monkeypatch):
    values = iter(("oauth-state", "oauth-nonce", "attempt"))
    monkeypatch.setattr(social_identity.secrets, "token_urlsafe", lambda _size: next(values))
    item, state = social_identity.new_attempt(
        provider="google", session=owner_session(), callback_url="https://api.example/social/callback", now=1_000,
    )
    assert state == "oauth-state"
    assert state not in json.dumps(item)
    assert item["token_hash"] == social_identity.state_key(state)
    assert item["expires_at"] == 1_000 + social_identity.LINK_TTL_SECONDS
    assert item["principal_id"] == "owner-subject" and item["installation_id"] == "install-1"


def test_authorization_urls_have_state_nonce_and_exact_callback_without_secret():
    for provider in ("google", "apple"):
        url = social_identity.authorization_url(
            provider, credentials(provider), callback_url="https://api.example/social/callback", state="state", nonce="nonce",
        )
        assert "state=state" in url and "nonce=nonce" in url
        assert "redirect_uri=https%3A%2F%2Fapi.example%2Fsocial%2Fcallback" in url
        assert "client_secret" not in url and "private_key" not in url


@pytest.mark.parametrize("provider", ["google", "apple"])
def test_provider_token_uses_stable_subject_not_email(provider):
    signed, public = token(provider)
    identity = social_identity.validate_identity_token(
        provider, signed, credentials(provider), expected_nonce="nonce",
        key_resolver=lambda _provider, _kid: public, now=1_001,
    )
    assert identity.subject == "provider-subject"
    assert identity.email_present and identity.email_verified


@pytest.mark.parametrize("change,reason", [
    ({"nonce": "wrong"}, "identity_provider_nonce_mismatch"),
    ({"verified": False}, "identity_provider_email_unverified"),
])
def test_provider_token_rejects_nonce_and_unverified_email(change, reason):
    signed, public = token(**change)
    with pytest.raises(social_identity.SocialIdentityError, match=reason):
        social_identity.validate_identity_token(
            "google", signed, credentials(), expected_nonce="nonce",
            key_resolver=lambda _provider, _kid: public, now=1_001,
        )


class Cognito:
    def __init__(self, *, linked=False, conflict=False):
        self.linked = linked
        self.conflict = conflict
        self.link_calls = 0

    def list_users(self, **_kwargs):
        return {"Users": [{"Username": "existing-cognito-username"}]}

    def admin_get_user(self, **_kwargs):
        identities = []
        if self.linked:
            identities.append({"providerName": "Google", "userId": "provider-subject"})
        return {"UserAttributes": [{"Name": "identities", "Value": json.dumps(identities)}]}

    def admin_link_provider_for_user(self, **kwargs):
        self.link_calls += 1
        assert kwargs["DestinationUser"]["ProviderAttributeValue"] == "existing-cognito-username"
        assert kwargs["SourceUser"]["ProviderAttributeName"] == "Cognito_Subject"
        assert kwargs["SourceUser"]["ProviderAttributeValue"] == "provider-subject"
        if self.conflict:
            raise RuntimeError("conflict detail that must not escape")
        self.linked = True


def test_link_targets_existing_subject_and_cognito_subject_only():
    client = Cognito()
    result = social_identity.link_provider_identity(
        client, user_pool_id="pool", destination_subject="owner-subject",
        identity=social_identity.ProviderIdentity("google", "provider-subject", True, True),
    )
    assert result == "linked" and client.link_calls == 1


def test_link_is_idempotent_and_conflict_fails_closed():
    linked = Cognito(linked=True)
    assert social_identity.link_provider_identity(
        linked, user_pool_id="pool", destination_subject="owner-subject",
        identity=social_identity.ProviderIdentity("google", "provider-subject", True, True),
    ) == "already_linked"
    assert linked.link_calls == 0
    conflict = Cognito(conflict=True)
    with pytest.raises(social_identity.SocialIdentityError, match="identity_provider_link_conflict"):
        social_identity.link_provider_identity(
            conflict, user_pool_id="pool", destination_subject="owner-subject",
            identity=social_identity.ProviderIdentity("google", "provider-subject", True, True),
        )


def external_event(email="owner@example.invalid", verified="true", provider="Google"):
    return {
        "triggerSource": "PreSignUp_ExternalProvider", "userPoolId": "pool-1",
        "userName": f"{provider}_provider-subject",
        "request": {"userAttributes": {"email": email, "email_verified": verified}},
        "response": {},
    }


class GuardCognito:
    def __init__(self, users): self.users = users
    def list_users(self, **_kwargs): return {"Users": self.users}


def test_external_signup_collision_is_blocked_but_never_linked_by_email(monkeypatch):
    monkeypatch.setenv("EXPECTED_USER_POOL_ID", "pool-1")
    with pytest.raises(ValueError, match="existing_account_link_required"):
        social_identity_guard.guard_external_provider_signup(external_event(), cognito=GuardCognito([{"Username": "owner"}]))
    assert social_identity_guard.guard_external_provider_signup(external_event(), cognito=GuardCognito([]))["userName"].startswith("Google_")


def test_external_signup_excludes_only_the_exact_provisional_provider_subject(monkeypatch):
    monkeypatch.setenv("EXPECTED_USER_POOL_ID", "pool-1")
    event = external_event(provider="SignInWithApple")

    accepted = social_identity_guard.guard_external_provider_signup(
        event,
        cognito=GuardCognito([{"Username": event["userName"]}]),
    )

    assert accepted is event


def test_external_signup_still_denies_another_user_beside_the_provisional_subject(monkeypatch):
    monkeypatch.setenv("EXPECTED_USER_POOL_ID", "pool-1")
    event = external_event(provider="SignInWithApple")

    with pytest.raises(ValueError, match="existing_account_link_required"):
        social_identity_guard.guard_external_provider_signup(
            event,
            cognito=GuardCognito([
                {"Username": event["userName"]},
                {"Username": "another-immutable-cognito-user"},
            ]),
        )


def test_google_external_signup_accepts_a_trusted_provider_email_without_mapped_verified_flag(monkeypatch):
    monkeypatch.setenv("EXPECTED_USER_POOL_ID", "pool-1")
    event = external_event(verified="")
    assert social_identity_guard.guard_external_provider_signup(
        event, cognito=GuardCognito([])
    )["userName"].startswith("Google_")


def test_apple_external_signup_accepts_provider_authenticated_email_without_unmapped_verified_flag(monkeypatch):
    monkeypatch.setenv("EXPECTED_USER_POOL_ID", "pool-1")
    event = external_event(verified="", provider="SignInWithApple")
    assert social_identity_guard.guard_external_provider_signup(
        event, cognito=GuardCognito([])
    )["userName"].startswith("SignInWithApple_")


def test_apple_external_signup_still_requires_email_and_blocks_collisions(monkeypatch):
    monkeypatch.setenv("EXPECTED_USER_POOL_ID", "pool-1")
    with pytest.raises(ValueError, match="verified_email_required"):
        social_identity_guard.guard_external_provider_signup(
            external_event(email="", verified="", provider="SignInWithApple"),
            cognito=GuardCognito([]),
        )
    with pytest.raises(ValueError, match="existing_account_link_required"):
        social_identity_guard.guard_external_provider_signup(
            external_event(verified="", provider="SignInWithApple"),
            cognito=GuardCognito([{"Username": "existing-owner"}]),
        )


def test_external_signup_rejects_unconfigured_provider_even_with_verified_email(monkeypatch):
    monkeypatch.setenv("EXPECTED_USER_POOL_ID", "pool-1")
    with pytest.raises(ValueError, match="unsupported_external_identity"):
        social_identity_guard.guard_external_provider_signup(
            external_event(provider="UntrustedProvider"),
            cognito=GuardCognito([]),
        )


def test_external_signup_rejects_an_unexpected_user_pool(monkeypatch):
    monkeypatch.setenv("EXPECTED_USER_POOL_ID", "pool-2")
    with pytest.raises(ValueError, match="unexpected_user_pool"):
        social_identity_guard.guard_external_provider_signup(external_event(), cognito=GuardCognito([]))
