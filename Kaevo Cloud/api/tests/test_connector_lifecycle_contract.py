from __future__ import annotations

from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

import connector_lifecycle as lifecycle
import handler


class Table:
    def __init__(self, name, items=None):
        self.name = name
        self.items = items or {}

    def get_item(self, Key, **_kwargs):
        key = next(iter(Key.values()))
        return {"Item": self.items.get(key)} if key in self.items else {}


class Client:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def transact_write_items(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")


@pytest.fixture
def identity():
    return SimpleNamespace(
        subject="owner-subject", account_id="acct_1", household_id="hh_1", profile_id="profile_1"
    )


def create(client, identity):
    return lifecycle.create_pairing_intent(
        client=client, connectors=Table("connectors"), intents=Table("intents"), audits=Table("audits"),
        identity=identity, environment="security-stage", server_id="srv_" + "S" * 32,
        local_nonce="N" * 32, public_jwk_json='{"kty":"EC"}', key_thumbprint="thumb-new",
        recovery_public_jwk_json='{"kty":"EC"}', recovery_thumbprint="thumb-recovery",
        connector_name="Synthetic Home", pairing_code="AAAA-BBBB-CCCC", request_id="request-1", now=100,
    )


def test_initial_pairing_transaction_contains_binding_connector_intent_and_audit(identity):
    client = Client()
    created = create(client, identity)
    writes = client.calls[0]["TransactItems"]
    assert len(writes) == 4
    assert created["connector"]["state"] == "pending_pairing"
    assert created["connector"]["credential_version"] == 0
    assert created["intent"]["target_version"] == 1
    assert writes[0]["Put"]["Item"]["record_type"] == "server_binding"
    assert writes[3]["Put"]["Item"]["actor_ref"].startswith("apr1_")


def test_pairing_audit_transaction_failure_cannot_activate(identity):
    client = Client(fail=True)
    with pytest.raises(lifecycle.LifecycleError, match="lifecycle_conflict"):
        create(client, identity)


def test_same_server_binding_is_conditionally_unique(identity):
    client = Client()
    create(client, identity)
    binding_put = client.calls[0]["TransactItems"][0]["Put"]
    assert binding_put["ConditionExpression"] == "attribute_not_exists(connector_id)"


def test_rotation_intent_is_monotonic_and_owner_bound(identity):
    connector = {
        "connector_id": "connector-1", "server_id": "srv_" + "S" * 32,
        "environment": "security-stage", "account_id": "acct_1", "household_id": "hh_1",
        "profile_id": "profile_1", "state": "active", "auth_state": "active", "revoked": False,
        "credential_version": 4, "max_issued_credential_version": 4, "key_thumbprint": "old-thumb",
    }
    client = Client()
    intent = lifecycle.create_update_intent(
        operation="rotate", client=client, connectors=Table("connectors"), intents=Table("intents"),
        audits=Table("audits"), identity=identity, environment="security-stage", connector=connector,
        local_nonce="R" * 32, proposed_public_jwk_json="{}", proposed_thumbprint="new-thumb",
        request_id="request-2", now=200,
    )
    assert intent["current_version"] == 4 and intent["target_version"] == 5
    updated = client.calls[0]["TransactItems"][0]["Put"]["Item"]
    assert updated["state"] == "rotation_pending"
    assert intent["owner_principal_ref"].startswith("apr1_")


def test_version_gap_or_decrease_is_rejected(identity):
    connector = {
        "connector_id": "connector-1", "server_id": "srv_" + "S" * 32,
        "environment": "security-stage", "account_id": "acct_1", "household_id": "hh_1",
        "profile_id": "profile_1", "state": "active", "credential_version": 3,
        "max_issued_credential_version": 4, "key_thumbprint": "old-thumb", "revoked": False,
    }
    with pytest.raises(lifecycle.LifecycleError, match="connector_version_invalid"):
        lifecycle.create_update_intent(
            operation="rotate", client=Client(), connectors=Table("c"), intents=Table("i"), audits=Table("a"),
            identity=identity, environment="security-stage", connector=connector, local_nonce="R" * 32,
            proposed_public_jwk_json="{}", proposed_thumbprint="new", request_id="r", now=1,
        )


def test_activation_consumes_intent_in_same_transaction():
    server_id = "srv_" + "S" * 32
    connector = {
        "connector_id": "connector-1", "server_id": server_id, "environment": "security-stage",
        "account_id": "acct_1", "household_id": "hh_1", "profile_id": "profile_1",
        "state": "rotation_pending", "auth_state": "rotation_pending", "credential_version": 1,
        "max_issued_credential_version": 1, "key_thumbprint": "old", "revoked": False,
        "pending_intent_id": "intent-1", "pending_intent_expires_at": 1000,
    }
    intent = {
        "token_hash": lifecycle.intent_key("intent-1"), "intent_id": "intent-1",
        "record_type": "connector_lifecycle_intent", "operation": "rotate", "state": "pending",
        "environment": "security-stage", "account_id": "acct_1", "household_id": "hh_1",
        "owner_principal_ref": "apr1_owner", "server_id": server_id, "connector_id": "connector-1",
        "current_version": 1, "target_version": 2, "current_thumbprint": "old",
        "proposed_thumbprint": "new", "local_nonce_hash": lifecycle._hash("L" * 32), "expires_at": 1000,
    }
    binding = {"connector_id": lifecycle.binding_key(server_id), "server_id": server_id,
               "active_connector_id": "connector-1", "state": "active"}
    client = Client()
    updated = lifecycle.activate_intent(
        client=client, connectors=Table("connectors", {binding["connector_id"]: binding}),
        intents=Table("intents"), audits=Table("audits"), environment="security-stage",
        intent=intent, connector=connector, local_nonce="L" * 32, public_jwk_json="{}",
        proposed_thumbprint="new", request_id="request-3", now=300,
    )
    assert updated["credential_version"] == 2 and updated["max_issued_credential_version"] == 2
    writes = client.calls[0]["TransactItems"]
    assert len(writes) == 4
    assert writes[2]["Put"]["Item"]["state"] == "consumed"
    assert writes[3]["Put"]["Item"]["actor_ref"].startswith("apr1_")


def test_replayed_or_expired_intent_is_rejected():
    for state, expires in (("consumed", 1000), ("pending", 1)):
        with pytest.raises(lifecycle.LifecycleError, match="lifecycle_intent_invalid"):
            lifecycle.activate_intent(
                client=Client(), connectors=Table("c"), intents=Table("i"), audits=Table("a"),
                environment="security-stage", intent={"operation": "rotate", "state": state, "expires_at": expires},
                connector={}, local_nonce="L" * 32, public_jwk_json="{}", proposed_thumbprint="new",
                request_id="r", now=2,
            )


def test_revoked_connector_cannot_rotate(identity):
    connector = {"state": "revoked", "revoked": True}
    with pytest.raises(lifecycle.LifecycleError, match="connector_unavailable"):
        lifecycle.create_update_intent(
            operation="rotate", client=Client(), connectors=Table("c"), intents=Table("i"), audits=Table("a"),
            identity=identity, environment="security-stage", connector=connector, local_nonce="R" * 32,
            proposed_public_jwk_json="{}", proposed_thumbprint="new", request_id="r", now=1,
        )


def test_cancel_rotation_restores_current_version_and_key(identity):
    server_id = "srv_" + "S" * 32
    connector = {
        "connector_id": "connector-1", "server_id": server_id, "environment": "security-stage",
        "account_id": "acct_1", "household_id": "hh_1", "profile_id": "profile_1",
        "state": "rotation_pending", "auth_state": "rotation_pending", "credential_version": 7,
        "max_issued_credential_version": 7, "key_thumbprint": "still-current", "revoked": False,
        "pending_intent_id": "intent-7", "pending_intent_expires_at": 100,
        "proposed_key_thumbprint": "never-activated", "proposed_public_jwk_json": "{}",
    }
    intent = {
        "token_hash": lifecycle.intent_key("intent-7"), "intent_id": "intent-7",
        "operation": "rotate", "state": "pending", "account_id": "acct_1",
        "household_id": "hh_1", "connector_id": "connector-1", "server_id": server_id,
    }
    client = Client()
    lifecycle.cancel_intent(
        client=client, connectors=Table("c"), intents=Table("i"), audits=Table("a"),
        identity=identity, intent=intent, connector=connector, request_id="r", now=101,
    )
    restored = client.calls[0]["TransactItems"][0]["Put"]["Item"]
    assert restored["state"] == "active"
    assert restored["credential_version"] == 7
    assert restored["key_thumbprint"] == "still-current"
    assert "proposed_key_thumbprint" not in restored


def test_cancel_initial_pairing_releases_only_reserved_binding(identity):
    server_id = "srv_" + "S" * 32
    connector = {"connector_id": "connector-1", "server_id": server_id,
                 "account_id": "acct_1", "household_id": "hh_1", "state": "pending_pairing"}
    intent = {"token_hash": lifecycle.intent_key("intent-1"), "intent_id": "intent-1",
              "operation": "pair", "state": "pending", "account_id": "acct_1",
              "household_id": "hh_1", "connector_id": "connector-1", "server_id": server_id}
    client = Client()
    lifecycle.cancel_intent(
        client=client, connectors=Table("c"), intents=Table("i"), audits=Table("a"),
        identity=identity, intent=intent, connector=connector, request_id="r", now=10,
    )
    writes = client.calls[0]["TransactItems"]
    assert writes[0]["Delete"]["Key"] == {"connector_id": "connector-1"}
    assert writes[1]["Delete"]["Key"] == {"connector_id": lifecycle.binding_key(server_id)}


def test_connector_auth_requires_current_version_and_server_binding(monkeypatch):
    server_id = "srv_" + "S" * 32
    connector = {"connector_id": "connector-1", "server_id": server_id, "environment": handler.KAEVO_ENV,
                 "account_id": "acct_1", "household_id": "hh_1", "state": "active",
                 "credential_version": 3, "key_thumbprint": "thumb", "revoked": False}
    binding = {"connector_id": lifecycle.binding_key(server_id), "environment": handler.KAEVO_ENV,
               "account_id": "acct_1", "household_id": "hh_1", "active_connector_id": "connector-1"}
    monkeypatch.setattr(handler, "home_connectors_table", Table("c", {
        "connector-1": connector, lifecycle.binding_key(server_id): binding,
    }))
    monkeypatch.setattr(handler, "verify_dpop", lambda *_args, **_kwargs: True)
    event = {"rawPath": "/v1/home-connectors/connector-1/heartbeat",
             "requestContext": {"http": {"method": "POST"}},
             "headers": {"dpop": "proof", "x-kaevo-credential-version": "3"}}
    assert handler.require_connector_auth(event, "connector-1")
    event["headers"]["x-kaevo-credential-version"] = "2"
    assert not handler.require_connector_auth(event, "connector-1")
