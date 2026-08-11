from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest
from botocore.exceptions import ClientError


os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

SRC = Path(__file__).resolve().parents[1] / "src"
HANDLER_PATH = SRC / "handler.py"
SPEC = importlib.util.spec_from_file_location("kaevo_account_foundation_handler", HANDLER_PATH)
handler = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(handler)

from account_foundation import (
    AccountFoundationError,
    CanonicalRole,
    Capability,
    HouseholdAccessRole,
    assert_auth_identity_binding,
    build_account_record,
    build_auth_identity_record,
    capabilities_for,
    household_access_role,
    household_capabilities_for,
    provider_subject_key,
    resolve_legacy_role,
)
from household_membership import (
    account_household_guard_id,
    build_account_household_guard,
    build_household_membership_record,
    build_household_owner_guard,
    household_membership_id,
)
from profile_binding import build_profile_binding, build_profile_creation
from profile_mapping import build_confirmed_mapping, local_profile_source_id


class Table:
    def __init__(self, key: str | tuple[str, ...], items: list[dict]):
        self.key = key
        self.items = {self.key_for(item): dict(item) for item in items}

    def key_for(self, item):
        if isinstance(self.key, tuple):
            return tuple(item[key] for key in self.key)
        return item[self.key]

    def get_item(self, *, Key, ConsistentRead=False):
        item = self.items.get(self.key_for(Key))
        return {"Item": dict(item)} if item else {}

    def query(self, **_kwargs):
        return {"Items": [dict(item) for item in self.items.values()]}

    def put_item(self, *, Item, **_kwargs):
        self.items[self.key_for(Item)] = dict(Item)

    def delete_item(self, *, Key, **_kwargs):
        self.items.pop(self.key_for(Key), None)

    def update_item(
        self,
        *,
        Key,
        UpdateExpression="",
        ExpressionAttributeNames=None,
        ExpressionAttributeValues=None,
        **_kwargs,
    ):
        key = self.key_for(Key)
        item = dict(self.items[key])
        values = ExpressionAttributeValues or {}
        names = ExpressionAttributeNames or {}
        if ":next_state" in values and ":mode" in values:
            item["state"] = values[":next_state"]
            item["deletion_mode"] = values[":mode"]
            item["deletion_requested_at"] = values[":updated_at"]
            item["deletion_execute_at_epoch"] = values[":execute_at"]
        if ":next_status" in values:
            item["status"] = values[":next_status"]
            item["deletion_execute_at_epoch"] = values[":execute_at"]
        if ":retained" in values:
            item["profile_ids"] = list(values[":retained"])
            item["state"] = values[":next_state"]
            item["revoked"] = values[":revoked"]
        if ":revoked_state" in values:
            item["state"] = values[":revoked_state"]
            item["revoked"] = values[":revoked"]
            item["revoked_at"] = values[":revoked_at"]
        if ":revoked" in values and "mapping_state" in item:
            item["mapping_state"] = values[":revoked"]
        if ":revoked" in values and item.get("entity_type") == "ProfileBinding":
            item["status"] = values[":revoked"]
        if ":pending" in values and names.get("#state") == "state":
            item["state"] = values[":pending"]
            item["deletion_execute_at_epoch"] = values[":execute_at"]
        if ":pending" in values and names.get("#status") == "status":
            item["status"] = values[":pending"]
            item["deletion_execute_at_epoch"] = values[":execute_at"]
        if ":updated_at" in values:
            item["updated_at"] = values[":updated_at"]
        if ":owner_principal_id" in values:
            item["owner_principal_id"] = values[":owner_principal_id"]
        if ":targets" in values:
            target_field = (
                "switch_profile_ids"
                if "switch_profile_ids" in UpdateExpression
                else "watching_profile_ids"
            )
            item[target_field] = list(values[":targets"])
        if ":updated" in values:
            item["updated_at"] = values[":updated"]
        if ":epoch" in values:
            item["updated_at_epoch"] = values[":epoch"]
        self.items[key] = item
        if ":updated_epoch" in values:
            item["updated_at_epoch"] = values[":updated_epoch"]
        self.items[key] = item
        return {"Attributes": dict(item)}


class TransactionClient:
    def __init__(self, tables):
        self.tables = tables
        self.calls = []
        self.concurrent_completion = None

    def transact_write_items(self, *, TransactItems):
        self.calls.append(TransactItems)
        if self.concurrent_completion is not None:
            completion, self.concurrent_completion = self.concurrent_completion, None
            completion()
            raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
        pending = []
        for operation in TransactItems:
            if "Put" in operation:
                put = operation["Put"]
                table = self.tables[put["TableName"]]
                item = put["Item"]
                if table.key_for(item) in table.items:
                    raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
                pending.append(("put", table, item, None))
                continue
            update = operation["Update"]
            table = self.tables[update["TableName"]]
            key = table.key_for(update["Key"])
            item = table.items.get(key)
            values = update.get("ExpressionAttributeValues") or {}
            if item is None:
                raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
            if ":active_status" in values and item.get("status") != values[":active_status"]:
                raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
            if ":confirmed" in values and item.get("mapping_state") != values[":confirmed"]:
                raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
            pending.append(("update", table, dict(item), values))
        for operation, table, item, values in pending:
            if operation == "put":
                table.items[table.key_for(item)] = dict(item)
                continue
            if ":next_status" in values:
                item.update({
                    "status": values[":next_status"],
                    "updated_at": values[":updated_at"],
                    "updated_at_epoch": values[":updated_epoch"],
                    "deletion_mode": values[":mode"],
                    "deletion_requested_by_account_id": values[":account_id"],
                    "deletion_requested_at": values[":updated_at"],
                    "deletion_execute_at_epoch": values[":execute_at"],
                })
            if ":revoked" in values:
                item.update({
                    "mapping_state": values[":revoked"],
                    "updated_at": values[":updated_at"],
                    "updated_at_epoch": values[":updated_epoch"],
                    "revoked_at": values[":updated_at"],
                    "revocation_reason": values[":reason"],
                })
            table.items[table.key_for(item)] = item


def graph(*, role="owner", account_id="acct_1", subject="subject-1"):
    profile_id = "profile-1"
    household_id = "household-1"
    return {
        "principal": {
            "principal_id": subject, "account_id": account_id, "household_id": household_id,
            "role": role, "authz_version": 1, "profile_ids": [profile_id],
            "state": "active", "revoked": False,
        },
        "membership": {
            "principal_id": subject, "account_id": account_id, "household_id": household_id,
            "profile_id": profile_id, "role": role, "authz_version": 1, "state": "active",
        },
        "household": {
            "household_id": household_id, "account_id": account_id,
            "owner_principal_id": subject if role == "owner" else "another-owner", "state": "active",
        },
        "profile": {
            "profile_id": profile_id, "account_id": account_id, "household_id": household_id,
            "owner_principal_id": subject if role == "owner" else "another-owner",
            "profile_type": "adult", "state": "active",
        },
    }


def protected_session(*, role="owner", account_id="acct_1", subject="subject-1"):
    return {
        "record_type": "access", "principal_id": subject, "account_id": account_id,
        "household_id": "household-1", "profile_id": "profile-1", "role": role,
        "authz_version": 1, "device_id": "device-1", "installation_id": "installation-1",
    }


def install_identity_context(monkeypatch, *, account_id="acct_1", subject="subject-1", role="owner"):
    records = graph(role=role, account_id=account_id, subject=subject)
    now_iso = "2026-07-23T00:00:00Z"
    auth_identity = build_auth_identity_record(
        account_id=account_id, provider="cognito", provider_subject=subject,
        now_iso=now_iso, now_epoch=1_000,
    )
    claims = handler.derive_authoritative_claims(
        subject, records["principal"], records["membership"], records["household"], records["profile"],
    )
    normalized_role = CanonicalRole(role)
    normalized_membership = build_household_membership_record(
        claims, normalized_role, now_iso=now_iso, now_epoch=1_000,
    )
    normalized_items = [normalized_membership, build_account_household_guard(
        claims, membership_id=normalized_membership["membership_id"], now_iso=now_iso, now_epoch=1_000,
    )]
    if normalized_role is CanonicalRole.OWNER:
        normalized_items.append(build_household_owner_guard(
            claims, membership_id=normalized_membership["membership_id"], now_iso=now_iso, now_epoch=1_000,
        ))
    monkeypatch.setattr(handler, "HOUSEHOLD_MEMBERSHIPS_TABLE", "household-memberships")
    monkeypatch.setattr(handler, "PROFILES_TABLE", "profiles")
    monkeypatch.setattr(handler, "PROFILE_BINDINGS_TABLE", "profile-bindings")
    monkeypatch.setattr(handler, "PROFILE_MAPPINGS_TABLE", "profile-mappings")
    monkeypatch.setattr(handler, "accounts_table", Table("account_id", [
        build_account_record(account_id, now_iso=now_iso, now_epoch=1_000),
    ]))
    monkeypatch.setattr(handler, "auth_identities_table", Table("auth_identity_key", [auth_identity]))
    monkeypatch.setattr(handler, "household_memberships_table", Table(
        ("household_id", "membership_id"), normalized_items,
    ))
    monkeypatch.setattr(handler, "profiles_table", Table("profile_id", []))
    monkeypatch.setattr(handler, "profile_bindings_table", Table(("account_id", "profile_id"), []))
    monkeypatch.setattr(handler, "profile_mappings_table", Table(("installation_id", "local_profile_source_id"), []))
    monkeypatch.setattr(handler, "principals_table", Table("principal_id", [records["principal"]]))
    monkeypatch.setattr(handler, "identity_memberships_table", Table("principal_id", [records["membership"]]))
    monkeypatch.setattr(handler, "identity_households_table", Table("household_id", [records["household"]]))
    monkeypatch.setattr(handler, "identity_profiles_table", Table("profile_id", [records["profile"]]))


def install_legacy_identity_context(monkeypatch, *, account_id="acct_1", subject="subject-1", role="owner"):
    records = graph(role=role, account_id=account_id, subject=subject)
    accounts = Table("account_id", [])
    auth_identities = Table("auth_identity_key", [])
    audit = Table("event_id", [])
    normalized_memberships = Table(("household_id", "membership_id"), [])
    profiles = Table("profile_id", [])
    profile_bindings = Table(("account_id", "profile_id"), [])
    profile_mappings = Table(("installation_id", "local_profile_source_id"), [])
    tables = {
        "accounts": accounts, "auth-identities": auth_identities, "audit": audit,
        "household-memberships": normalized_memberships,
        "profiles": profiles, "profile-bindings": profile_bindings,
        "profile-mappings": profile_mappings,
    }
    transaction_client = TransactionClient(tables)
    dynamo = type("Dynamo", (), {})()
    dynamo.meta = type("Meta", (), {"client": transaction_client})()
    monkeypatch.setattr(handler, "ACCOUNTS_TABLE", "accounts")
    monkeypatch.setattr(handler, "AUTH_IDENTITIES_TABLE", "auth-identities")
    monkeypatch.setattr(handler, "HOUSEHOLD_MEMBERSHIPS_TABLE", "household-memberships")
    monkeypatch.setattr(handler, "PROFILES_TABLE", "profiles")
    monkeypatch.setattr(handler, "PROFILE_BINDINGS_TABLE", "profile-bindings")
    monkeypatch.setattr(handler, "PROFILE_MAPPINGS_TABLE", "profile-mappings")
    monkeypatch.setattr(handler, "SECURITY_AUDIT_TABLE", "audit")
    monkeypatch.setattr(handler, "accounts_table", accounts)
    monkeypatch.setattr(handler, "auth_identities_table", auth_identities)
    monkeypatch.setattr(handler, "household_memberships_table", normalized_memberships)
    monkeypatch.setattr(handler, "profiles_table", profiles)
    monkeypatch.setattr(handler, "profile_bindings_table", profile_bindings)
    monkeypatch.setattr(handler, "profile_mappings_table", profile_mappings)
    monkeypatch.setattr(handler, "security_audit_table", audit)
    monkeypatch.setattr(handler, "principals_table", Table("principal_id", [records["principal"]]))
    monkeypatch.setattr(handler, "identity_memberships_table", Table("principal_id", [records["membership"]]))
    monkeypatch.setattr(handler, "identity_households_table", Table("household_id", [records["household"]]))
    monkeypatch.setattr(handler, "identity_profiles_table", Table("profile_id", [records["profile"]]))
    monkeypatch.setattr(handler, "dynamodb", dynamo)
    return tables, transaction_client


def install_account_backfilled_context(monkeypatch, *, account_id="acct_1", subject="subject-1", role="owner"):
    tables, transaction_client = install_legacy_identity_context(
        monkeypatch, account_id=account_id, subject=subject, role=role,
    )
    now_iso = "2026-07-23T00:00:00Z"
    tables["accounts"].put_item(Item=build_account_record(account_id, now_iso=now_iso, now_epoch=1_000))
    tables["auth-identities"].put_item(Item=build_auth_identity_record(
        account_id=account_id, provider="cognito", provider_subject=subject,
        now_iso=now_iso, now_epoch=1_000,
    ))
    return tables, transaction_client


def install_normalized_profile_context(monkeypatch, *, account_id="acct_1", subject="subject-1", role="owner"):
    tables, transaction_client = install_account_backfilled_context(
        monkeypatch, account_id=account_id, subject=subject, role=role,
    )
    session = protected_session(account_id=account_id, subject=subject, role=role)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: session)
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)
    normalized = handler.migrate_household_membership_v3({})
    assert normalized["statusCode"] == 200
    transaction_client.calls.clear()
    return tables, transaction_client, session


def add_active_normalized_member(tables, *, account_id="acct_2", role="adult"):
    now_iso = "2026-07-23T00:00:00Z"
    tables["accounts"].put_item(Item=build_account_record(account_id, now_iso=now_iso, now_epoch=1_000))
    membership_id = household_membership_id(account_id, "household-1")
    tables["household-memberships"].put_item(Item={
        "household_id": "household-1", "membership_id": membership_id,
        "entity_type": "HouseholdMembership", "account_id": account_id,
        "canonical_role": role, "status": "active", "schema_version": 1,
    })


def test_canonical_role_capabilities_have_one_authoritative_mapping():
    assert capabilities_for(CanonicalRole.OWNER) == frozenset(capability.value for capability in Capability)
    assert Capability.HOUSEHOLD_MANAGE.value not in capabilities_for(CanonicalRole.ADULT)
    assert Capability.RECOMMENDATION_SEND.value in capabilities_for(CanonicalRole.TEEN)
    assert capabilities_for(CanonicalRole.CHILD) == {Capability.PROFILE_MANAGE_SELF.value}


@pytest.mark.parametrize("source, expected", [
    ("owner", CanonicalRole.OWNER), ("adult", CanonicalRole.ADULT),
    ("child", CanonicalRole.CHILD), ("kid", CanonicalRole.CHILD),
    ("teen", CanonicalRole.TEEN),
])
def test_unambiguous_legacy_roles_map_explicitly(source, expected):
    resolution = resolve_legacy_role(source)
    assert resolution.canonical_role is expected
    assert resolution.requires_owner_resolution is False


@pytest.mark.parametrize("source", ["admin", "member"])
def test_ambiguous_ios_legacy_roles_require_owner_resolution(source):
    resolution = resolve_legacy_role(source)
    assert resolution.source_role == source
    assert resolution.canonical_role is None
    assert resolution.requires_owner_resolution is True


def test_household_access_role_is_independent_from_age_classification():
    assert household_access_role(None, canonical=CanonicalRole.OWNER) is HouseholdAccessRole.OWNER
    assert household_access_role(None, canonical=CanonicalRole.ADULT) is HouseholdAccessRole.MEMBER
    assert household_access_role("admin", canonical=CanonicalRole.ADULT) is HouseholdAccessRole.ADMIN
    admin_capabilities = household_capabilities_for(
        CanonicalRole.ADULT, HouseholdAccessRole.ADMIN,
    )
    assert Capability.PROFILE_MANAGE_HOUSEHOLD.value in admin_capabilities
    assert Capability.REQUESTS_VIEW_HOUSEHOLD.value not in admin_capabilities
    assert Capability.DOWNLOADS_VIEW_HOUSEHOLD.value not in admin_capabilities
    assert Capability.STREAMS_VIEW_HOUSEHOLD.value in admin_capabilities
    assert Capability.BILLING_MANAGE.value not in admin_capabilities
    assert Capability.HOUSEHOLD_TRANSFER_OWNERSHIP.value not in admin_capabilities
    assert Capability.PROFILE_DELETE_HOUSEHOLD.value not in admin_capabilities
    member_capabilities = household_capabilities_for(
        CanonicalRole.ADULT, HouseholdAccessRole.MEMBER,
    )
    assert Capability.PROFILE_MANAGE_HOUSEHOLD.value not in member_capabilities
    assert Capability.PROFILE_SWITCH.value not in member_capabilities


def test_provider_subject_is_unique_and_email_never_merges_accounts():
    first = build_auth_identity_record(
        account_id="acct_one", provider="google", provider_subject="provider-user-one",
        email="shared@example.com", email_verified=True, now_iso="2026-07-23T00:00:00Z", now_epoch=1,
    )
    second = build_auth_identity_record(
        account_id="acct_two", provider="google", provider_subject="provider-user-two",
        email="shared@example.com", email_verified=True, now_iso="2026-07-23T00:00:01Z", now_epoch=2,
    )
    assert first["auth_identity_key"] != second["auth_identity_key"]
    assert first["account_id"] != second["account_id"]
    assert "provider_subject" not in first
    with pytest.raises(AccountFoundationError, match="binding_conflict"):
        assert_auth_identity_binding(
            first, account_id="acct_two", provider="google", provider_subject="provider-user-one",
        )
    assert provider_subject_key("google", "provider-user-one") == first["auth_identity_key"]


def test_identity_me_resolves_only_the_protected_server_context(monkeypatch):
    install_identity_context(monkeypatch)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: protected_session())
    response = handler.identity_me_v3({
        "queryStringParameters": {"account_id": "attacker", "role": "child", "profile_id": "attacker-profile"},
        "requestContext": {"authorizer": {"jwt": {"claims": {"role": "child", "account_id": "attacker"}}}},
    })
    body = json.loads(response["body"])
    assert response["statusCode"] == 200
    assert body["account"] == {
        "account_id": "acct_1",
        "status": "active",
        "authz_version": 1,
    }
    assert body["household"]["role"] == "owner"
    assert body["household"]["membership_id"] == household_membership_id("acct_1", "household-1")
    assert "household.manage" in body["household"]["capabilities"]
    assert body["auth_identities"] == [{"provider": "cognito", "email_verified": False, "status": "active"}]
    assert body["device"] == {"device_id": "device-1", "installation_id": "installation-1", "status": "active"}
    assert body["profile_access"] == []
    assert body["migration_state"] == "already_normalized"


@pytest.mark.parametrize("session_state", ["missing", "revoked_or_invalid_dpop", "replayed_dpop"])
def test_identity_me_rejects_missing_revoked_and_dpop_rejected_sessions(monkeypatch, session_state):
    install_identity_context(monkeypatch)
    # authenticated_app_session is the existing replay-guarded DPoP boundary.
    # Each of these states is represented by its fail-closed ``None`` result.
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: None)
    response = handler.identity_me_v3({})
    assert response["statusCode"] == 401
    assert json.loads(response["body"])["state"] == "protected_session_required"


def test_identity_me_rejects_a_session_after_authorization_changes(monkeypatch):
    install_identity_context(monkeypatch)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: protected_session(role="child"))
    response = handler.identity_me_v3({})
    assert response["statusCode"] == 401
    assert json.loads(response["body"])["state"] == "stale_authorization"


def test_template_declares_additive_account_foundation_storage_and_route():
    template = (Path(__file__).resolve().parents[2] / "infra" / "template.yaml").read_text()
    assert "KaevoAccountsTable:" in template
    assert "KaevoAuthIdentitiesTable:" in template
    assert "account_id-created_at_epoch-index" in template
    # Identity V3 routes intentionally use explicit API Gateway route
    # resources instead of SAM HttpApi events. This preserves a single
    # path-scoped invoke permission for the shared API function.
    assert "RouteKey: GET /v3/identity/me" in template
    assert "RouteKey: POST /v3/identity/migrate-household-membership" in template
    assert "RouteKey: PUT /v3/identity/profiles/{profileId}/watching-targets" in template
    assert "RouteKey: PUT /v3/identity/profiles/{profileId}/seerr-binding" in template
    assert "RouteKey: POST /v3/identity/profiles/{profileId}/deletion" in template
    assert "ACCOUNTS_TABLE: !Ref KaevoAccountsTable" in template
    assert "AUTH_IDENTITIES_TABLE: !Ref KaevoAuthIdentitiesTable" in template
    assert "KaevoHouseholdMembershipsTable:" in template
    assert "HOUSEHOLD_MEMBERSHIPS_TABLE: !Ref KaevoHouseholdMembershipsTable" in template


def test_existing_account_migration_is_atomic_idempotent_and_returns_identity(monkeypatch):
    tables, transaction_client = install_legacy_identity_context(monkeypatch)
    session = protected_session()
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: session)
    audit_events = []
    monkeypatch.setattr(handler, "commit_security_audit", lambda item, **_kwargs: audit_events.append(dict(item)))
    event = {"body": json.dumps({"account_id": "attacker", "provider_subject": "attacker"})}

    first = handler.migrate_existing_account_v3(event)
    first_body = json.loads(first["body"])
    assert first["statusCode"] == 200
    assert first_body["migration_state"] == "migration_completed"
    assert first_body["state"] == "household_membership_migration_required"
    assert len(tables["accounts"].items) == len(tables["auth-identities"].items) == 1
    assert len(transaction_client.calls) == 1
    assert len(transaction_client.calls[0]) == 3  # Account, AuthIdentity, completed audit.

    second = handler.migrate_existing_account_v3(event)
    second_body = json.loads(second["body"])
    assert second["statusCode"] == 200
    assert second_body["migration_state"] == "already_migrated"
    assert len(tables["accounts"].items) == len(tables["auth-identities"].items) == 1
    assert "attacker" not in json.dumps(second_body)
    assert "subject-1" not in json.dumps(audit_events + list(tables["audit"].items.values()))


def test_concurrent_existing_account_migration_converges_without_duplicate_records(monkeypatch):
    tables, transaction_client = install_legacy_identity_context(monkeypatch)
    session = protected_session()
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: session)
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)

    def complete_competing_request():
        now_iso = "2026-07-23T00:00:00Z"
        account = build_account_record("acct_1", now_iso=now_iso, now_epoch=1_000)
        identity = build_auth_identity_record(
            account_id="acct_1", provider="cognito", provider_subject="subject-1",
            now_iso=now_iso, now_epoch=1_000,
        )
        tables["accounts"].put_item(Item=account)
        tables["auth-identities"].put_item(Item=identity)

    transaction_client.concurrent_completion = complete_competing_request
    response = handler.migrate_existing_account_v3({})
    body = json.loads(response["body"])
    assert response["statusCode"] == 200
    assert body["state"] == "household_membership_migration_required"
    assert body["migration_state"] == "already_migrated"
    assert len(tables["accounts"].items) == len(tables["auth-identities"].items) == 1


def test_existing_account_migration_rejects_conflicts_missing_graph_and_ambiguous_roles(monkeypatch):
    tables, _transaction_client = install_legacy_identity_context(monkeypatch)
    session = protected_session()
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: session)
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)
    conflict = build_auth_identity_record(
        account_id="acct_other", provider="cognito", provider_subject="subject-1",
        now_iso="2026-07-23T00:00:00Z", now_epoch=1_000,
    )
    tables["auth-identities"].put_item(Item=conflict)
    response = handler.migrate_existing_account_v3({})
    assert response["statusCode"] == 409
    assert json.loads(response["body"])["state"] == "provider_identity_conflict"

    tables, _transaction_client = install_legacy_identity_context(monkeypatch)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: session)
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handler, "principals_table", Table("principal_id", []))
    missing = handler.migrate_existing_account_v3({})
    assert json.loads(missing["body"])["state"] == "authority_record_missing"

    for legacy_role in ("admin", "member"):
        _tables, _transaction_client = install_legacy_identity_context(monkeypatch, role=legacy_role)
        monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: protected_session(role=legacy_role))
        monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)
        manual = handler.migrate_existing_account_v3({})
        assert manual["statusCode"] == 409
        assert json.loads(manual["body"])["state"] == "manual_review_required"


def test_offline_backfill_planner_is_dry_run_only(tmp_path):
    script = Path(__file__).resolve().parents[2] / "scripts" / "plan-existing-account-backfill.py"
    spec = importlib.util.spec_from_file_location("kaevo_backfill_planner", script)
    planner = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(planner)
    authority = graph()
    snapshot = {"records": [{"subject": "subject-1", **authority}]}
    original = json.loads(json.dumps(snapshot))
    report = planner.plan_snapshot(snapshot, maximum=1)
    assert report["mode"] == "dry_run"
    assert report["write_operations"] == 0
    assert report["findings"][0]["state"] == "eligible"
    assert report["findings"][0]["operations"] == ["create_account", "create_cognito_auth_identity"]
    assert snapshot == original

    export = tmp_path / "authority.json"
    export.write_text(json.dumps(snapshot), encoding="utf-8")
    with pytest.raises(SystemExit):
        planner.main(["--input", str(export), "--execute"])


@pytest.mark.parametrize("role", ["owner", "adult", "child", "teen"])
def test_household_membership_normalizes_each_canonical_role(monkeypatch, role):
    tables, transaction_client = install_account_backfilled_context(monkeypatch, role=role)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: protected_session(role=role))
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)

    response = handler.migrate_household_membership_v3({
        "body": json.dumps({
            "account_id": "attacker", "household_id": "attacker-household", "role": "owner",
            "capabilities": ["household.manage"], "profile_access": [{"profile_id": "attacker"}],
        }),
    })
    body = json.loads(response["body"])
    assert response["statusCode"] == 200
    assert body["migration_state"] == "membership_migration_completed"
    expected_access_role = "owner" if role == "owner" else "member"
    assert body["household"]["role"] == expected_access_role
    assert body["household"]["canonical_role"] == role
    assert body["household"]["membership_id"] == household_membership_id("acct_1", "household-1")
    assert body["profile_access"] == []
    expected_writes = 4 if role == "owner" else 3  # membership, uniqueness, optional owner, audit
    assert len(transaction_client.calls) == 1
    assert len(transaction_client.calls[0]) == expected_writes
    assert "attacker" not in json.dumps(body)
    assert len(tables["household-memberships"].items) == (3 if role == "owner" else 2)


def test_household_membership_is_idempotent_and_preserves_existing_owner(monkeypatch):
    tables, _transaction_client = install_account_backfilled_context(monkeypatch)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: protected_session())
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)

    first = handler.migrate_household_membership_v3({})
    snapshot = {str(key): dict(value) for key, value in tables["household-memberships"].items.items()}
    second = handler.migrate_household_membership_v3({})
    assert json.loads(first["body"])["migration_state"] == "membership_migration_completed"
    assert json.loads(second["body"])["migration_state"] == "already_normalized"
    assert {str(key): dict(value) for key, value in tables["household-memberships"].items.items()} == snapshot


def test_household_membership_concurrent_request_converges_without_duplicate_records(monkeypatch):
    tables, transaction_client = install_account_backfilled_context(monkeypatch, role="adult")
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: protected_session(role="adult"))
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)
    records = graph(role="adult")
    claims = handler.derive_authoritative_claims(
        "subject-1", records["principal"], records["membership"], records["household"], records["profile"],
    )

    def complete_competing_request():
        now_iso = "2026-07-23T00:00:00Z"
        membership = build_household_membership_record(claims, CanonicalRole.ADULT, now_iso=now_iso, now_epoch=1_000)
        tables["household-memberships"].put_item(Item=membership)
        tables["household-memberships"].put_item(Item=build_account_household_guard(
            claims, membership_id=membership["membership_id"], now_iso=now_iso, now_epoch=1_000,
        ))

    transaction_client.concurrent_completion = complete_competing_request
    response = handler.migrate_household_membership_v3({})
    assert response["statusCode"] == 200
    assert json.loads(response["body"])["migration_state"] == "already_normalized"
    assert len(tables["household-memberships"].items) == 2


@pytest.mark.parametrize("legacy_role", ["admin", "member"])
def test_household_membership_leaves_ambiguous_legacy_roles_unresolved(monkeypatch, legacy_role):
    _tables, _transaction_client = install_account_backfilled_context(monkeypatch, role=legacy_role)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: protected_session(role=legacy_role))
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)
    response = handler.migrate_household_membership_v3({})
    assert response["statusCode"] == 409
    assert json.loads(response["body"])["state"] == "legacy_role_unresolved"


def test_household_membership_rejects_missing_and_ambiguous_authority(monkeypatch):
    _tables, _transaction_client = install_account_backfilled_context(monkeypatch)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: protected_session())
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(handler, "principals_table", Table("principal_id", []))
    missing = handler.migrate_household_membership_v3({})
    assert json.loads(missing["body"])["state"] == "household_authority_missing"

    _tables, _transaction_client = install_account_backfilled_context(monkeypatch)
    ambiguous_principal = graph()["principal"]
    ambiguous_principal["household_ids"] = ["household-1", "household-2"]
    monkeypatch.setattr(handler, "principals_table", Table("principal_id", [ambiguous_principal]))
    ambiguous = handler.migrate_household_membership_v3({})
    assert ambiguous["statusCode"] == 409
    assert json.loads(ambiguous["body"])["state"] == "household_authority_ambiguous"


def test_household_membership_never_creates_a_second_owner_or_reactivates_history(monkeypatch):
    tables, _transaction_client = install_account_backfilled_context(monkeypatch)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: protected_session())
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)
    # This guard is an explicit competing owner, not an inferred owner.
    tables["household-memberships"].put_item(Item={
        "household_id": "household-1", "membership_id": handler.household_owner_guard_id("household-1"),
        "entity_type": "HouseholdMembershipOwnerGuard", "normalized_membership_id": "hm1-other",
        "account_id": "acct_other", "status": "active", "schema_version": 1,
    })
    conflict = handler.migrate_household_membership_v3({})
    assert json.loads(conflict["body"])["state"] == "ownership_conflict"
    assert len(tables["household-memberships"].items) == 1

    tables, _transaction_client = install_account_backfilled_context(monkeypatch, role="adult")
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: protected_session(role="adult"))
    records = graph(role="adult")
    claims = handler.derive_authoritative_claims(
        "subject-1", records["principal"], records["membership"], records["household"], records["profile"],
    )
    inactive = build_household_membership_record(claims, CanonicalRole.ADULT, now_iso="2026-07-23T00:00:00Z", now_epoch=1)
    inactive["status"] = "removed"
    tables["household-memberships"].put_item(Item=inactive)
    blocked = handler.migrate_household_membership_v3({})
    assert json.loads(blocked["body"])["state"] == "membership_migration_not_required"
    assert inactive["status"] == "removed"


def test_identity_me_requires_membership_then_returns_server_derived_profile_access(monkeypatch):
    tables, _transaction_client = install_account_backfilled_context(monkeypatch, role="adult")
    session = protected_session(role="adult")
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: session)
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)
    before = handler.identity_me_v3({})
    assert json.loads(before["body"])["state"] == "household_membership_migration_required"
    migrated = handler.migrate_household_membership_v3({})
    assert migrated["statusCode"] == 200
    after = handler.identity_me_v3({}, verified_session=session)
    after_body = json.loads(after["body"])
    assert after_body["household"]["role"] == "member"
    assert after_body["household"]["canonical_role"] == "adult"
    assert after_body["profile_access"] == []
    assert after_body["migration_state"] == "already_normalized"
    assert len(tables["household-memberships"].items) == 2


def test_identity_me_accepts_member_account_in_owner_household(monkeypatch):
    install_identity_context(
        monkeypatch,
        account_id="member-account",
        subject="member-subject",
        role="adult",
    )
    handler.identity_households_table.items["household-1"]["account_id"] = "owner-account"
    session = protected_session(
        account_id="member-account",
        subject="member-subject",
        role="adult",
    )
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: session)
    monkeypatch.setattr(handler, "commit_security_audit", lambda *_args, **_kwargs: None)

    response = handler.identity_me_v3({}, verified_session=session)
    body = json.loads(response["body"])

    assert response["statusCode"] == 200
    assert body["account"]["status"] == "active"
    assert body["household"]["role"] == "member"
    assert body["household"]["canonical_role"] == "adult"


def test_membership_migration_audit_is_privacy_safe_and_dpop_boundary_remains_required(monkeypatch):
    tables, _transaction_client = install_account_backfilled_context(monkeypatch, subject="sensitive-subject", role="child")
    session = protected_session(subject="sensitive-subject", role="child")
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: session)
    audit = []
    monkeypatch.setattr(handler, "commit_security_audit", lambda item, **_kwargs: audit.append(dict(item)))
    response = handler.migrate_household_membership_v3({"headers": {"dpop": "private-material"}})
    assert response["statusCode"] == 200
    serialized = json.dumps(audit + list(tables["audit"].items.values()))
    assert "sensitive-subject" not in serialized
    assert "private-material" not in serialized

    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: None)
    rejected = handler.migrate_household_membership_v3({})
    assert rejected["statusCode"] == 401
    assert json.loads(rejected["body"])["state"] == "protected_session_required"


def test_household_membership_offline_planner_is_dry_run_only_and_finds_owner_conflicts(tmp_path):
    script = Path(__file__).resolve().parents[2] / "scripts" / "plan-household-membership-normalization.py"
    spec = importlib.util.spec_from_file_location("kaevo_membership_planner", script)
    planner = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(planner)
    owner = {"subject": "subject-1", **graph(role="owner")}
    second_owner = {"subject": "subject-2", **graph(role="owner", account_id="acct_2", subject="subject-2")}
    snapshot = {"records": [owner, second_owner]}
    original = json.loads(json.dumps(snapshot))
    report = planner.plan_snapshot(snapshot, maximum=2)
    assert report["mode"] == "dry_run"
    assert report["write_operations"] == 0
    assert {finding["state"] for finding in report["findings"]} == {"ownership_conflict"}
    assert snapshot == original

    export = tmp_path / "authority.json"
    export.write_text(json.dumps(snapshot), encoding="utf-8")
    with pytest.raises(SystemExit):
        planner.main(["--input", str(export), "--execute"])


def test_cloud_profile_creation_is_atomic_server_issued_and_ignores_identity_inputs(monkeypatch):
    tables, transaction_client, _session = install_normalized_profile_context(monkeypatch)
    event = {"body": json.dumps({
        "display_name": "Alex", "profile_type": "adult", "age_classification": "adult",
        "account_id": "attacker", "household_id": "other", "binding_id": "attacker-binding",
        "owner_account_id": "attacker", "access_level": "view", "capabilities": ["household.manage"],
    })}
    response = handler.create_profile_v3(event)
    body = json.loads(response["body"])
    assert response["statusCode"] == 200
    assert body["migration_state"] == "profile_created"
    assert len(body["profile_access"]) == 1
    profile = body["profile_access"][0]
    assert profile["profile_id"].startswith("prf1_")
    assert profile["profile_type"] == "adult"
    assert profile["access_level"] == "manage"
    assert len(transaction_client.calls) == 1
    assert len(transaction_client.calls[0]) == 3  # Profile, initial binding, audit.
    created = next(iter(tables["profiles"].items.values()))
    assert created["household_id"] == "household-1"
    assert created["protection_policy_ref"] == "profile-protection-unconfigured-v1"
    assert "attacker" not in json.dumps(created)
    assert "Alex" not in json.dumps(list(tables["audit"].items.values()))


def test_profile_bindings_allow_explicit_switch_and_view_only(monkeypatch):
    tables, _transaction_client, _session = install_normalized_profile_context(monkeypatch)
    first = handler.create_profile_v3({"body": json.dumps({
        "display_name": "Private Adult", "profile_type": "adult", "age_classification": "adult",
    })})
    first_profile_id = json.loads(first["body"])["profile_access"][0]["profile_id"]
    add_active_normalized_member(tables)
    switch = handler.create_profile_binding_v3({"body": json.dumps({
        "target_account_id": "acct_2", "access_level": "switch", "account_id": "attacker",
    })}, f"/v3/identity/profiles/{first_profile_id}/bindings")
    assert json.loads(switch["body"])["state"] == "profile_binding_created"

    second = handler.create_profile_v3({"body": json.dumps({
        "display_name": "Child", "profile_type": "child", "age_classification": "child",
    })})
    second_profile_id = next(item["profile_id"] for item in json.loads(second["body"])["profile_access"] if item["profile_id"] != first_profile_id)
    view = handler.create_profile_binding_v3({"body": json.dumps({
        "target_account_id": "acct_2", "access_level": "view",
    })}, f"/v3/identity/profiles/{second_profile_id}/bindings")
    assert json.loads(view["body"])["state"] == "profile_binding_created"
    bindings = tables["profile-bindings"].items
    assert bindings[("acct_2", first_profile_id)]["access_level"] == "switch"
    assert bindings[("acct_2", second_profile_id)]["access_level"] == "view"


def test_profile_binding_rejects_elevation_cross_household_unknown_or_inactive_member(monkeypatch):
    tables, _transaction_client, _session = install_normalized_profile_context(monkeypatch)
    created = handler.create_profile_v3({"body": json.dumps({
        "display_name": "Teen", "profile_type": "teen", "age_classification": "teen",
    })})
    profile_id = json.loads(created["body"])["profile_access"][0]["profile_id"]
    for payload, state in (
        ({"target_account_id": "missing", "access_level": "view"}, "target_account_not_active_member"),
        ({"target_account_id": "acct_2", "access_level": "manage"}, "profile_access_level_not_permitted"),
    ):
        result = handler.create_profile_binding_v3({"body": json.dumps(payload)}, f"/v3/identity/profiles/{profile_id}/bindings")
        assert json.loads(result["body"])["state"] == state

    add_active_normalized_member(tables)
    tables["profiles"].put_item(Item={
        "profile_id": "prf1_other", "entity_type": "Profile", "household_id": "other-household",
        "profile_type": "adult", "display_name": "Other", "age_classification": "adult",
        "status": "active", "schema_version": 1,
    })
    cross = handler.create_profile_binding_v3({"body": json.dumps({
        "target_account_id": "acct_2", "access_level": "view",
    })}, "/v3/identity/profiles/prf1_other/bindings")
    assert json.loads(cross["body"])["state"] == "cross_household_binding_rejected"

    target_key = ("household-1", household_membership_id("acct_2", "household-1"))
    tables["household-memberships"].items[target_key]["status"] = "removed"
    removed = handler.create_profile_binding_v3({"body": json.dumps({
        "target_account_id": "acct_2", "access_level": "view",
    })}, f"/v3/identity/profiles/{profile_id}/bindings")
    assert json.loads(removed["body"])["state"] == "target_account_not_active_member"


def test_profile_binding_is_idempotent_concurrent_and_never_reactivates(monkeypatch):
    tables, transaction_client, _session = install_normalized_profile_context(monkeypatch)
    created = handler.create_profile_v3({"body": json.dumps({
        "display_name": "Child", "profile_type": "child", "age_classification": "child",
    })})
    profile_id = json.loads(created["body"])["profile_access"][0]["profile_id"]
    add_active_normalized_member(tables)
    event = {"body": json.dumps({"target_account_id": "acct_2", "access_level": "view"})}

    profile = tables["profiles"].get_item(Key={"profile_id": profile_id})["Item"]
    def complete_competing_request():
        tables["profile-bindings"].put_item(Item=build_profile_binding(
            account_id="acct_2", profile=profile, access_level="view", granted_by_account_id="acct_1",
            now_iso="2026-07-23T00:00:00Z", now_epoch=1, provenance="test",
        ))
    transaction_client.concurrent_completion = complete_competing_request
    converged = handler.create_profile_binding_v3(event, f"/v3/identity/profiles/{profile_id}/bindings")
    assert json.loads(converged["body"])["state"] == "profile_binding_already_exists"
    assert len([key for key in tables["profile-bindings"].items if key == ("acct_2", profile_id)]) == 1

    tables["profile-bindings"].items[("acct_2", profile_id)]["status"] = "revoked"
    blocked = handler.create_profile_binding_v3(event, f"/v3/identity/profiles/{profile_id}/bindings")
    assert json.loads(blocked["body"])["state"] == "profile_binding_not_reactivated"


def test_identity_me_returns_only_explicit_active_bindings(monkeypatch):
    tables, _transaction_client, session = install_normalized_profile_context(monkeypatch)
    no_bindings = handler.identity_me_v3({}, verified_session=session)
    assert json.loads(no_bindings["body"])["profile_access"] == []
    created = handler.create_profile_v3({"body": json.dumps({
        "display_name": "Owner Adult", "profile_type": "adult", "age_classification": "adult",
    })})
    profile_id = json.loads(created["body"])["profile_access"][0]["profile_id"]
    assert json.loads(handler.identity_me_v3({}, verified_session=session)["body"])["profile_access"][0]["profile_id"] == profile_id
    # A revoked binding remains historical data but is not resolved access.
    tables["profile-bindings"].items[("acct_1", profile_id)]["status"] = "revoked"
    assert json.loads(handler.identity_me_v3({}, verified_session=session)["body"])["profile_access"] == []


def test_identity_me_exposes_only_the_exact_normalized_self_profile_for_replacement_mapping(monkeypatch):
    tables, _transaction_client, session = install_normalized_profile_context(monkeypatch)
    membership_id = household_membership_id("acct_1", "household-1")
    membership = tables["household-memberships"].items[("household-1", membership_id)]
    membership["profile_id"] = "profile-1"
    identity_profile = handler.identity_profiles_table.items["profile-1"]
    identity_profile["display_name"] = "Owner"

    response = handler.identity_me_v3({}, verified_session=session)

    assert response["statusCode"] == 200
    assert json.loads(response["body"])["profile_access"] == [{
        "profile_id": "profile-1",
        "profile_type": "adult",
        "display_name": "Owner",
        "access_level": "manage",
        "status": "active",
        "is_self": True,
        "request_access_enabled": True,
        "parental_controls": None,
        "switch_protection": "not_configured",
        "allowed_viewing_profile_ids": ["profile-1"],
    }]

    # The exact profile edge is mandatory: a stale or unrelated pointer is
    # never surfaced as a candidate for device-local mapping.
    membership["profile_id"] = "another-profile"
    assert json.loads(handler.identity_me_v3({}, verified_session=session)["body"])["profile_access"] == []


def test_identity_me_prefers_exact_profile_request_policy_over_stale_membership_projection(monkeypatch):
    tables, _transaction_client, session = install_normalized_profile_context(monkeypatch)
    membership_id = household_membership_id("acct_1", "household-1")
    membership = tables["household-memberships"].items[("household-1", membership_id)]
    membership["profile_id"] = "profile-1"
    membership["request_access_enabled"] = False
    identity_profile = handler.identity_profiles_table.items["profile-1"]
    identity_profile["display_name"] = "Member"
    identity_profile["request_access_enabled"] = True

    response = handler.identity_me_v3({}, verified_session=session)

    assert response["statusCode"] == 200
    assert json.loads(response["body"])["profile_access"][0]["request_access_enabled"] is True


def test_identity_me_exposes_only_exact_self_seerr_binding(monkeypatch):
    tables, _transaction_client, session = install_normalized_profile_context(monkeypatch)
    membership_id = household_membership_id("acct_1", "household-1")
    membership = tables["household-memberships"].items[("household-1", membership_id)]
    membership["profile_id"] = "profile-1"
    identity_profile = handler.identity_profiles_table.items["profile-1"]
    identity_profile.update({
        "display_name": "Owner",
        "seerr_binding_state": "active",
        "seerr_user_id": "42",
    })

    response = handler.identity_me_v3({}, verified_session=session)

    assert response["statusCode"] == 200
    self_access = json.loads(response["body"])["profile_access"]
    assert len(self_access) == 1
    assert self_access[0]["profile_id"] == "profile-1"
    assert self_access[0]["is_self"] is True
    assert self_access[0]["seerr_user_id"] == "42"

    identity_profile["seerr_binding_state"] = "inactive"
    response = handler.identity_me_v3({}, verified_session=session)
    assert "seerr_user_id" not in json.loads(response["body"])["profile_access"][0]


def test_owner_updates_exact_watching_targets_without_changing_switch_authority(monkeypatch):
    tables, _transaction_client, _session = install_normalized_profile_context(monkeypatch)
    source = handler.identity_profiles_table.items["profile-1"]
    source["switch_profile_ids"] = ["profile-switch-only"]
    source["watching_profile_ids"] = []
    handler.identity_profiles_table.put_item(Item={
        "profile_id": "profile-viewer-2",
        "account_id": "acct_2",
        "household_id": "household-1",
        "profile_type": "kid",
        "state": "active",
    })

    result = handler.update_profile_watching_targets_v3(
        {"body": json.dumps({"profile_ids": ["profile-viewer-2"]})},
        "/v3/identity/profiles/profile-1/watching-targets",
    )
    body = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert body == {
        "state": "watching_targets_updated",
        "profile_ids": ["profile-viewer-2"],
    }
    stored = handler.identity_profiles_table.items["profile-1"]
    assert stored["watching_profile_ids"] == ["profile-viewer-2"]
    assert stored["switch_profile_ids"] == ["profile-switch-only"]


def test_owner_recovers_exact_parent_managed_kid_as_switch_and_view_target(monkeypatch):
    owner_profile = {
        "profile_id": "profile-owner",
        "household_id": "household-1",
        "household_access_role": "owner",
        "state": "active",
    }
    kid_controls = {
        "version": 1,
        "is_enabled": True,
        "preset": "olderKids",
        "hide_unrated_content": True,
        "blocked_genres": ["horror"],
        "blocked_tags": [],
        "allowed_tags": ["kaevo-kids-approved"],
        "exceptions": [],
    }
    monkeypatch.setattr(handler, "identity_profiles_table", Table("profile_id", [
        owner_profile,
        {
            "profile_id": "profile-kid",
            "household_id": "household-1",
            "owner_principal_id": "principal-owner",
            "display_name": "Kid",
            "profile_type": "kid",
            "state": "active",
            "managed_by_owner": True,
            "parental_controls": kid_controls,
        },
        {
            "profile_id": "profile-other-household",
            "household_id": "household-2",
            "owner_principal_id": "principal-owner",
            "display_name": "Other",
            "profile_type": "kid",
            "state": "active",
            "managed_by_owner": True,
        },
    ]))

    resolved = handler._authorized_parent_managed_profile_access(
        principal={
            "principal_id": "principal-owner",
            "profile_ids": ["profile-owner", "profile-kid", "profile-other-household"],
        },
        source_profile=owner_profile,
        household_id="household-1",
        is_household_owner=True,
    )

    assert resolved == [{
        "profile_id": "profile-kid",
        "profile_type": "kid",
        "display_name": "Kid",
        "access_level": "switch",
        "status": "active",
        "switch_protection": "not_configured",
        "parental_controls": kid_controls,
    }]
    assert handler._authorized_parent_managed_profile_access(
        principal={"principal_id": "principal-owner", "profile_ids": ["profile-kid"]},
        source_profile=owner_profile,
        household_id="household-1",
        is_household_owner=False,
    ) == []


def test_owner_roster_reads_back_parent_managed_kid_access_without_membership_or_seat(monkeypatch):
    tables, _transaction_client, session = install_normalized_profile_context(monkeypatch)
    membership_id = household_membership_id("acct_1", "household-1")
    membership = tables["household-memberships"].items[("household-1", membership_id)]
    membership["profile_id"] = "profile-1"
    owner = handler.identity_profiles_table.items["profile-1"]
    owner.update({
        "display_name": "Owner",
        "role": "owner",
        "canonical_role": "owner",
        "household_access_role": "owner",
        "switch_profile_ids": ["profile-kid"],
        "watching_profile_ids": ["profile-kid"],
    })
    principal = handler.principals_table.items[session["principal_id"]]
    principal["profile_ids"] = ["profile-1", "profile-kid"]
    handler.identity_profiles_table.put_item(Item={
        "profile_id": "profile-kid",
        "account_id": "acct_1",
        "household_id": "household-1",
        "owner_principal_id": session["principal_id"],
        "display_name": "Kid",
        "profile_type": "kid",
        "role": "child",
        "canonical_role": "child",
        "household_access_role": "member",
        "cloud_access_enabled": False,
        "managed_by_owner": True,
        "state": "active",
        "switch_profile_ids": [],
        "watching_profile_ids": [],
        "jellyfin_binding_state": "active",
        "jellyfin_user_id": "jellyfin-kid",
        "seerr_binding_state": "active",
        "seerr_user_id": "seerr-kid",
    })

    switch_result = handler.update_profile_switch_targets_v3(
        {"body": json.dumps({"profile_ids": ["profile-1"]})},
        "/v3/identity/profiles/profile-kid/switch-targets",
    )
    watching_result = handler.update_profile_watching_targets_v3(
        {"body": json.dumps({"profile_ids": ["profile-1"]})},
        "/v3/identity/profiles/profile-kid/watching-targets",
    )
    roster_result = handler.list_household_profiles_v3({})

    assert switch_result["statusCode"] == 200
    assert watching_result["statusCode"] == 200
    assert roster_result["statusCode"] == 200
    roster = {
        item["profile_id"]: item
        for item in json.loads(roster_result["body"])["profiles"]
    }
    assert roster["profile-kid"]["allowed_profile_switch_targets"] == ["profile-1"]
    assert roster["profile-kid"]["allowed_watching_targets"] == ["profile-1"]
    assert roster["profile-kid"]["cloud_access_enabled"] is False
    assert all(
        str(item.get("profile_id") or "") != "profile-kid"
        for item in tables["household-memberships"].items.values()
    )
    stored_kid = handler.identity_profiles_table.items["profile-kid"]
    assert stored_kid["jellyfin_user_id"] == "jellyfin-kid"
    assert stored_kid["seerr_user_id"] == "seerr-kid"


def test_parental_controls_wire_contract_matches_ios_and_rejects_coerced_ids():
    policy = {
        "version": 1,
        "is_enabled": True,
        "preset": "olderKids",
        "hide_unrated_content": True,
        "blocked_genres": ["horror"],
        "blocked_tags": ["mature"],
        "allowed_tags": ["kaevo-kids-approved"],
        "exceptions": [{
            "id": "exception-1",
            "title": "Approved title",
            "scope": "title",
            "provider_item_ids": ["jellyfin-item-1"],
        }],
    }
    assert handler._normalized_parental_controls(
        policy, require_child_safe=True,
    ) == policy
    with pytest.raises(ValueError):
        handler._normalized_parental_controls(
            {**policy, "allowed_tags": [123]}, require_child_safe=True,
        )


def test_watching_targets_are_owner_only_and_resolve_exact_same_household_ids(monkeypatch):
    tables, _transaction_client, owner_session = install_normalized_profile_context(monkeypatch)
    membership_id = household_membership_id("acct_1", "household-1")
    tables["household-memberships"].items[("household-1", membership_id)]["profile_id"] = "profile-1"
    source = handler.identity_profiles_table.items["profile-1"]
    source["display_name"] = "Owner"
    source["watching_profile_ids"] = ["profile-viewer-2", "profile-cross-household"]
    for profile_id, household_id in (
        ("profile-viewer-2", "household-1"),
        ("profile-cross-household", "other-household"),
    ):
        handler.identity_profiles_table.put_item(Item={
            "profile_id": profile_id,
            "account_id": "acct_2",
            "household_id": household_id,
            "profile_type": "kid",
            "display_name": "Exact Viewer" if profile_id == "profile-viewer-2" else "Other Household",
            "state": "active",
        })

    identity = handler.identity_me_v3({}, verified_session=owner_session)
    profile_access = json.loads(identity["body"])["profile_access"]
    self_access = next(
        item for item in profile_access
        if item.get("is_self") is True
    )
    assert self_access["allowed_viewing_profile_ids"] == [
        "profile-1", "profile-viewer-2",
    ]
    assert next(item for item in profile_access if item["profile_id"] == "profile-viewer-2") == {
        "profile_id": "profile-viewer-2",
        "profile_type": "kid",
        "display_name": "Exact Viewer",
        "access_level": "view",
        "status": "active",
        "parental_controls": None,
        "switch_protection": "not_configured",
    }

    _tables, _transaction_client, _member_session = install_normalized_profile_context(
        monkeypatch,
        account_id="member-account",
        subject="member-subject",
        role="adult",
    )
    handler.identity_profiles_table.put_item(Item={
        "profile_id": "profile-viewer-2",
        "account_id": "acct_2",
        "household_id": "household-1",
        "profile_type": "kid",
        "state": "active",
    })
    rejected = handler.update_profile_watching_targets_v3(
        {"body": json.dumps({"profile_ids": ["profile-viewer-2"]})},
        "/v3/identity/profiles/profile-1/watching-targets",
    )
    assert rejected["statusCode"] == 403
    assert json.loads(rejected["body"])["state"] == "watching_targets_owner_required"

def test_profile_binding_offline_planner_is_fixture_only_and_never_writes(tmp_path):
    script = Path(__file__).resolve().parents[2] / "scripts" / "plan-profile-binding-migration.py"
    spec = importlib.util.spec_from_file_location("kaevo_profile_binding_planner", script)
    planner = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(planner)
    snapshot = {"records": [
        {"household_id": "household-1", "display_name": "Alex", "profile_type": "adult", "age_classification": "adult", "active_household_membership": True},
        {"household_id": "household-1", "display_name": "alex", "profile_type": "adult", "age_classification": "adult", "active_household_membership": True},
        {"household_id": "household-1", "display_name": "Unknown", "profile_type": "child", "age_classification": "unresolved", "active_household_membership": True},
    ]}
    original = json.loads(json.dumps(snapshot))
    report = planner.plan_snapshot(snapshot, maximum=3)
    assert report["mode"] == "dry_run"
    assert report["write_operations"] == 0
    assert {finding["state"] for finding in report["findings"]} == {
        "duplicate_display_name_review_required", "unresolved_age_classification",
    }
    assert snapshot == original
    export = tmp_path / "profiles.json"
    export.write_text(json.dumps(snapshot), encoding="utf-8")
    with pytest.raises(SystemExit):
        planner.main(["--input", str(export), "--execute"])


def test_profile_mapping_preview_and_confirmation_are_explicit_and_installation_scoped(monkeypatch):
    tables, _transaction_client, _session = install_normalized_profile_context(monkeypatch)
    created = handler.create_profile_v3({"body": json.dumps({
        "display_name": "Cloud Alex", "profile_type": "adult", "age_classification": "adult",
    })})
    cloud_profile_id = json.loads(created["body"])["profile_access"][0]["profile_id"]
    source = "lps1_" + "a" * 64
    preview = handler.preview_profile_mapping_v3({"body": json.dumps({
        "local_profile_source_id": source, "display_name": "Cloud Alex", "age_classification": "adult",
    })})
    preview_body = json.loads(preview["body"])
    assert preview_body["state"] == "candidate"
    assert preview_body["cloud_profiles"][0]["profile_id"] == cloud_profile_id
    assert "matched" not in json.dumps(preview_body).lower()

    missing_confirmation = handler.confirm_profile_mapping_v3({"body": json.dumps({
        "local_profile_source_id": source, "cloud_profile_id": cloud_profile_id,
    })})
    assert json.loads(missing_confirmation["body"])["state"] == "explicit_confirmation_required"
    confirmed = handler.confirm_profile_mapping_v3({"body": json.dumps({
        "local_profile_source_id": source, "cloud_profile_id": cloud_profile_id, "explicit_confirmation": True,
        "account_id": "attacker", "household_id": "attacker-household",
    })})
    confirmed_body = json.loads(confirmed["body"])
    assert confirmed_body["state"] == "mapping_confirmed"
    assert tables["profile-mappings"].items[("installation-1", source)]["cloud_profile_id"] == cloud_profile_id
    repeated = handler.confirm_profile_mapping_v3({"body": json.dumps({
        "local_profile_source_id": source, "cloud_profile_id": cloud_profile_id, "explicit_confirmation": True,
    })})
    assert json.loads(repeated["body"])["state"] == "mapping_already_confirmed"


def test_profile_mapping_requires_switch_or_manage_and_does_not_change_existing_mapping(monkeypatch):
    tables, _transaction_client, _session = install_normalized_profile_context(monkeypatch)
    created = handler.create_profile_v3({"body": json.dumps({
        "display_name": "Private", "profile_type": "adult", "age_classification": "adult",
    })})
    profile_id = json.loads(created["body"])["profile_access"][0]["profile_id"]
    source = "lps1_" + "b" * 64
    confirmed = handler.confirm_profile_mapping_v3({"body": json.dumps({
        "local_profile_source_id": source, "cloud_profile_id": profile_id, "explicit_confirmation": True,
    })})
    assert confirmed["statusCode"] == 200
    # A different selected cloud profile cannot silently replace the confirmed mapping.
    tables["profiles"].put_item(Item={
        "profile_id": "prf1_viewonly", "entity_type": "Profile", "household_id": "household-1",
        "profile_type": "adult", "display_name": "View only", "age_classification": "adult",
        "status": "active", "schema_version": 1,
    })
    tables["profile-bindings"].put_item(Item=build_profile_binding(
        account_id="acct_1", profile=tables["profiles"].get_item(Key={"profile_id": "prf1_viewonly"})["Item"],
        access_level="view", granted_by_account_id="acct_1", now_iso="2026-07-23T00:00:00Z", now_epoch=1, provenance="test",
    ))
    view_only = handler.confirm_profile_mapping_v3({"body": json.dumps({
        "local_profile_source_id": "lps1_" + "c" * 64, "cloud_profile_id": "prf1_viewonly", "explicit_confirmation": True,
    })})
    assert json.loads(view_only["body"])["state"] == "mapping_not_authorized"
    conflict = handler.confirm_profile_mapping_v3({"body": json.dumps({
        "local_profile_source_id": source, "cloud_profile_id": "prf1_viewonly", "explicit_confirmation": True,
    })})
    assert json.loads(conflict["body"])["state"] == "mapping_not_authorized"
    assert tables["profile-mappings"].items[("installation-1", source)]["cloud_profile_id"] == profile_id


def test_create_and_confirm_profile_mapping_is_atomic_and_local_only_has_no_cloud_record(monkeypatch):
    tables, transaction_client, _session = install_normalized_profile_context(monkeypatch)
    source = "lps1_" + "d" * 64
    created = handler.create_and_confirm_profile_mapping_v3({"body": json.dumps({
        "local_profile_source_id": source, "explicit_confirmation": True,
        "display_name": "Reviewed Child", "profile_type": "child", "age_classification": "child",
        "watch_history": ["must-not-copy"], "pin": "must-not-copy",
    })})
    body = json.loads(created["body"])
    assert body["state"] == "cloud_profile_created_and_mapped"
    assert len(transaction_client.calls[-1]) == 4
    profile = tables["profiles"].get_item(Key={"profile_id": body["cloud_profile_id"]})["Item"]
    assert "watch_history" not in profile and "pin" not in profile
    assert tables["profile-mappings"].items[("installation-1", source)]["mapping_state"] == "confirmed"
    # Local Only is intentionally device-local and has no Cloud route/record.
    assert len(tables["profile-mappings"].items) == 1
    assert local_profile_source_id(source) == source


def test_profile_mapping_conflict_converges_after_concurrent_same_confirmation(monkeypatch):
    tables, transaction_client, _session = install_normalized_profile_context(monkeypatch)
    created = handler.create_profile_v3({"body": json.dumps({
        "display_name": "Concurrent", "profile_type": "adult", "age_classification": "adult",
    })})
    profile_id = json.loads(created["body"])["profile_access"][0]["profile_id"]
    source = "lps1_" + "e" * 64
    transaction_client.concurrent_completion = lambda: tables["profile-mappings"].put_item(Item=build_confirmed_mapping(
        installation_id="installation-1", local_source_id=source, account_id="acct_1",
        household_id="household-1", cloud_profile_id=profile_id,
        now_iso="2026-07-23T00:00:00Z", now_epoch=1,
    ))
    response = handler.confirm_profile_mapping_v3({"body": json.dumps({
        "local_profile_source_id": source, "cloud_profile_id": profile_id, "explicit_confirmation": True,
    })})
    assert json.loads(response["body"])["state"] == "mapping_already_confirmed"


@pytest.mark.parametrize(
    ("mode", "expected_state", "expected_status"),
    [
        ("immediate", "profile_deleted", "deleted"),
        ("retained_30_days", "profile_deletion_scheduled", "deletion_pending"),
    ],
)
def test_owner_profile_deletion_requires_exact_confirmed_mapping_and_revokes_it(
    monkeypatch, mode, expected_state, expected_status,
):
    tables, transaction_client, session = install_normalized_profile_context(monkeypatch)
    created = handler.create_profile_v3({"body": json.dumps({
        "display_name": "Fixture Profile", "profile_type": "adult", "age_classification": "adult",
    })})
    profile_id = json.loads(created["body"])["profile_access"][0]["profile_id"]
    source = "lps1_" + "f" * 64
    confirmed = handler.confirm_profile_mapping_v3({"body": json.dumps({
        "local_profile_source_id": source,
        "cloud_profile_id": profile_id,
        "explicit_confirmation": True,
    })})
    assert confirmed["statusCode"] == 200
    mapping = tables["profile-mappings"].items[("installation-1", source)]
    transaction_client.calls.clear()

    result = handler.delete_profile_v3(
        {"body": json.dumps({
            "local_profile_source_id": source,
            "mapping_id": mapping["mapping_id"],
            "mode": mode,
            "explicit_confirmation": True,
        })},
        f"/v3/identity/profiles/{profile_id}/deletion",
    )
    body = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert body["state"] == expected_state
    assert body["profile_status"] == expected_status
    assert body["mapping_state"] == "revoked"
    if mode == "immediate":
        assert profile_id not in tables["profiles"].items
        assert ("installation-1", source) not in tables["profile-mappings"].items
        assert body["absence_verified"] is True
    else:
        assert tables["profiles"].items[profile_id]["status"] == expected_status
        assert tables["profile-mappings"].items[("installation-1", source)]["mapping_state"] == "revoked"
    assert len(transaction_client.calls) == 1
    assert len(transaction_client.calls[0]) == 3
    assert json.loads(handler.identity_me_v3({}, verified_session=session)["body"])["profile_access"] == []


def test_profile_deletion_is_owner_only_and_fails_closed_on_wrong_mapping_receipt(monkeypatch):
    tables, transaction_client, _session = install_normalized_profile_context(monkeypatch)
    created = handler.create_profile_v3({"body": json.dumps({
        "display_name": "Protected Profile", "profile_type": "adult", "age_classification": "adult",
    })})
    profile_id = json.loads(created["body"])["profile_access"][0]["profile_id"]
    source = "lps1_" + "1" * 64
    confirmed = handler.confirm_profile_mapping_v3({"body": json.dumps({
        "local_profile_source_id": source,
        "cloud_profile_id": profile_id,
        "explicit_confirmation": True,
    })})
    assert confirmed["statusCode"] == 200
    transaction_client.calls.clear()

    wrong_receipt = handler.delete_profile_v3(
        {"body": json.dumps({
            "local_profile_source_id": source,
            "mapping_id": "map1_wrong",
            "mode": "immediate",
            "explicit_confirmation": True,
        })},
        f"/v3/identity/profiles/{profile_id}/deletion",
    )
    assert wrong_receipt["statusCode"] == 409
    assert json.loads(wrong_receipt["body"])["state"] == "mapping_conflict"
    assert tables["profiles"].items[profile_id]["status"] == "active"
    assert tables["profile-mappings"].items[("installation-1", source)]["mapping_state"] == "confirmed"
    assert transaction_client.calls == []

    monkeypatch.setattr(handler, "_mapping_context", lambda _event: (
        protected_session(role="adult"),
        {
            "account": {"account_id": "acct_1"},
            "household": {
                "household_id": "household-1",
                "capabilities": [
                    Capability.PROFILE_MANAGE_HOUSEHOLD.value,
                    Capability.PROFILE_SWITCH.value,
                ],
            },
            "profile_access": [{"profile_id": profile_id, "access_level": "manage", "status": "active"}],
        },
        None,
    ))
    denied = handler.delete_profile_v3(
        {"body": json.dumps({
            "local_profile_source_id": source,
            "mapping_id": tables["profile-mappings"].items[("installation-1", source)]["mapping_id"],
            "mode": "immediate",
            "explicit_confirmation": True,
        })},
        f"/v3/identity/profiles/{profile_id}/deletion",
    )
    assert denied["statusCode"] == 403
    assert json.loads(denied["body"])["state"] == "profile_deletion_not_authorized"
    assert tables["profiles"].items[profile_id]["status"] == "active"
    assert transaction_client.calls == []


def install_canonical_member_deletion_graph(monkeypatch):
    tables, _transaction_client, session = install_normalized_profile_context(monkeypatch)
    tables.update({
        "principals": handler.principals_table,
        "identity-memberships": handler.identity_memberships_table,
        "identity-profiles": handler.identity_profiles_table,
    })
    household_id = "household-1"
    profile_id = "profile-member-1"
    account_id = "acct_member"
    subject = "subject-member"
    owner = tables["principals"].items["subject-1"]
    owner["profile_ids"] = [session["profile_id"], profile_id]
    tables["principals"].items["subject-1"] = owner
    tables["principals"].put_item(Item={
        "principal_id": subject,
        "account_id": account_id,
        "household_id": household_id,
        "role": "adult",
        "profile_ids": [profile_id],
        "state": "active",
        "revoked": False,
    })
    tables["identity-memberships"].put_item(Item={
        "principal_id": subject,
        "account_id": account_id,
        "household_id": household_id,
        "profile_id": profile_id,
        "role": "adult",
        "state": "active",
    })
    tables["identity-profiles"].put_item(Item={
        "profile_id": profile_id,
        "account_id": account_id,
        "household_id": household_id,
        "owner_principal_id": "subject-1",
        "member_principal_id": subject,
        "display_name": "Member",
        "profile_type": "adult",
        "role": "adult",
        "canonical_role": "adult",
        "household_access_role": "member",
        "state": "active",
    })
    membership_id = household_membership_id(account_id, household_id)
    tables["household-memberships"].put_item(Item={
        "household_id": household_id,
        "membership_id": membership_id,
        "entity_type": "HouseholdMembership",
        "account_id": account_id,
        "profile_id": profile_id,
        "canonical_role": "adult",
        "household_access_role": "member",
        "status": "active",
    })
    tables["household-memberships"].put_item(Item={
        "household_id": household_id,
        "membership_id": account_household_guard_id(account_id, household_id),
        "entity_type": "HouseholdMembershipAccountGuard",
        "account_id": account_id,
        "guarded_membership_id": membership_id,
    })
    tables["profile-bindings"].put_item(Item={
        "account_id": account_id,
        "profile_id": profile_id,
        "entity_type": "ProfileBinding",
        "household_id": household_id,
        "status": "active",
    })
    source = "lps1_" + "9" * 64
    tables["profile-mappings"].put_item(Item=build_confirmed_mapping(
        installation_id="installation-member",
        local_source_id=source,
        account_id=account_id,
        household_id=household_id,
        cloud_profile_id=profile_id,
        now_iso="2026-07-30T00:00:00Z",
        now_epoch=1,
    ))

    additions = {
        "installations": Table("installation_id", [{
            "installation_id": "installation-member",
            "principal_id": subject,
            "account_id": account_id,
            "household_id": household_id,
            "state": "active",
            "revoked": False,
            "created_at_epoch": 1,
        }]),
        "app-sessions": Table("token_hash", []),
        "household-invitations": Table("code_hash", [{
            "code_hash": "redacted-hash",
            "invitation_id": "invite-member",
            "profile_id": profile_id,
            "household_id": household_id,
            "state": "consumed",
        }]),
        "household-join-transactions": Table("join_resume_hash", [{
            "join_resume_hash": "redacted-resume",
            "invitation_id": "invite-member",
            "state": "membership_created",
        }]),
        "events": Table(("profile_id", "event_key"), [{
            "profile_id": profile_id,
            "event_key": "event-1",
        }]),
        "profile-settings": Table("profile_id", [{"profile_id": profile_id}]),
        "entitlements": Table("profile_id", [{"profile_id": profile_id}]),
        "devices": Table("device_id", [{
            "device_id": "device-member",
            "profile_id": profile_id,
            "updated_at": "2026-07-30T00:00:00Z",
        }]),
    }
    tables.update(additions)
    monkeypatch.setattr(handler, "installations_table", additions["installations"])
    monkeypatch.setattr(handler, "app_sessions_table", additions["app-sessions"])
    monkeypatch.setattr(handler, "household_invitations_table", additions["household-invitations"])
    monkeypatch.setattr(handler, "household_join_transactions_table", additions["household-join-transactions"])
    monkeypatch.setattr(handler, "events_table", additions["events"])
    monkeypatch.setattr(handler, "profile_settings_table", additions["profile-settings"])
    monkeypatch.setattr(handler, "entitlements_table", additions["entitlements"])
    monkeypatch.setattr(handler, "devices_table", additions["devices"])
    return tables, session, profile_id, account_id, subject, source


def test_canonical_member_immediate_deletion_removes_exact_graph_and_never_cognito(monkeypatch):
    tables, _session, profile_id, account_id, subject, source = (
        install_canonical_member_deletion_graph(monkeypatch)
    )

    result = handler.delete_profile_v3(
        {"body": json.dumps({
            "mode": "immediate",
            "explicit_confirmation": True,
        })},
        f"/v3/identity/profiles/{profile_id}/deletion",
    )
    body = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert body["state"] == "profile_deleted"
    assert body["absence_verified"] is True
    assert body["cognito_identity_deleted"] is False
    assert profile_id not in tables["identity-profiles"].items
    assert subject not in tables["identity-memberships"].items
    assert (
        "household-1",
        household_membership_id(account_id, "household-1"),
    ) not in tables["household-memberships"].items
    assert (
        "household-1",
        account_household_guard_id(account_id, "household-1"),
    ) not in tables["household-memberships"].items
    assert (account_id, profile_id) not in tables["profile-bindings"].items
    assert ("installation-member", source) not in tables["profile-mappings"].items
    assert tables["installations"].items["installation-member"]["state"] == "revoked"
    assert profile_id not in tables["principals"].items["subject-1"]["profile_ids"]
    assert tables["principals"].items[subject]["state"] == "revoked"
    assert tables["auth-identities"].items  # Cognito binding is deliberately retained.
    assert tables["household-invitations"].items == {}
    assert tables["household-join-transactions"].items == {}
    assert tables["events"].items == {}
    assert tables["profile-settings"].items == {}
    assert tables["entitlements"].items == {}
    assert tables["devices"].items == {}


def test_canonical_member_deletion_does_not_leave_authority_stuck_when_avatar_cleanup_is_unavailable(monkeypatch):
    tables, _session, profile_id, _account_id, subject, _source = (
        install_canonical_member_deletion_graph(monkeypatch)
    )

    class FailingAvatarStorage:
        def delete_object(self, **_kwargs):
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "DeleteObject")

    monkeypatch.setattr(handler, "PROFILE_AVATARS_BUCKET", "private-profile-avatars")
    monkeypatch.setattr(handler, "s3_client", FailingAvatarStorage())

    result = handler.delete_profile_v3(
        {"body": json.dumps({
            "mode": "immediate",
            "explicit_confirmation": True,
        })},
        f"/v3/identity/profiles/{profile_id}/deletion",
    )
    body = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert body["state"] == "profile_deleted"
    assert profile_id not in tables["identity-profiles"].items
    assert tables["principals"].items[subject]["state"] == "revoked"


def test_canonical_member_retention_revokes_access_and_preserves_exact_recovery_graph(monkeypatch):
    tables, _session, profile_id, account_id, subject, source = (
        install_canonical_member_deletion_graph(monkeypatch)
    )

    result = handler.delete_profile_v3(
        {"body": json.dumps({
            "mode": "retained_30_days",
            "explicit_confirmation": True,
        })},
        f"/v3/identity/profiles/{profile_id}/deletion",
    )
    body = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert body["state"] == "profile_deletion_scheduled"
    assert body["profile_status"] == "deletion_pending"
    assert body["absence_verified"] is False
    assert tables["identity-profiles"].items[profile_id]["state"] == "deletion_pending"
    assert tables["identity-memberships"].items[subject]["state"] == "deletion_pending"
    membership_key = (
        "household-1",
        household_membership_id(account_id, "household-1"),
    )
    assert tables["household-memberships"].items[membership_key]["status"] == "deletion_pending"
    assert tables["profile-bindings"].items[(account_id, profile_id)]["status"] == "revoked"
    assert tables["profile-mappings"].items[("installation-member", source)]["mapping_state"] == "revoked"
    assert tables["installations"].items["installation-member"]["state"] == "revoked"
    assert tables["household-invitations"].items["redacted-hash"]["state"] == "deletion_pending"
    assert tables["household-join-transactions"].items["redacted-resume"]["state"] == "deletion_pending"
    assert tables["events"].items
    assert tables["profile-settings"].items
    assert tables["entitlements"].items
    assert tables["devices"].items


def test_canonical_member_deletion_repairs_only_a_missing_exact_owner_edge(monkeypatch):
    tables, session, profile_id, _account_id, _subject, _source = (
        install_canonical_member_deletion_graph(monkeypatch)
    )
    canonical = tables["identity-profiles"].items[profile_id]
    canonical.pop("owner_principal_id")
    tables["identity-profiles"].items[profile_id] = canonical

    result = handler.delete_profile_v3(
        {"body": json.dumps({
            "mode": "retained_30_days",
            "explicit_confirmation": True,
        })},
        f"/v3/identity/profiles/{profile_id}/deletion",
    )

    assert result["statusCode"] == 200
    assert tables["identity-profiles"].items[profile_id]["owner_principal_id"] == session["principal_id"]


def test_canonical_member_deletion_never_replaces_a_different_owner_edge(monkeypatch):
    tables, _session, profile_id, _account_id, _subject, _source = (
        install_canonical_member_deletion_graph(monkeypatch)
    )
    canonical = tables["identity-profiles"].items[profile_id]
    canonical["owner_principal_id"] = "different-owner"
    tables["identity-profiles"].items[profile_id] = canonical

    result = handler.delete_profile_v3(
        {"body": json.dumps({
            "mode": "immediate",
            "explicit_confirmation": True,
        })},
        f"/v3/identity/profiles/{profile_id}/deletion",
    )

    assert result["statusCode"] == 409
    assert json.loads(result["body"])["state"] == "profile_deletion_ownership_ambiguous"


def test_due_retained_profile_is_finalized_and_exact_absence_is_verified_on_owner_refresh(monkeypatch):
    tables, _session, profile_id, _account_id, _subject, _source = (
        install_canonical_member_deletion_graph(monkeypatch)
    )
    scheduled = handler.delete_profile_v3(
        {"body": json.dumps({
            "mode": "retained_30_days",
            "explicit_confirmation": True,
        })},
        f"/v3/identity/profiles/{profile_id}/deletion",
    )
    execute_at = json.loads(scheduled["body"])["deletion_execute_at_epoch"]
    monkeypatch.setattr(handler, "epoch_now", lambda: execute_at + 1)

    roster = handler.list_household_profiles_v3({})

    assert roster["statusCode"] == 200
    assert profile_id not in {
        item["profile_id"] for item in json.loads(roster["body"])["profiles"]
    }
    assert profile_id not in tables["identity-profiles"].items
    assert tables["household-invitations"].items == {}
    assert tables["household-join-transactions"].items == {}


def test_canonical_owner_profile_is_never_deleted(monkeypatch):
    tables, _transaction_client, session = install_normalized_profile_context(monkeypatch)
    for name in (
        "installations_table",
        "app_sessions_table",
        "household_invitations_table",
        "household_join_transactions_table",
        "events_table",
        "profile_settings_table",
        "entitlements_table",
        "devices_table",
    ):
        monkeypatch.setattr(handler, name, Table("id", []))

    result = handler.delete_profile_v3(
        {"body": json.dumps({
            "mode": "immediate",
            "explicit_confirmation": True,
        })},
        f"/v3/identity/profiles/{session['profile_id']}/deletion",
    )

    assert result["statusCode"] == 403
    assert json.loads(result["body"])["state"] == "owner_profile_deletion_forbidden"
    assert session["profile_id"] in handler.identity_profiles_table.items


def test_profile_mapping_planner_is_fixture_only_and_never_writes(tmp_path):
    script = Path(__file__).resolve().parents[2] / "scripts" / "plan-local-profile-cloud-mapping.py"
    spec = importlib.util.spec_from_file_location("kaevo_profile_mapping_planner", script)
    planner = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(planner)
    snapshot = {"records": [
        {"installation_id": "i-1", "local_profile_source_id": "lps1_" + "a" * 64, "account_id": "a-1", "household_id": "h-1", "active_account_membership": True},
        {"installation_id": "i-1", "local_profile_source_id": "lps1_" + "a" * 64, "account_id": "a-1", "household_id": "h-1", "active_account_membership": True},
        {"installation_id": "i-2", "local_profile_source_id": "invalid", "account_id": "a-2", "household_id": "h-2", "active_account_membership": True},
    ]}
    original = json.loads(json.dumps(snapshot))
    report = planner.plan_snapshot(snapshot, maximum=3)
    assert report["mode"] == "dry_run" and report["write_operations"] == 0
    assert {finding["state"] for finding in report["findings"]} == {
        "duplicate_local_source_review_required", "invalid_local_source_review_required",
    }
    assert "lps1_" not in json.dumps(report)
    assert snapshot == original
    export = tmp_path / "mappings.json"
    export.write_text(json.dumps(snapshot), encoding="utf-8")
    with pytest.raises(SystemExit):
        planner.main(["--input", str(export), "--execute"])
