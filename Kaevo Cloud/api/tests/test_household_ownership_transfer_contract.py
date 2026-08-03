from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

HANDLER_PATH = Path(__file__).resolve().parents[1] / "src" / "handler.py"
TEMPLATE_PATH = Path(__file__).resolve().parents[2] / "infra" / "template.yaml"
SPEC = importlib.util.spec_from_file_location(
    "kaevo_household_ownership_transfer_handler",
    HANDLER_PATH,
)
handler = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(handler)


class ExactTable:
    def __init__(self, items=()):
        self.items = [dict(item) for item in items]

    def get_item(self, *, Key, **_kwargs):
        item = next(
            (
                candidate
                for candidate in self.items
                if all(candidate.get(key) == value for key, value in Key.items())
            ),
            None,
        )
        return {"Item": dict(item)} if item is not None else {}

    def query(self, **_kwargs):
        return {"Items": [dict(item) for item in self.items]}


class RepairableExactTable(ExactTable):
    def __init__(self, items=()):
        super().__init__(items)
        self.update_calls = []

    def update_item(self, *, Key, ExpressionAttributeValues, **kwargs):
        self.update_calls.append({"Key": dict(Key), **kwargs})
        item = next(
            candidate
            for candidate in self.items
            if all(candidate.get(key) == value for key, value in Key.items())
        )
        assert not item.get("profile_id")
        item.update({
            "profile_id": ExpressionAttributeValues[":profile_id"],
            "household_access_role": ExpressionAttributeValues[":access_role"],
            "updated_at": ExpressionAttributeValues[":updated_at"],
            "updated_at_epoch": ExpressionAttributeValues[":updated_at_epoch"],
            "migration_provenance": ExpressionAttributeValues[":provenance"],
        })
        return {}


class TransactionRecorder:
    def __init__(self):
        self.calls = []

    def transact_write_items(self, **kwargs):
        self.calls.append(kwargs)


def install_authority_fixture(monkeypatch):
    household_id = "household-1"
    owner_account_id = "account-owner"
    target_account_id = "account-target"
    owner_profile_id = "profile-owner"
    target_profile_id = "profile-target"
    owner_subject = "subject-owner"
    target_subject = "subject-target"
    owner_membership_id = handler.household_membership_id(
        owner_account_id,
        household_id,
    )
    target_membership_id = handler.household_membership_id(
        target_account_id,
        household_id,
    )
    owner_guard_id = handler.household_owner_guard_id(household_id)

    household = {
        "household_id": household_id,
        "account_id": owner_account_id,
        "owner_principal_id": owner_subject,
        "state": "active",
    }
    owner_principal = {
        "principal_id": owner_subject,
        "account_id": owner_account_id,
        "household_id": household_id,
        "role": "owner",
        "state": "active",
    }
    target_principal = {
        "principal_id": target_subject,
        "account_id": target_account_id,
        "household_id": household_id,
        "role": "adult",
        "state": "active",
    }
    owner_profile = {
        "profile_id": owner_profile_id,
        "account_id": owner_account_id,
        "household_id": household_id,
        "owner_principal_id": owner_subject,
        "display_name": "Owner",
        "profile_type": "adult",
        "role": "owner",
        "state": "active",
    }
    target_profile = {
        "profile_id": target_profile_id,
        "account_id": target_account_id,
        "household_id": household_id,
        "member_principal_id": target_subject,
        "display_name": "Margaret",
        "profile_type": "adult",
        "role": "adult",
        "state": "active",
    }
    owner_membership = {
        "household_id": household_id,
        "membership_id": owner_membership_id,
        "entity_type": "HouseholdMembership",
        "account_id": owner_account_id,
        "profile_id": owner_profile_id,
        "canonical_role": "owner",
        "household_access_role": "owner",
        "status": "active",
    }
    target_membership = {
        "household_id": household_id,
        "membership_id": target_membership_id,
        "entity_type": "HouseholdMembership",
        "account_id": target_account_id,
        "profile_id": target_profile_id,
        "canonical_role": "adult",
        "household_access_role": "admin",
        "status": "active",
    }
    owner_guard = {
        "household_id": household_id,
        "membership_id": owner_guard_id,
        "entity_type": "HouseholdMembershipOwnerGuard",
        "account_id": owner_account_id,
        "normalized_membership_id": owner_membership_id,
        "status": "active",
    }

    monkeypatch.setattr(handler, "identity_households_table", ExactTable([household]))
    monkeypatch.setattr(
        handler,
        "principals_table",
        ExactTable([owner_principal, target_principal]),
    )
    monkeypatch.setattr(
        handler,
        "identity_memberships_table",
        ExactTable([
            {
                "principal_id": owner_subject,
                "account_id": owner_account_id,
                "household_id": household_id,
                "profile_id": owner_profile_id,
                "role": "owner",
                "state": "active",
            },
            {
                "principal_id": target_subject,
                "account_id": target_account_id,
                "household_id": household_id,
                "profile_id": target_profile_id,
                "role": "adult",
                "state": "active",
            },
        ]),
    )
    monkeypatch.setattr(
        handler,
        "identity_profiles_table",
        ExactTable([owner_profile, target_profile]),
    )
    monkeypatch.setattr(
        handler,
        "household_memberships_table",
        ExactTable([owner_membership, target_membership, owner_guard]),
    )
    monkeypatch.setattr(handler, "profiles_table", ExactTable([]))
    monkeypatch.setattr(handler, "profile_bindings_table", ExactTable([]))

    def resolve(*, subject, **_kwargs):
        if subject == owner_subject:
            return (
                SimpleNamespace(
                    account_id=owner_account_id,
                    household_id=household_id,
                    profile_id=owner_profile_id,
                    authz_version=7,
                ),
                handler.CanonicalRole.OWNER,
                owner_membership,
            )
        return (
            SimpleNamespace(
                account_id=target_account_id,
                household_id=household_id,
                profile_id=target_profile_id,
                authz_version=3,
            ),
            handler.CanonicalRole.ADULT,
            target_membership,
        )

    monkeypatch.setattr(handler, "resolve_household_membership", resolve)
    session = {
        "record_type": "access",
        "principal_id": owner_subject,
        "profile_id": owner_profile_id,
        "household_id": household_id,
    }
    context = {
        "account": {"account_id": owner_account_id},
        "household": {
            "household_id": household_id,
            "canonical_role": "owner",
            "household_access_role": "owner",
            "capabilities": ["household.transfer_ownership", "household.manage"],
        },
    }
    monkeypatch.setattr(
        handler,
        "_ownership_transfer_context",
        lambda _event: (session, context, None),
    )
    monkeypatch.setattr(
        handler,
        "_profile_binding_audit",
        lambda *_args, **_kwargs: {"event_id": "audit-transfer-1"},
    )
    monkeypatch.setattr(handler, "commit_security_audit", lambda _audit: None)
    monkeypatch.setattr(handler, "utc_now_iso", lambda: "2026-07-29T12:00:00+00:00")
    monkeypatch.setattr(handler, "epoch_now", lambda: 1785326400)

    for name in (
        "PRINCIPALS_TABLE",
        "IDENTITY_MEMBERSHIPS_TABLE",
        "HOUSEHOLD_MEMBERSHIPS_TABLE",
        "IDENTITY_HOUSEHOLDS_TABLE",
        "IDENTITY_PROFILES_TABLE",
        "SECURITY_AUDIT_TABLE",
    ):
        monkeypatch.setattr(handler, name, name.lower())

    recorder = TransactionRecorder()
    monkeypatch.setattr(
        handler,
        "dynamodb",
        SimpleNamespace(meta=SimpleNamespace(client=recorder)),
    )
    return {
        "session": session,
        "context": context,
        "target_account_id": target_account_id,
        "target_profile_id": target_profile_id,
        "target_subject": target_subject,
        "recorder": recorder,
    }


def test_owner_sees_only_exact_active_adult_transfer_candidates(monkeypatch):
    fixture = install_authority_fixture(monkeypatch)
    result = handler.list_ownership_transfer_candidates_v3({})
    body = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert body == {
        "state": "ownership_transfer_candidates_ready",
        "candidates": [{
            "account_id": fixture["target_account_id"],
            "profile_id": fixture["target_profile_id"],
            "display_name": "Margaret",
            "canonical_role": "adult",
            "household_access_role": "admin",
        }],
    }


def test_household_roster_uses_only_active_exact_profiles_and_never_invitations(monkeypatch):
    fixture = install_authority_fixture(monkeypatch)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: fixture["session"])
    monkeypatch.setattr(
        handler,
        "_normalized_profile_context",
        lambda _event, _session: (fixture["context"], None),
    )

    class InvitationTableMustNotBeRead:
        def __getattr__(self, _name):
            raise AssertionError("canonical roster must not read household invitations")

    monkeypatch.setattr(handler, "household_invitations_table", InvitationTableMustNotBeRead())
    result = handler.list_household_profiles_v3({})
    body = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert body["state"] == "household_profiles_ready"
    assert [item["display_name"] for item in body["profiles"]] == ["Margaret", "Owner"]
    assert {item["status"] for item in body["profiles"]} == {"active"}
    assert {item["profile_id"] for item in body["profiles"]} == {
        fixture["target_profile_id"], "profile-owner",
    }


def test_household_roster_repairs_one_exact_legacy_profile_pointer(monkeypatch):
    fixture = install_authority_fixture(monkeypatch)
    target_account_id = fixture["target_account_id"]
    target_profile_id = fixture["target_profile_id"]
    target_subject = fixture["target_subject"]
    target_membership_id = handler.household_membership_id(target_account_id, "household-1")
    owner_membership = next(
        item for item in handler.household_memberships_table.items
        if item.get("profile_id") == "profile-owner"
    )
    legacy_normalized_membership = {
        "household_id": "household-1",
        "membership_id": target_membership_id,
        "entity_type": "HouseholdMembership",
        "account_id": target_account_id,
        "canonical_role": "adult",
        "status": "active",
        "schema_version": 1,
    }
    membership_table = RepairableExactTable([
        owner_membership,
        legacy_normalized_membership,
    ])
    monkeypatch.setattr(handler, "household_memberships_table", membership_table)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: fixture["session"])
    monkeypatch.setattr(
        handler,
        "_normalized_profile_context",
        lambda _event, _session: (fixture["context"], None),
    )
    monkeypatch.setattr(handler, "profiles_table", ExactTable([{
        "profile_id": target_profile_id,
        "entity_type": "Profile",
        "household_id": "household-1",
        "display_name": "Margaret",
        "profile_type": "adult",
        "age_classification": "adult",
        "status": "active",
        "schema_version": 1,
    }]))
    monkeypatch.setattr(handler, "profile_bindings_table", ExactTable([{
        "account_id": target_account_id,
        "profile_id": target_profile_id,
        "entity_type": "ProfileBinding",
        "household_id": "household-1",
        "status": "active",
    }]))
    monkeypatch.setattr(handler, "principals_table", ExactTable([{
        "principal_id": target_subject,
        "account_id": target_account_id,
        "household_id": "household-1",
        "role": "adult",
        "authz_version": 1,
        "profile_ids": [target_profile_id],
        "state": "active",
    }]))
    monkeypatch.setattr(handler, "identity_memberships_table", ExactTable([{
        "principal_id": target_subject,
        "account_id": target_account_id,
        "household_id": "household-1",
        "profile_id": target_profile_id,
        "role": "adult",
        "authz_version": 1,
        "state": "active",
    }]))
    monkeypatch.setattr(handler, "identity_households_table", ExactTable([{
        "household_id": "household-1",
        "account_id": "account-owner",
        "owner_principal_id": "subject-owner",
        "state": "active",
    }]))
    monkeypatch.setattr(handler, "utc_now_iso", lambda: "2026-07-31T12:00:00+00:00")
    monkeypatch.setattr(handler, "epoch_now", lambda: 1785508800)

    result = handler.list_household_profiles_v3({})
    body = json.loads(result["body"])

    assert result["statusCode"] == 200
    assert [item["display_name"] for item in body["profiles"]] == ["Margaret", "Owner"]
    assert len(membership_table.update_calls) == 1
    repaired = membership_table.get_item(Key={
        "household_id": "household-1",
        "membership_id": target_membership_id,
    })["Item"]
    assert repaired["profile_id"] == target_profile_id
    assert repaired["household_access_role"] == "member"


def test_legacy_profile_pointer_is_not_repaired_without_exact_binding(monkeypatch):
    fixture = install_authority_fixture(monkeypatch)
    target_account_id = fixture["target_account_id"]
    membership = {
        "household_id": "household-1",
        "membership_id": handler.household_membership_id(target_account_id, "household-1"),
        "entity_type": "HouseholdMembership",
        "account_id": target_account_id,
        "canonical_role": "adult",
        "status": "active",
        "schema_version": 1,
    }
    membership_table = RepairableExactTable([membership])
    monkeypatch.setattr(handler, "household_memberships_table", membership_table)

    result = handler._repair_legacy_active_membership_profile_pointer(membership)

    assert result == membership
    assert membership_table.update_calls == []


def test_household_roster_ignores_legacy_profiles_and_rejects_members(monkeypatch):
    fixture = install_authority_fixture(monkeypatch)
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: fixture["session"])
    manager_context = fixture["context"]
    monkeypatch.setattr(
        handler,
        "_normalized_profile_context",
        lambda _event, _session: (manager_context, None),
    )
    cloud_profile = {
        "profile_id": "cloud-profile-1",
        "entity_type": "Profile",
        "household_id": "household-1",
        "profile_type": "adult",
        "age_classification": "adult",
        "display_name": "Cloud profile",
        "status": "active",
        "schema_version": 1,
    }
    monkeypatch.setattr(handler, "profiles_table", ExactTable([cloud_profile, cloud_profile]))

    roster = handler.list_household_profiles_v3({})
    roster_body = json.loads(roster["body"])
    assert roster["statusCode"] == 200
    assert "cloud-profile-1" not in {
        item["profile_id"] for item in roster_body["profiles"]
    }

    member_context = {
        **manager_context,
        "household": {**manager_context["household"], "capabilities": []},
    }
    monkeypatch.setattr(
        handler,
        "_normalized_profile_context",
        lambda _event, _session: (member_context, None),
    )
    denied = handler.list_household_profiles_v3({})
    assert denied["statusCode"] == 403
    assert json.loads(denied["body"])["state"] == "household_profile_roster_not_authorized"


def test_transfer_requires_explicit_confirmation_before_any_write(monkeypatch):
    fixture = install_authority_fixture(monkeypatch)
    result = handler.transfer_household_ownership_v3({
        "body": json.dumps({
            "target_account_id": fixture["target_account_id"],
            "target_profile_id": fixture["target_profile_id"],
            "explicit_confirmation": False,
        }),
    })

    assert result["statusCode"] == 409
    assert json.loads(result["body"]) == {
        "state": "ownership_transfer_confirmation_required",
    }
    assert fixture["recorder"].calls == []


def test_confirmed_transfer_is_one_atomic_authority_transaction(monkeypatch):
    fixture = install_authority_fixture(monkeypatch)
    result = handler.transfer_household_ownership_v3({
        "body": json.dumps({
            "target_account_id": fixture["target_account_id"],
            "target_profile_id": fixture["target_profile_id"],
            "explicit_confirmation": True,
        }),
    })

    assert result["statusCode"] == 200
    assert json.loads(result["body"]) == {
        "state": "household_ownership_transferred",
        "requires_reauthentication": True,
    }
    assert len(fixture["recorder"].calls) == 1
    writes = fixture["recorder"].calls[0]["TransactItems"]
    assert len(writes) == 11
    assert writes[-1] == {
        "Put": {
            "TableName": "security_audit_table",
            "Item": {"event_id": "audit-transfer-1"},
            "ConditionExpression": "attribute_not_exists(event_id)",
        },
    }

    current_principal = writes[0]["Update"]
    target_principal = writes[1]["Update"]
    household = writes[7]["Update"]
    assert current_principal["ExpressionAttributeValues"][":admin"] == "admin"
    assert target_principal["ExpressionAttributeValues"][":owner_access"] == "owner"
    assert household["ExpressionAttributeValues"][":target_subject"] == fixture["target_subject"]
    assert (
        household["ExpressionAttributeValues"][":target_account_id"]
        == fixture["target_account_id"]
    )


def test_ownership_transfer_routes_and_household_transaction_authority_are_deployed():
    template = TEMPLATE_PATH.read_text(encoding="utf-8")

    assert "KaevoIdentityV3ListOwnershipTransferCandidatesRoute:" in template
    assert (
        "RouteKey: GET /v3/identity/households/ownership-transfer/candidates"
        in template
    )
    assert "KaevoIdentityV3TransferHouseholdOwnershipRoute:" in template
    assert (
        "RouteKey: POST /v3/identity/households/ownership-transfer"
        in template
    )
    assert "RouteKey: GET /v3/identity/households/profiles" in template


def test_household_invitation_index_supports_exact_reset_and_deletion_cleanup():
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    invitation_table = template.split(
        "  KaevoHouseholdInvitationsTable:", maxsplit=1,
    )[1].split("  KaevoHouseholdJoinTransactionsTable:", maxsplit=1)[0]

    assert "AttributeName: household_id" in invitation_table
    assert "IndexName: household_id-index" in invitation_table
    assert "ProjectionType: ALL" in invitation_table

    transaction_policy = template.split(
        "- Sid: ConnectorLifecycleAndIdentityTransactions",
        maxsplit=1,
    )[1].split("- Sid: ReadAuditReferenceKey", maxsplit=1)[0]
    assert "!GetAtt KaevoIdentityHouseholdsTable.Arn" in transaction_policy
