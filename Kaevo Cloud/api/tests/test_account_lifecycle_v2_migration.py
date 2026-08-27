import hashlib
import json
import time
import uuid
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import account_lifecycle_v2_migration as migration
from account_foundation import provider_subject_key
from security_identity import base64url_encode, jwk_thumbprint, token_hash


NOW = 1_800_000_000
ACCOUNT = "acct_0123456789abcdef01234567"
SUBJECT = "subject-123"
HOUSEHOLD = "hh_0123456789abcdef0123456789"
IDENTITY_PROFILE = "profile_0123456789abcdef012345"
CLOUD_PROFILE = "prf1_01234567-89ab-4def-8123-456789abcdef"
PUBLIC_BASE_URL = "https://o25nzxe9bk.execute-api.us-west-2.amazonaws.com/production"


class ProductionTable:
    def __init__(self, items=None, query=None):
        self.items = dict(items or {})
        self.query_result = query

    def get_item(self, *, Key, **_kwargs):
        key = next(iter(Key.values()))
        item = self.items.get(key)
        return {"Item": item} if item is not None else {}

    def query(self, **kwargs):
        if callable(self.query_result):
            return {"Items": self.query_result(kwargs)}
        return {"Items": list(self.query_result or [])}

    def put_item(self, *, Item, **_kwargs):
        key = str(Item.get("token_hash") or Item.get("record_key") or "")
        self.items[key] = dict(Item)


class ProductionDynamoDB:
    def __init__(self, tables):
        self.tables = tables
        self.transactions = []
        self.meta = SimpleNamespace(client=self)

    def Table(self, name):
        return self.tables[name]

    def transact_write_items(self, **kwargs):
        self.transactions.append(kwargs)


def graph():
    account = {
        "account_id": ACCOUNT, "entity_type": "Account", "status": "active",
    }
    auth = {
        "auth_identity_key": provider_subject_key("cognito", SUBJECT),
        "account_id": ACCOUNT, "provider": "cognito",
        "entity_type": "AuthIdentity", "status": "active",
    }
    principal = {
        "principal_id": SUBJECT, "account_id": ACCOUNT,
        "household_id": HOUSEHOLD, "profile_ids": [IDENTITY_PROFILE],
        "role": "owner", "state": "active",
    }
    identity_membership = {
        "principal_id": SUBJECT, "account_id": ACCOUNT,
        "household_id": HOUSEHOLD, "profile_id": IDENTITY_PROFILE,
        "role": "owner", "state": "active",
    }
    household = {
        "household_id": HOUSEHOLD, "account_id": ACCOUNT,
        "owner_principal_id": SUBJECT, "state": "active",
    }
    membership = {
        "membership_id": "hm1_owner", "entity_type": "HouseholdMembership",
        "account_id": ACCOUNT, "household_id": HOUSEHOLD,
        "canonical_role": "owner", "household_access_role": "owner",
        "status": "active",
    }
    guards = [
        {
            "membership_id": "ahu1_owner",
            "entity_type": "HouseholdMembershipAccountGuard",
            "account_id": ACCOUNT, "household_id": HOUSEHOLD, "status": "active",
        },
        {
            "membership_id": "hog1_owner",
            "entity_type": "HouseholdMembershipOwnerGuard",
            "account_id": ACCOUNT, "household_id": HOUSEHOLD, "status": "active",
        },
    ]
    identity_profile = {
        "profile_id": IDENTITY_PROFILE, "account_id": ACCOUNT,
        "household_id": HOUSEHOLD, "owner_principal_id": SUBJECT,
        "display_name": "Must not enter registry", "state": "active",
    }
    cloud_profile = {
        "profile_id": CLOUD_PROFILE, "household_id": HOUSEHOLD,
        "display_name": "Must not enter registry", "entity_type": "Profile",
        "status": "active",
    }
    binding = {
        "binding_id": "pbd1_binding", "profile_id": CLOUD_PROFILE,
        "account_id": ACCOUNT, "household_id": HOUSEHOLD,
        "entity_type": "ProfileBinding", "status": "active",
    }
    return {
        "account": account, "auth_identity": auth, "principal": principal,
        "identity_membership": identity_membership, "household": household,
        "account_memberships": [membership, *guards],
        "household_memberships": [membership],
        "identity_profiles": [identity_profile], "cloud_profiles": [cloud_profile],
        "profile_bindings": [binding],
    }


def build(**changes):
    values = graph()
    values.update(changes)
    return migration.build_registry(
        account_id=ACCOUNT, subject=SUBJECT, now=NOW, **values,
    )


def test_exact_legacy_graph_creates_complete_privacy_safe_registry():
    records = build()
    root = next(record for record in records if record["record_key"] == "root")
    assert root["account_role"] == "owner"
    assert root["owner_deletion_state"] == "sole_member"
    assert root["migration_provenance"] == "protected-exact-v1-to-v2"
    resources = [record for record in records if record.get("resource_type")]
    assert {record["resource_type"] for record in resources} == {
        "account", "auth_identity", "cognito_subject", "principal",
        "identity_membership", "household", "household_membership",
        "household_membership_guard", "identity_profile", "cloud_profile",
        "profile_binding",
    }
    assert {record["resource_id"] for record in resources if record["resource_type"] in {
        "identity_profile", "cloud_profile",
    }} == {IDENTITY_PROFILE, CLOUD_PROFILE}
    assert all("display_name" not in record and "email" not in record for record in records)


def test_other_adult_requires_ownership_transfer_instead_of_guessing():
    values = graph()
    values["household_memberships"].append({
        "membership_id": "hm1_other", "entity_type": "HouseholdMembership",
        "account_id": "acct_other0123456789abcdef", "household_id": HOUSEHOLD,
        "canonical_role": "adult", "household_access_role": "member",
        "status": "active",
    })
    records = migration.build_registry(
        account_id=ACCOUNT, subject=SUBJECT, now=NOW, **values,
    )
    root = next(record for record in records if record["record_key"] == "root")
    assert root["owner_deletion_state"] == "transfer_required"


def test_profile_set_conflict_fails_closed():
    values = graph()
    values["principal"]["profile_ids"].append("profile_unproven")
    with pytest.raises(
        migration.LifecycleV2MigrationError, match="identity_profile_set_conflict",
    ):
        migration.build_registry(
            account_id=ACCOUNT, subject=SUBJECT, now=NOW, **values,
        )


def test_cross_account_binding_fails_closed():
    values = graph()
    values["profile_bindings"][0]["account_id"] = "acct_other0123456789abcdef"
    with pytest.raises(
        migration.LifecycleV2MigrationError, match="profile_binding_conflict",
    ):
        migration.build_registry(
            account_id=ACCOUNT, subject=SUBJECT, now=NOW, **values,
        )


def test_ready_receipt_keeps_member_household_from_membership_resource():
    records = build()
    root = next(record for record in records if record["record_key"] == "root")
    root["account_role"] = "member"
    records = [
        record for record in records if record.get("resource_type") != "household"
    ]
    receipt = migration._ready(records, created=True)
    assert receipt["household_id"] == HOUSEHOLD


def test_snapshot_check_binds_exact_key_and_expected_fields():
    check = migration._snapshot_check(
        "source-table", {"account_id": ACCOUNT},
        {"status": "active", "household_id": HOUSEHOLD},
    )["ConditionCheck"]
    assert check["Key"] == {"account_id": ACCOUNT}
    assert set(check["ExpressionAttributeNames"].values()) == {
        "status", "household_id",
    }
    assert set(check["ExpressionAttributeValues"].values()) == {
        "active", HOUSEHOLD,
    }


def test_malformed_request_is_rejected_before_any_cloud_read():
    with pytest.raises(
        migration.LifecycleV2MigrationError, match="migration_request_invalid",
    ):
        migration.migrate_existing_account_v2(
            {"body": "{"}, session={}, dynamodb=None, now=NOW,
        )


def test_production_shaped_migration_reproduces_missing_issuer_audit_failure(monkeypatch):
    """Reproduce the physical 409 -> migration 400 boundary without any write."""
    current = int(time.time())
    access_token = "production-shaped-protected-access-token"
    installation_id = "3100c7ae-abf9-4cde-ae57-6ef02db6d735"
    signing_key = ec.generate_private_key(ec.SECP256R1())
    numbers = signing_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(numbers.x.to_bytes(32, "big")),
        "y": base64url_encode(numbers.y.to_bytes(32, "big")),
    }
    dpop = jwt.encode(
        {
            "htm": "POST",
            "htu": PUBLIC_BASE_URL + "/v4/account-lifecycle/migrate-existing",
            "iat": current,
            "jti": str(uuid.uuid4()),
            "ath": base64url_encode(hashlib.sha256(access_token.encode("ascii")).digest()),
        },
        signing_key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )
    request = {
        "rawPath": "/production/v4/account-lifecycle/migrate-existing",
        "headers": {"authorization": f"Bearer {access_token}", "dpop": dpop},
        "requestContext": {
            "requestId": "production-shaped-migration-request",
            "stage": "production",
            "http": {"method": "POST"},
        },
        "body": json.dumps({"explicit_confirmation": True}),
    }

    values = graph()
    table_names = {
        "ACCOUNT_LIFECYCLE_V2_TABLE": "kaevo-cloud-production-account-lifecycle-v2",
        "ACCOUNTS_TABLE": "kaevo-cloud-production-accounts",
        "AUTH_IDENTITIES_TABLE": "kaevo-cloud-production-auth-identities",
        "PRINCIPALS_TABLE": "kaevo-cloud-production-principals",
        "IDENTITY_MEMBERSHIPS_TABLE": "kaevo-cloud-production-identity-memberships",
        "HOUSEHOLD_MEMBERSHIPS_TABLE": "kaevo-cloud-production-household-memberships",
        "IDENTITY_HOUSEHOLDS_TABLE": "kaevo-cloud-production-identity-households",
        "IDENTITY_PROFILES_TABLE": "kaevo-cloud-production-identity-profiles",
        "PROFILES_TABLE": "kaevo-cloud-production-profiles",
        "PROFILE_BINDINGS_TABLE": "kaevo-cloud-production-profile-bindings",
        "APP_SESSIONS_TABLE": "kaevo-cloud-production-app-sessions",
        "INSTALLATIONS_TABLE": "kaevo-cloud-production-installations",
        "SECURITY_AUDIT_TABLE": "kaevo-cloud-production-security-audit",
    }
    for name, value in table_names.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("KAEVO_ENV", "production")
    monkeypatch.setenv("PUBLIC_API_BASE_URL", PUBLIC_BASE_URL)
    monkeypatch.delenv("EXPECTED_COGNITO_ISSUER", raising=False)

    sessions = ProductionTable({
        f"access#{token_hash(access_token)}": {
            "record_type": "access",
            "state": "active",
            "expires_at": current + 900,
            "account_id": ACCOUNT,
            "principal_id": SUBJECT,
            "installation_id": installation_id,
            "family_id": "family-production-shaped",
            "key_thumbprint": jwk_thumbprint(jwk),
        },
    })
    memberships = ProductionTable(query=lambda kwargs: (
        values["account_memberships"]
        if kwargs.get("IndexName") == "account_id-updated_at_epoch-index"
        else values["household_memberships"]
    ))
    dynamodb = ProductionDynamoDB({
        table_names["ACCOUNT_LIFECYCLE_V2_TABLE"]: ProductionTable(query=[]),
        table_names["ACCOUNTS_TABLE"]: ProductionTable({ACCOUNT: values["account"]}),
        table_names["AUTH_IDENTITIES_TABLE"]: ProductionTable({
            values["auth_identity"]["auth_identity_key"]: values["auth_identity"],
        }),
        table_names["PRINCIPALS_TABLE"]: ProductionTable({SUBJECT: values["principal"]}),
        table_names["IDENTITY_MEMBERSHIPS_TABLE"]: ProductionTable({
            SUBJECT: values["identity_membership"],
        }),
        table_names["HOUSEHOLD_MEMBERSHIPS_TABLE"]: memberships,
        table_names["IDENTITY_HOUSEHOLDS_TABLE"]: ProductionTable({
            HOUSEHOLD: values["household"],
        }),
        table_names["IDENTITY_PROFILES_TABLE"]: ProductionTable({
            IDENTITY_PROFILE: values["identity_profiles"][0],
        }),
        table_names["PROFILES_TABLE"]: ProductionTable({
            CLOUD_PROFILE: values["cloud_profiles"][0],
        }),
        table_names["PROFILE_BINDINGS_TABLE"]: ProductionTable(
            query=values["profile_bindings"],
        ),
        table_names["APP_SESSIONS_TABLE"]: sessions,
        table_names["INSTALLATIONS_TABLE"]: ProductionTable({
            installation_id: {"state": "active", "revoked": False},
        }),
    })
    monkeypatch.setattr(migration.boto3, "resource", lambda _service: dynamodb)

    response = migration.lambda_handler(request, None)

    assert response["statusCode"] == 400
    assert json.loads(response["body"]) == {"state": "audit_unavailable"}
    assert dynamodb.transactions == []
