from __future__ import annotations

import json
import os
import pathlib
import sys

import boto3
import pytest
from botocore.exceptions import ClientError

os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from identity_authority import AuthorityError
import identity_enrollment
import security_audit
from identity_enrollment import enroll_owner


class FakeTable:
    def __init__(self, *keys):
        self.keys = keys
        self.items = {}

    def item_key(self, item):
        values = tuple(item[key] for key in self.keys)
        return values[0] if len(values) == 1 else values

    def get_item(self, *, Key, ConsistentRead=False):
        assert ConsistentRead is True
        item = self.items.get(self.item_key(Key))
        return {"Item": dict(item)} if item else {}


class FakeTransactionClient:
    def __init__(self, owner):
        self.owner = owner
        self.fail = False
        self.collision_hook = None

    def transact_write_items(self, *, TransactItems):
        if self.fail:
            raise ClientError({"Error": {"Code": "InternalServerError"}}, "TransactWriteItems")
        if self.collision_hook:
            hook, self.collision_hook = self.collision_hook, None
            hook()
            raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
        pending = []
        for operation in TransactItems:
            if "Put" in operation:
                put = operation["Put"]
                item = put["Item"]
                table = self.owner.tables[put["TableName"]]
                item_key = table.item_key(item)
                if item_key in table.items:
                    raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
                pending.append(("put", table, item_key, item))
                continue
            update = operation["Update"]
            table = self.owner.tables[update["TableName"]]
            item_key = table.item_key(update["Key"])
            item = table.items.get(item_key)
            if not item or str(item.get("profile_id") or "").strip():
                raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
            values = update["ExpressionAttributeValues"]
            repaired = {
                **item,
                "profile_id": values[":profile_id"],
                "updated_at": values[":updated_at"],
                "updated_at_epoch": values[":updated_at_epoch"],
                "migration_provenance": values[":provenance"],
            }
            pending.append(("update", table, item_key, repaired))
        for _kind, table, item_key, item in pending:
            table.items[item_key] = item


class FakeDynamo:
    def __init__(self):
        self.tables = {
            "accounts": FakeTable("account_id"), "auth-identities": FakeTable("auth_identity_key"),
            "principals": FakeTable("principal_id"), "memberships": FakeTable("principal_id"),
            "household-memberships": FakeTable("household_id", "membership_id"),
            "households": FakeTable("household_id"), "profiles": FakeTable("profile_id"),
            "audit": FakeTable("event_id"),
        }
        self.meta = type("Meta", (), {})()
        self.meta.client = FakeTransactionClient(self)

    def Table(self, name):
        return self.tables[name]


@pytest.fixture(autouse=True)
def enrollment_environment(monkeypatch):
    for key, value in {
        "ACCOUNTS_TABLE": "accounts", "AUTH_IDENTITIES_TABLE": "auth-identities",
        "PRINCIPALS_TABLE": "principals", "IDENTITY_MEMBERSHIPS_TABLE": "memberships",
        "HOUSEHOLD_MEMBERSHIPS_TABLE": "household-memberships",
        "IDENTITY_HOUSEHOLDS_TABLE": "households", "IDENTITY_PROFILES_TABLE": "profiles",
        "SECURITY_AUDIT_TABLE": "audit", "EXPECTED_COGNITO_ISSUER": "https://issuer.example/pool",
        "EXPECTED_ENROLLMENT_CLIENT_ID": "enrollment-client", "KAEVO_ENV": "test",
        "EXPECTED_NATIVE_CLIENT_ID": "native-client",
        "AUDIT_REFERENCE_SECRET_ARN": "test-audit-secret",
    }.items():
        monkeypatch.setenv(key, value)
    security_audit.clear_audit_key_cache()
    security_audit._secret_cache["test-audit-secret"] = b"T" * 64


def event(
    subject="user-1", *, client_id="enrollment-client", token_use="access",
    now=1_000, body=None, email=None, email_verified=False,
):
    claims = {
        "sub": subject, "iss": "https://issuer.example/pool", "client_id": client_id,
        "token_use": token_use, "iat": str(now), "exp": str(now + 300),
        "auth_time": str(now),
    }
    if email is not None:
        claims["email"] = email
        claims["email_verified"] = "true" if email_verified else "false"
    return {
        "requestContext": {"authorizer": {"jwt": {"claims": claims}}},
        "body": json.dumps(body or {}),
    }


def test_owner_enrollment_generates_authority_server_side_and_is_idempotent():
    dynamo = FakeDynamo()
    first = enroll_owner(event(body={
        "account_id": "attacker-account", "household_id": "attacker-household",
        "profile_id": "attacker-profile", "role": "support", "authz_version": 999,
    }), dynamodb=dynamo, now=1_000)
    assert first["statusCode"] == 201
    principal = dynamo.tables["principals"].items["user-1"]
    assert principal["account_id"].startswith("acct_") and principal["account_id"] != "attacker-account"
    assert principal["role"] == "owner" and principal["authz_version"] == 1
    profile = next(iter(dynamo.tables["profiles"].items.values()))
    assert profile["display_name"] == "My Profile"
    assert profile["profile_type"] == "adult"
    account = dynamo.tables["accounts"].items[principal["account_id"]]
    assert account["entity_type"] == "Account" and account["status"] == "active"
    auth_identity = next(iter(dynamo.tables["auth-identities"].items.values()))
    assert auth_identity["account_id"] == principal["account_id"]
    assert auth_identity["provider"] == "cognito"
    normalized = list(dynamo.tables["household-memberships"].items.values())
    assert len(normalized) == 3
    assert {item["entity_type"] for item in normalized} == {
        "HouseholdMembership",
        "HouseholdMembershipAccountGuard",
        "HouseholdMembershipOwnerGuard",
    }
    membership_record = next(
        item for item in normalized if item["entity_type"] == "HouseholdMembership"
    )
    assert membership_record["profile_id"] == next(iter(dynamo.tables["profiles"].items))
    assert membership_record["migration_provenance"] == "owner-enrollment-v1"
    assert len(dynamo.tables["audit"].items) == 1

    second = enroll_owner(event(), dynamodb=dynamo, now=1_001)
    assert second["statusCode"] == 200
    assert json.loads(second["body"])["state"] == "already_enrolled"
    assert len(dynamo.tables["households"].items) == 1
    assert len(dynamo.tables["accounts"].items) == 1
    assert len(dynamo.tables["auth-identities"].items) == 1
    assert len(dynamo.tables["household-memberships"].items) == 3


def test_owner_enrollment_persists_only_a_verified_cognito_email():
    dynamo = FakeDynamo()

    result = enroll_owner(
        event(email="Owner@Example.com", email_verified=True),
        dynamodb=dynamo,
        now=1_000,
    )

    assert result["statusCode"] == 201
    auth_identity = next(iter(dynamo.tables["auth-identities"].items.values()))
    assert auth_identity["normalized_email"] == "owner@example.com"
    assert auth_identity["email_verified"] is True


def test_owner_enrollment_does_not_persist_an_unverified_email():
    dynamo = FakeDynamo()

    result = enroll_owner(
        event(email="unverified@example.com", email_verified=False),
        dynamodb=dynamo,
        now=1_000,
    )

    assert result["statusCode"] == 201
    auth_identity = next(iter(dynamo.tables["auth-identities"].items.values()))
    assert "normalized_email" not in auth_identity
    assert auth_identity["email_verified"] is False


def test_existing_legacy_owner_replay_repairs_only_missing_foundation_records():
    dynamo = FakeDynamo()
    first = enroll_owner(event(), dynamodb=dynamo, now=1_000)
    assert first["statusCode"] == 201
    principal_before = dict(dynamo.tables["principals"].items["user-1"])
    membership_before = dict(dynamo.tables["memberships"].items["user-1"])
    household_before = next(iter(dynamo.tables["households"].items.values())).copy()
    profile_before = next(iter(dynamo.tables["profiles"].items.values())).copy()

    dynamo.tables["accounts"].items.clear()
    dynamo.tables["auth-identities"].items.clear()
    dynamo.tables["household-memberships"].items.clear()

    replay = enroll_owner(event(), dynamodb=dynamo, now=1_001)
    assert replay["statusCode"] == 200
    assert json.loads(replay["body"])["state"] == "already_enrolled"
    assert len(dynamo.tables["accounts"].items) == 1
    assert len(dynamo.tables["auth-identities"].items) == 1
    assert len(dynamo.tables["household-memberships"].items) == 3
    assert dynamo.tables["principals"].items["user-1"] == principal_before
    assert dynamo.tables["memberships"].items["user-1"] == membership_before
    assert next(iter(dynamo.tables["households"].items.values())) == household_before
    assert next(iter(dynamo.tables["profiles"].items.values())) == profile_before


def test_existing_normalized_owner_replay_repairs_missing_exact_profile_pointer():
    dynamo = FakeDynamo()
    first = enroll_owner(event(), dynamodb=dynamo, now=1_000)
    assert first["statusCode"] == 201

    membership = next(
        item for item in dynamo.tables["household-memberships"].items.values()
        if item["entity_type"] == "HouseholdMembership"
    )
    expected_profile_id = membership.pop("profile_id")
    membership["migration_provenance"] = "legacy-authority-graph-v1"

    replay = enroll_owner(event(), dynamodb=dynamo, now=1_001)

    assert replay["statusCode"] == 200
    assert json.loads(replay["body"])["state"] == "already_enrolled"
    repaired = next(
        item for item in dynamo.tables["household-memberships"].items.values()
        if item["entity_type"] == "HouseholdMembership"
    )
    assert repaired["profile_id"] == expected_profile_id
    assert repaired["migration_provenance"] == "owner-enrollment-repair-v1"
    assert len(dynamo.tables["household-memberships"].items) == 3


@pytest.mark.parametrize("client_id,token_use", [("main-client", "access"), ("enrollment-client", "id")])
def test_main_client_and_id_tokens_cannot_bootstrap(client_id, token_use):
    with pytest.raises(AuthorityError):
        enroll_owner(event(client_id=client_id, token_use=token_use), dynamodb=FakeDynamo(), now=1_000)


def test_different_subjects_get_distinct_authority_graphs():
    dynamo = FakeDynamo()
    enroll_owner(event("user-1"), dynamodb=dynamo, now=1_000)
    enroll_owner(event("user-2"), dynamodb=dynamo, now=1_001)
    first = dynamo.tables["principals"].items["user-1"]
    second = dynamo.tables["principals"].items["user-2"]
    assert first["account_id"] != second["account_id"]
    assert first["household_id"] != second["household_id"]


def test_verified_native_client_can_bootstrap_then_replay_idempotently():
    dynamo = FakeDynamo()
    first = enroll_owner(event(client_id="native-client"), dynamodb=dynamo, now=1_000)
    second = enroll_owner(event(client_id="native-client"), dynamodb=dynamo, now=1_001)
    assert first["statusCode"] == 201
    assert json.loads(first["body"])["state"] == "enrolled"
    assert second["statusCode"] == 200
    assert json.loads(second["body"])["state"] == "already_enrolled"


def test_transaction_failure_leaves_no_partial_identity_graph():
    dynamo = FakeDynamo()
    dynamo.meta.client.fail = True
    with pytest.raises(AuthorityError, match="enrollment_failed"):
        enroll_owner(event(), dynamodb=dynamo, now=1_000)
    assert all(not table.items for table in dynamo.tables.values())


def test_concurrent_enrollment_converges_on_one_authoritative_principal():
    dynamo = FakeDynamo()
    dynamo.meta.client.collision_hook = lambda: enroll_owner(event(), dynamodb=dynamo, now=1_000)
    result = enroll_owner(event(), dynamodb=dynamo, now=1_000)
    assert result["statusCode"] == 200
    assert json.loads(result["body"])["state"] == "already_enrolled"
    assert len(dynamo.tables["principals"].items) == 1
    assert len(dynamo.tables["households"].items) == 1
    assert len(dynamo.tables["profiles"].items) == 1


def test_owner_enrollment_uses_one_resource_client_serialization_layer():
    resource = boto3.resource(
        "dynamodb",
        region_name="us-west-2",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )
    dynamo = FakeDynamo()
    dynamo.meta.client = resource.meta.client
    captured = {}

    class WireRequestCaptured(Exception):
        pass

    def capture_wire_request(request, **_kwargs):
        captured.update(json.loads(request.body))
        raise WireRequestCaptured

    resource.meta.client.meta.events.register(
        "before-send.dynamodb.TransactWriteItems",
        capture_wire_request,
    )
    with pytest.raises(WireRequestCaptured):
        enroll_owner(event(), dynamodb=dynamo, now=1_000)

    operations = captured["TransactItems"]
    assert len(operations) == 10
    account = operations[0]["Put"]["Item"]
    auth_identity = operations[1]["Put"]["Item"]
    principal = operations[2]["Put"]["Item"]
    assert account["account_id"] == principal["account_id"]
    assert auth_identity["account_id"] == principal["account_id"]
    assert "provider_subject" not in auth_identity
    assert principal["principal_id"] == {"S": "user-1"}
    assert set(principal["account_id"]) == {"S"}
    assert set(principal["household_id"]) == {"S"}
    assert principal["authz_version"] == {"N": "1"}
    assert principal["profile_ids"]["L"][0].keys() == {"S"}
    assert principal["revoked"] == {"BOOL": False}

    for operation in operations:
        for value in operation["Put"]["Item"].values():
            assert not (set(value) == {"M"} and set(value["M"]) == {"S"})


def test_enrollment_failure_log_does_not_expose_identity_or_token(caplog):
    canary_subject = "synthetic-canary-subject-never-log"
    canary_token = "synthetic-canary-token-never-log"
    request = event(canary_subject, client_id="unauthorized-client")
    request["headers"] = {"authorization": f"Bearer {canary_token}"}

    response = identity_enrollment.lambda_handler(request, None)

    assert response["statusCode"] == 401
    assert json.loads(response["body"]) == {"state": "not_authorized"}
    combined = "\n".join(record.getMessage() for record in caplog.records)
    assert canary_subject not in combined
    assert canary_token not in combined
    assert "Bearer" not in combined
