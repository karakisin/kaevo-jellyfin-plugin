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
from identity_enrollment import enroll_owner


class FakeTable:
    def __init__(self, key):
        self.key = key
        self.items = {}

    def get_item(self, *, Key, ConsistentRead=False):
        assert ConsistentRead is True
        item = self.items.get(Key[self.key])
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
            put = operation["Put"]
            item = put["Item"]
            table = self.owner.tables[put["TableName"]]
            if item[table.key] in table.items:
                raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
            pending.append((table, item))
        for table, item in pending:
            table.items[item[table.key]] = item


class FakeDynamo:
    def __init__(self):
        self.tables = {
            "principals": FakeTable("principal_id"), "memberships": FakeTable("principal_id"),
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
        "PRINCIPALS_TABLE": "principals", "IDENTITY_MEMBERSHIPS_TABLE": "memberships",
        "IDENTITY_HOUSEHOLDS_TABLE": "households", "IDENTITY_PROFILES_TABLE": "profiles",
        "SECURITY_AUDIT_TABLE": "audit", "EXPECTED_COGNITO_ISSUER": "https://issuer.example/pool",
        "EXPECTED_ENROLLMENT_CLIENT_ID": "enrollment-client",
    }.items():
        monkeypatch.setenv(key, value)


def event(subject="user-1", *, client_id="enrollment-client", token_use="access", now=1_000, body=None):
    return {
        "requestContext": {"authorizer": {"jwt": {"claims": {
            "sub": subject, "iss": "https://issuer.example/pool", "client_id": client_id,
            "token_use": token_use, "iat": str(now), "exp": str(now + 300), "auth_time": str(now),
        }}}},
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
    assert len(dynamo.tables["audit"].items) == 1

    second = enroll_owner(event(), dynamodb=dynamo, now=1_001)
    assert second["statusCode"] == 200
    assert json.loads(second["body"])["state"] == "already_enrolled"
    assert len(dynamo.tables["households"].items) == 1


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
    assert len(operations) == 5
    principal = operations[0]["Put"]["Item"]
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
