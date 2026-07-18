from __future__ import annotations

import json
import os
import pathlib
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import boto3
import pytest

os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

import identity_enrollment
import security_audit
from identity_enrollment import enroll_owner


ENDPOINT = os.environ.get("KAEVO_DYNAMODB_LOCAL_ENDPOINT")
pytestmark = pytest.mark.skipif(not ENDPOINT, reason="DynamoDB Local endpoint not configured")


def resource():
    return boto3.resource(
        "dynamodb",
        endpoint_url=ENDPOINT,
        region_name="us-west-2",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


def client():
    return boto3.client(
        "dynamodb",
        endpoint_url=ENDPOINT,
        region_name="us-west-2",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


def event(subject="integration-owner", *, client_id="enrollment-client", token_use="access", now=1_000):
    return {
        "requestContext": {"authorizer": {"jwt": {"claims": {
            "sub": subject,
            "iss": "https://issuer.example/pool",
            "client_id": client_id,
            "token_use": token_use,
            "iat": str(now),
            "exp": str(now + 300),
            "auth_time": str(now),
        }}}},
        "body": "{}",
    }


@pytest.fixture
def local_tables(monkeypatch):
    suffix = uuid.uuid4().hex[:10]
    table_names = {
        "PRINCIPALS_TABLE": (f"ksec011a-principals-{suffix}", "principal_id"),
        "IDENTITY_MEMBERSHIPS_TABLE": (f"ksec011a-memberships-{suffix}", "principal_id"),
        "IDENTITY_HOUSEHOLDS_TABLE": (f"ksec011a-households-{suffix}", "household_id"),
        "IDENTITY_PROFILES_TABLE": (f"ksec011a-profiles-{suffix}", "profile_id"),
        "SECURITY_AUDIT_TABLE": (f"ksec011a-audit-{suffix}", "event_id"),
    }
    dynamo = resource()
    for environment_name, (table_name, key_name) in table_names.items():
        monkeypatch.setenv(environment_name, table_name)
        dynamo.create_table(
            TableName=table_name,
            BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": key_name, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": key_name, "AttributeType": "S"}],
        ).wait_until_exists()
    monkeypatch.setenv("EXPECTED_COGNITO_ISSUER", "https://issuer.example/pool")
    monkeypatch.setenv("EXPECTED_ENROLLMENT_CLIENT_ID", "enrollment-client")
    monkeypatch.setenv("KAEVO_ENV", "test")
    monkeypatch.setenv("AUDIT_REFERENCE_SECRET_ARN", "test-audit-secret")
    security_audit.clear_audit_key_cache()
    security_audit._secret_cache["test-audit-secret"] = b"T" * 64
    try:
        yield dynamo, table_names
    finally:
        for table_name, _key_name in table_names.values():
            dynamo.Table(table_name).delete()


def native_items(dynamo, table_names):
    return {
        environment_name: dynamo.Table(table_name).scan(ConsistentRead=True).get("Items", [])
        for environment_name, (table_name, _key_name) in table_names.items()
    }


def assert_complete_graph(items, subject):
    assert all(len(records) == 1 for records in items.values())
    principal = items["PRINCIPALS_TABLE"][0]
    membership = items["IDENTITY_MEMBERSHIPS_TABLE"][0]
    household = items["IDENTITY_HOUSEHOLDS_TABLE"][0]
    profile = items["IDENTITY_PROFILES_TABLE"][0]
    audit = items["SECURITY_AUDIT_TABLE"][0]
    assert principal["principal_id"] == membership["principal_id"] == subject
    assert principal["account_id"] == membership["account_id"] == household["account_id"] == profile["account_id"]
    assert principal["household_id"] == membership["household_id"] == household["household_id"] == profile["household_id"]
    assert principal["profile_ids"] == [membership["profile_id"]]
    assert membership["profile_id"] == profile["profile_id"]
    assert audit["household_id"] == audit["scope_ref"]
    assert audit["household_id"] != household["household_id"]
    assert audit["actor_ref"].startswith("apr1_")
    assert subject not in json.dumps(audit)


def test_real_transaction_commits_five_typed_records_and_replays(local_tables):
    dynamo, table_names = local_tables
    first = enroll_owner(event(), dynamodb=dynamo, now=1_000)
    assert first["statusCode"] == 201
    assert json.loads(first["body"])["state"] == "enrolled"

    items = native_items(dynamo, table_names)
    assert_complete_graph(items, "integration-owner")

    raw = client()
    key_names = {
        environment_name: key_name
        for environment_name, (_table_name, key_name) in table_names.items()
    }
    for environment_name, (table_name, _key_name) in table_names.items():
        wire_items = raw.scan(TableName=table_name, ConsistentRead=True)["Items"]
        assert len(wire_items) == 1
        assert set(wire_items[0][key_names[environment_name]]) == {"S"}
    principal = raw.scan(TableName=table_names["PRINCIPALS_TABLE"][0])["Items"][0]
    assert principal["authz_version"] == {"N": "1"}
    assert principal["profile_ids"]["L"][0].keys() == {"S"}
    assert principal["revoked"] == {"BOOL": False}

    before = {name: len(records) for name, records in items.items()}
    replay = enroll_owner(event(), dynamodb=dynamo, now=1_001)
    assert replay["statusCode"] == 200
    assert json.loads(replay["body"])["state"] == "already_enrolled"
    after = native_items(dynamo, table_names)
    assert {name: len(records) for name, records in after.items()} == before


def test_real_transaction_concurrency_converges_on_one_graph(local_tables):
    _dynamo, table_names = local_tables
    barrier = threading.Barrier(2)

    def attempt():
        barrier.wait()
        return enroll_owner(event("concurrent-owner"), dynamodb=resource(), now=1_000)

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _index: attempt(), range(2)))
    assert sorted(response["statusCode"] for response in responses) == [200, 201]
    assert sorted(json.loads(response["body"])["state"] for response in responses) == [
        "already_enrolled", "enrolled",
    ]
    assert_complete_graph(native_items(resource(), table_names), "concurrent-owner")


def test_real_transaction_condition_conflict_is_safe_and_atomic(local_tables, monkeypatch):
    dynamo, table_names = local_tables
    household_table = dynamo.Table(table_names["IDENTITY_HOUSEHOLDS_TABLE"][0])
    household_table.put_item(Item={"household_id": "hh_conflict", "state": "sentinel"})

    generated = {
        "acct": "acct_conflict",
        "hh": "hh_conflict",
        "profile": "profile_conflict",
        "event": "event_conflict",
    }
    monkeypatch.setattr(identity_enrollment, "_identifier", lambda prefix: generated[prefix])
    monkeypatch.setattr(identity_enrollment.boto3, "resource", lambda service: dynamo)

    response = identity_enrollment.lambda_handler(event("conflict-owner"), None)
    assert response["statusCode"] == 401
    assert json.loads(response["body"]) == {"state": "not_authorized"}
    assert "DynamoDB" not in response["body"]
    assert "TransactionCanceled" not in response["body"]

    items = native_items(dynamo, table_names)
    assert items["PRINCIPALS_TABLE"] == []
    assert items["IDENTITY_MEMBERSHIPS_TABLE"] == []
    assert items["IDENTITY_PROFILES_TABLE"] == []
    assert items["SECURITY_AUDIT_TABLE"] == []
    assert items["IDENTITY_HOUSEHOLDS_TABLE"] == [
        {"household_id": "hh_conflict", "state": "sentinel"},
    ]
