import json

import pytest
from botocore.exceptions import ClientError

import account_lifecycle_v2_enrollment as enrollment
import security_audit
from account_foundation import build_auth_identity_record
from account_lifecycle_v2_aws import CognitoSubjectDeletion, DynamoKaevoGraphDeletion


NOW = 1_800_000_000


class Table:
    def __init__(self, *keys):
        self.keys = keys
        self.items = {}

    def item_key(self, item):
        result = tuple(item[key] for key in self.keys)
        return result[0] if len(result) == 1 else result

    def get_item(self, *, Key, ConsistentRead=False):
        assert ConsistentRead is True
        item = self.items.get(self.item_key(Key))
        return {"Item": dict(item)} if item else {}

    def query(self, *, KeyConditionExpression, ConsistentRead=False):
        assert ConsistentRead is True
        return {"Items": [dict(item) for item in self.items.values()]}

    def delete_item(self, *, Key):
        self.items.pop(self.item_key(Key), None)


class TransactionClient:
    def __init__(self, owner):
        self.owner = owner
        self.fail = False

    def transact_write_items(self, *, TransactItems):
        if self.fail:
            raise ClientError({"Error": {"Code": "InternalServerError"}}, "TransactWriteItems")
        pending = []
        for action in TransactItems:
            put = action["Put"]
            table = self.owner.tables[put["TableName"]]
            key = table.item_key(put["Item"])
            if key in table.items:
                raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
            pending.append((table, key, dict(put["Item"])))
        for table, key, item in pending:
            table.items[key] = item


class Dynamo:
    def __init__(self):
        self.tables = {
            "accounts": Table("account_id"),
            "auth": Table("auth_identity_key"),
            "principals": Table("principal_id"),
            "identity-memberships": Table("principal_id"),
            "household-memberships": Table("household_id", "membership_id"),
            "identity-households": Table("household_id"),
            "identity-profiles": Table("profile_id"),
            "profiles": Table("profile_id"),
            "bindings": Table("account_id", "profile_id"),
            "lifecycle": Table("account_id", "record_key"),
            "audit": Table("event_id"),
        }
        self.meta = type("Meta", (), {})()
        self.meta.client = TransactionClient(self)

    def Table(self, name):
        return self.tables[name]


class Cognito:
    def admin_get_user(self, **_kwargs):
        raise AssertionError("verified token email should not require Cognito lookup")


@pytest.fixture(autouse=True)
def environment(monkeypatch):
    values = {
        "ACCOUNTS_TABLE": "accounts",
        "AUTH_IDENTITIES_TABLE": "auth",
        "PRINCIPALS_TABLE": "principals",
        "IDENTITY_MEMBERSHIPS_TABLE": "identity-memberships",
        "HOUSEHOLD_MEMBERSHIPS_TABLE": "household-memberships",
        "IDENTITY_HOUSEHOLDS_TABLE": "identity-households",
        "IDENTITY_PROFILES_TABLE": "identity-profiles",
        "PROFILES_TABLE": "profiles",
        "PROFILE_BINDINGS_TABLE": "bindings",
        "ACCOUNT_LIFECYCLE_V2_TABLE": "lifecycle",
        "SECURITY_AUDIT_TABLE": "audit",
        "AUDIT_REFERENCE_SECRET_ARN": "test-audit-key",
        "EXPECTED_COGNITO_ISSUER": "https://issuer.example/pool",
        "EXPECTED_ENROLLMENT_CLIENT_ID": "enrollment-client",
        "EXPECTED_NATIVE_CLIENT_ID": "native-client",
        "COGNITO_USER_POOL_ID": "pool",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    security_audit.clear_audit_key_cache()
    security_audit._secret_cache["test-audit-key"] = b"V" * 64


def event(body=None, *, subject="subject-123"):
    return {
        "requestContext": {
            "requestId": "request-123",
            "authorizer": {"jwt": {"claims": {
                "sub": subject,
                "iss": "https://issuer.example/pool",
                "client_id": "native-client",
                "token_use": "access",
                "iat": NOW - 10,
                "exp": NOW + 300,
                "auth_time": NOW - 20,
                "email": "new.owner@example.com",
                "email_verified": "true",
            }}},
        },
        "body": json.dumps(body or {}),
    }


def decoded(response):
    return json.loads(response["body"])


def test_fresh_enrollment_atomically_creates_ready_graph_and_registry(monkeypatch):
    dynamo = Dynamo()
    identifiers = iter([
        "acct_0123456789abcdef01234567",
        "hh_0123456789abcdef0123456789",
        "profile_0123456789abcdef012345",
    ])
    monkeypatch.setattr(enrollment, "_identifier", lambda _prefix: next(identifiers))

    response = enrollment.enroll_owner_v2(
        event({"account_id": "attacker", "profile_id": "attacker"}),
        dynamodb=dynamo,
        cognito=Cognito(),
        now=NOW,
    )

    body = decoded(response)
    assert response["statusCode"] == 201
    assert body == {
        "state": "ready",
        "created": True,
        "account_id": "acct_0123456789abcdef01234567",
        "household_id": "hh_0123456789abcdef0123456789",
        "profile_id": "profile_0123456789abcdef012345",
        "lifecycle_revision": 1,
    }
    assert len(dynamo.tables["lifecycle"].items) == 13
    root = dynamo.tables["lifecycle"].items[(body["account_id"], "root")]
    assert root["schema_version"] == 2 and root["state"] == "active"
    assert root["account_role"] == "owner"
    assert root["owner_deletion_state"] == "sole_member"
    resources = [
        item for item in dynamo.tables["lifecycle"].items.values()
        if item.get("record_type") == "account_lifecycle_resource"
    ]
    assert {item["resource_type"] for item in resources} == {
        "account", "auth_identity", "cognito_subject", "principal",
        "identity_membership", "household", "household_membership",
        "household_membership_guard", "identity_profile", "cloud_profile",
        "profile_binding",
    }
    assert all("email" not in item and "display_name" not in item for item in resources)
    assert set(dynamo.tables["identity-profiles"].items) == set(dynamo.tables["profiles"].items)
    binding = next(iter(dynamo.tables["bindings"].items.values()))
    assert binding["migration_provenance"] == "account-lifecycle-v2"
    assert len(dynamo.tables["household-memberships"].items) == 3


def test_repeat_enrollment_returns_same_ready_receipt_without_new_graph(monkeypatch):
    dynamo = Dynamo()
    identifiers = iter([
        "acct_0123456789abcdef01234567",
        "hh_0123456789abcdef0123456789",
        "profile_0123456789abcdef012345",
    ])
    monkeypatch.setattr(enrollment, "_identifier", lambda _prefix: next(identifiers))
    first = enrollment.enroll_owner_v2(event(), dynamodb=dynamo, cognito=Cognito(), now=NOW)
    second = enrollment.enroll_owner_v2(event(), dynamodb=dynamo, cognito=Cognito(), now=NOW + 1)

    assert first["statusCode"] == 201
    assert second["statusCode"] == 200
    assert decoded(second)["created"] is False
    assert decoded(second)["account_id"] == decoded(first)["account_id"]
    assert len(dynamo.tables["accounts"].items) == 1


def test_repeat_enrollment_returns_subject_profile_not_an_arbitrary_cloud_profile(monkeypatch):
    dynamo = Dynamo()
    identifiers = iter([
        "acct_0123456789abcdef01234567",
        "hh_0123456789abcdef0123456789",
        "profile_owner0123456789abcdef",
    ])
    monkeypatch.setattr(enrollment, "_identifier", lambda _prefix: next(identifiers))
    first = enrollment.enroll_owner_v2(
        event(), dynamodb=dynamo, cognito=Cognito(), now=NOW,
    )
    first_receipt = decoded(first)
    extra = enrollment._resource(
        first_receipt["account_id"],
        "cloud_profile",
        "profile_household_member_extra",
        now=NOW + 1,
    )
    dynamo.tables["lifecycle"].items[
        (first_receipt["account_id"], extra["record_key"])
    ] = extra

    repeated = enrollment.enroll_owner_v2(
        event(), dynamodb=dynamo, cognito=Cognito(), now=NOW + 2,
    )

    assert repeated["statusCode"] == 200
    assert decoded(repeated)["profile_id"] == first_receipt["profile_id"]


def test_existing_v1_auth_identity_is_not_guessed_into_v2_registry():
    dynamo = Dynamo()
    auth = build_auth_identity_record(
        account_id="acct_legacy0123456789abcdef",
        provider="cognito",
        provider_subject="subject-123",
        now_iso="2026-08-21T00:00:00Z",
        now_epoch=NOW,
        email="legacy@example.com",
        email_verified=True,
    )
    dynamo.tables["auth"].items[auth["auth_identity_key"]] = auth

    with pytest.raises(
        enrollment.LifecycleV2EnrollmentError,
        match="legacy_account_requires_separate_migration",
    ):
        enrollment.enroll_owner_v2(event(), dynamodb=dynamo, cognito=Cognito(), now=NOW)


def test_failed_transaction_leaves_no_partial_account(monkeypatch):
    dynamo = Dynamo()
    dynamo.meta.client.fail = True
    identifiers = iter([
        "acct_0123456789abcdef01234567",
        "hh_0123456789abcdef0123456789",
        "profile_0123456789abcdef012345",
    ])
    monkeypatch.setattr(enrollment, "_identifier", lambda _prefix: next(identifiers))

    with pytest.raises(enrollment.LifecycleV2EnrollmentError, match="enrollment_transaction_failed"):
        enrollment.enroll_owner_v2(event(), dynamodb=dynamo, cognito=Cognito(), now=NOW)

    assert all(not table.items for table in dynamo.tables.values())


def test_terminal_deletion_releases_email_for_new_immutable_account(monkeypatch):
    """One email can enroll again only after exact subject/email/graph absence."""
    dynamo = Dynamo()
    identifiers = iter([
        "acct_old0123456789abcdef012345",
        "hh_old0123456789abcdef01234567",
        "profile_old0123456789abcdef012",
        "acct_new0123456789abcdef012345",
        "hh_new0123456789abcdef01234567",
        "profile_new0123456789abcdef012",
    ])
    monkeypatch.setattr(enrollment, "_identifier", lambda _prefix: next(identifiers))
    old_subject = "subject-old"
    new_subject = "subject-new"
    first = enrollment.enroll_owner_v2(
        event(subject=old_subject), dynamodb=dynamo, cognito=Cognito(), now=NOW,
    )
    first_receipt = decoded(first)
    resources = [
        dict(item) for item in dynamo.tables["lifecycle"].items.values()
        if item.get("record_type") == "account_lifecycle_resource"
    ]
    auth_resource = next(
        item for item in resources if item.get("resource_type") == "auth_identity"
    )

    class DeletingCognito:
        def __init__(self):
            self.users = [{
                "Username": "native-old",
                "Attributes": [
                    {"Name": "sub", "Value": old_subject},
                    {"Name": "email", "Value": "new.owner@example.com"},
                    {"Name": "email_verified", "Value": "true"},
                ],
            }]

        def list_users(self, *, Filter, **_kwargs):
            field, _, quoted = Filter.partition(" = ")
            expected = quoted.strip('"')
            matches = []
            for user in self.users:
                attributes = {
                    item["Name"]: item["Value"] for item in user["Attributes"]
                }
                if attributes.get(field) == expected:
                    matches.append(dict(user))
            return {"Users": matches}

        def admin_delete_user(self, *, Username, **_kwargs):
            self.users = [
                user for user in self.users if user.get("Username") != Username
            ]

    cognito = DeletingCognito()
    cognito_deletion = CognitoSubjectDeletion(
        cognito,
        user_pool_id="pool",
        auth_identities_table=dynamo.tables["auth"],
    )
    cognito_deletion.delete_identity(
        account_id=first_receipt["account_id"],
        subject=old_subject,
        auth_identity_key=str(auth_resource["resource_id"]),
    )
    assert cognito_deletion.identity_and_email_absent(
        account_id=first_receipt["account_id"],
        subject=old_subject,
        auth_identity_key=str(auth_resource["resource_id"]),
    ) is True

    graph = DynamoKaevoGraphDeletion(
        lifecycle_table=dynamo.tables["lifecycle"],
        tables={
            "accounts": dynamo.tables["accounts"],
            "auth_identities": dynamo.tables["auth"],
            "principals": dynamo.tables["principals"],
            "identity_memberships": dynamo.tables["identity-memberships"],
            "household_memberships": dynamo.tables["household-memberships"],
            "identity_households": dynamo.tables["identity-households"],
            "identity_profiles": dynamo.tables["identity-profiles"],
            "profiles": dynamo.tables["profiles"],
            "profile_bindings": dynamo.tables["bindings"],
        },
    )
    graph.delete_resources(
        account_id=first_receipt["account_id"],
        operation_id="ald2_enrollment_recreation_proof",
        resources=resources,
    )
    assert graph.resources_absent(
        account_id=first_receipt["account_id"],
        operation_id="ald2_enrollment_recreation_proof",
        resources=resources,
    ) is True

    second = enrollment.enroll_owner_v2(
        event(subject=new_subject), dynamodb=dynamo, cognito=Cognito(), now=NOW + 1,
    )
    second_receipt = decoded(second)
    assert second["statusCode"] == 201
    assert second_receipt["account_id"] != first_receipt["account_id"]
    assert second_receipt["household_id"] != first_receipt["household_id"]
    assert second_receipt["profile_id"] != first_receipt["profile_id"]
