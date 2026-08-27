import pytest

from account_foundation import provider_subject_key
from account_lifecycle_v2_aws import (
    CognitoSubjectDeletion,
    DynamoKaevoGraphDeletion,
    DynamoOperationJournal,
)
from account_lifecycle_v2_executor import LifecycleV2ExecutionError


ACCOUNT_ID = "acct_0123456789abcdef01234567"
OPERATION_ID = "ald2_0123456789abcdef0123456789abcdef"


class Table:
    def __init__(self, *keys):
        self.keys = keys
        self.items = {}
        self.deletions = []
        self.updates = []

    def key(self, item):
        values = tuple(item[key] for key in self.keys)
        return values[0] if len(values) == 1 else values

    def delete_item(self, *, Key):
        self.deletions.append(dict(Key))
        self.items.pop(self.key(Key), None)

    def get_item(self, *, Key, ConsistentRead=False):
        assert ConsistentRead is True
        item = self.items.get(self.key(Key))
        return {"Item": dict(item)} if item else {}

    def query(self, *, KeyConditionExpression, ConsistentRead=False, ExclusiveStartKey=None):
        assert ConsistentRead is True
        return {"Items": [dict(item) for item in self.items.values()]}

    def update_item(self, *, Key, ExpressionAttributeValues, **_kwargs):
        self.updates.append({
            "Key": dict(Key),
            "ExpressionAttributeValues": dict(ExpressionAttributeValues),
        })
        item = self.items.get(self.key(Key))
        if item is None:
            raise AssertionError("expected lifecycle root")
        if ":profile_ids" in ExpressionAttributeValues:
            item["cloud_seat_profile_ids"] = set(
                item.get("cloud_seat_profile_ids") or []
            ).difference(ExpressionAttributeValues[":profile_ids"])
            item["updated_at_epoch"] = ExpressionAttributeValues[":updated_at_epoch"]
            return
        item["owner_deletion_state"] = ExpressionAttributeValues[":next"]
        item["revision"] = int(item.get("revision") or 0) + 1


class SessionTable(Table):
    def query(self, *, IndexName, KeyConditionExpression, ExclusiveStartKey=None):
        assert IndexName == "family_id-created_at_epoch-index"
        # The adapter subsequently performs strongly consistent primary-key
        # reads, so returning this test family is sufficient to prove scope.
        return {"Items": [dict(item) for item in self.items.values()
                          if item.get("family_id") == "family-1"]}


class InvitationTable(Table):
    def query(
        self, *, IndexName, KeyConditionExpression, ConsistentRead=False,
        ExclusiveStartKey=None,
    ):
        assert IndexName == "household_id-index"
        assert ConsistentRead is False
        return {"Items": [dict(item) for item in self.items.values()]}


def resource(kind, identifier, attributes=None):
    return {
        "resource_key": f"resource#{kind}#{identifier}",
        "resource_type": kind,
        "resource_id": identifier,
        "attributes": dict(attributes or {}),
    }


def test_operation_retry_persists_exact_resume_phase():
    class JournalTable:
        def __init__(self):
            self.request = None

        def update_item(self, **kwargs):
            self.request = kwargs
            return {"Attributes": {
                "account_id": ACCOUNT_ID,
                "record_key": "operation#ald2_exact",
                "operation_id": "ald2_exact",
                "phase": "retry_required",
                "resume_phase": kwargs["ExpressionAttributeValues"][":resume"],
            }}

    table = JournalTable()
    journal = DynamoOperationJournal(table, clock=lambda: 1_800_000_000)

    result = journal.record_retry({
        "account_id": ACCOUNT_ID,
        "record_key": "operation#ald2_exact",
        "operation_id": "ald2_exact",
        "phase": "verifying_cognito_absence",
    }, reason="cognito_absence_unconfirmed")

    assert result["resume_phase"] == "verifying_cognito_absence"
    assert table.request["ExpressionAttributeValues"][":resume"] == (
        "verifying_cognito_absence"
    )


def test_graph_deletion_uses_only_frozen_exact_keys_and_proves_absence():
    lifecycle = Table("account_id", "record_key")
    tables = {
        "profile_bindings": Table("account_id", "profile_id"),
        "profiles": Table("profile_id"),
        "identity_profiles": Table("profile_id"),
        "household_memberships": Table("household_id", "membership_id"),
        "identity_memberships": Table("principal_id"),
        "principals": Table("principal_id"),
        "identity_households": Table("household_id"),
        "auth_identities": Table("auth_identity_key"),
        "accounts": Table("account_id"),
    }
    resources = [
        resource("account", ACCOUNT_ID),
        resource("auth_identity", "auth-key"),
        resource("cognito_subject", "subject-123"),
        resource("principal", "subject-123"),
        resource("identity_membership", "subject-123"),
        resource("household", "hh-1"),
        resource("household_membership", "membership-1", {
            "household_id": "hh-1", "profile_id": "profile-1",
        }),
        resource("household_membership_guard", "guard-1", {"household_id": "hh-1"}),
        resource("identity_profile", "profile-1"),
        resource("cloud_profile", "profile-1"),
        resource("profile_binding", "binding-1", {"profile_id": "profile-1"}),
    ]
    business_items = {
        "profile_bindings": {"account_id": ACCOUNT_ID, "profile_id": "profile-1"},
        "profiles": {"profile_id": "profile-1"},
        "identity_profiles": {"profile_id": "profile-1"},
        "household_memberships": {"household_id": "hh-1", "membership_id": "membership-1"},
        "identity_memberships": {"principal_id": "subject-123"},
        "principals": {"principal_id": "subject-123"},
        "identity_households": {
            "household_id": "hh-1", "cloud_seat_profile_ids": {"profile-1"},
        },
        "auth_identities": {"auth_identity_key": "auth-key"},
        "accounts": {"account_id": ACCOUNT_ID},
    }
    for name, item in business_items.items():
        tables[name].items[tables[name].key(item)] = dict(item)
    guard = {"household_id": "hh-1", "membership_id": "guard-1"}
    tables["household_memberships"].items[tables["household_memberships"].key(guard)] = guard
    lifecycle.items[(ACCOUNT_ID, "root")] = {"account_id": ACCOUNT_ID, "record_key": "root"}
    for item in resources:
        lifecycle.items[(ACCOUNT_ID, item["resource_key"])] = {
            "account_id": ACCOUNT_ID, "record_key": item["resource_key"],
        }
    lifecycle.items[(ACCOUNT_ID, f"operation#{OPERATION_ID}")] = {
        "account_id": ACCOUNT_ID,
        "record_key": f"operation#{OPERATION_ID}",
        "record_type": "account_lifecycle_operation",
        "operation_id": OPERATION_ID,
    }
    stale_operation_id = "ald2_stale0123456789abcdef0123456789ab"
    lifecycle.items[(ACCOUNT_ID, f"operation#{stale_operation_id}")] = {
        "account_id": ACCOUNT_ID,
        "record_key": f"operation#{stale_operation_id}",
        "record_type": "account_lifecycle_operation",
        "operation_id": stale_operation_id,
    }

    graph = DynamoKaevoGraphDeletion(lifecycle_table=lifecycle, tables=tables)
    graph.delete_resources(
        account_id=ACCOUNT_ID, operation_id=OPERATION_ID, resources=resources,
    )

    assert graph.resources_absent(
        account_id=ACCOUNT_ID, operation_id=OPERATION_ID, resources=resources,
    ) is True
    assert (ACCOUNT_ID, f"operation#{OPERATION_ID}") in lifecycle.items
    assert (ACCOUNT_ID, f"operation#{stale_operation_id}") not in lifecycle.items
    assert tables["profile_bindings"].deletions == [{
        "account_id": ACCOUNT_ID, "profile_id": "profile-1",
    }]
    assert tables["accounts"].deletions == [{"account_id": ACCOUNT_ID}]
    assert (ACCOUNT_ID, "root") not in lifecycle.items


def test_graph_deletion_removes_only_exact_member_invitation_rows():
    lifecycle = Table("account_id", "record_key")
    invitations = InvitationTable("code_hash")
    invitations.items = {
        "member-code": {
            "code_hash": "member-code",
            "household_id": "hh-1",
            "profile_id": "profile-1",
            "state": "consumed",
        },
        "other-code": {
            "code_hash": "other-code",
            "household_id": "hh-1",
            "profile_id": "profile-2",
            "state": "pending",
        },
    }
    resources = [
        resource("identity_profile", "profile-1", {
            "household_id": "hh-1",
        }),
    ]
    lifecycle.items[(ACCOUNT_ID, "root")] = {
        "account_id": ACCOUNT_ID, "record_key": "root",
    }
    lifecycle.items[(ACCOUNT_ID, resources[0]["resource_key"])] = {
        "account_id": ACCOUNT_ID,
        "record_key": resources[0]["resource_key"],
    }
    lifecycle.items[(ACCOUNT_ID, f"operation#{OPERATION_ID}")] = {
        "account_id": ACCOUNT_ID,
        "record_key": f"operation#{OPERATION_ID}",
        "record_type": "account_lifecycle_operation",
        "operation_id": OPERATION_ID,
    }
    graph = DynamoKaevoGraphDeletion(
        lifecycle_table=lifecycle,
        household_invitations_table=invitations,
        tables={"identity_profiles": Table("profile_id")},
    )

    graph.delete_resources(
        account_id=ACCOUNT_ID, operation_id=OPERATION_ID, resources=resources,
    )

    assert "member-code" not in invitations.items
    assert "other-code" in invitations.items
    assert graph.resources_absent(
        account_id=ACCOUNT_ID, operation_id=OPERATION_ID, resources=resources,
    ) is True


class Cognito:
    def __init__(self, users):
        self.users = list(users)
        self.deleted = []

    def list_users(self, **_kwargs):
        return {"Users": list(self.users)}

    def admin_delete_user(self, *, UserPoolId, Username):
        self.deleted.append((UserPoolId, Username))
        self.users = [user for user in self.users if user.get("Username") != Username]


class AuthIdentityTable:
    def __init__(self, *, subject="subject-123", email="owner@example.com"):
        self.key = provider_subject_key("cognito", subject)
        self.item = {
            "auth_identity_key": self.key,
            "entity_type": "AuthIdentity",
            "provider": "cognito",
            "provider_subject": subject,
            "account_id": ACCOUNT_ID,
            "status": "active",
            "normalized_email": email,
            "email_verified": True,
        }

    def get_item(self, *, Key, ConsistentRead=False):
        assert ConsistentRead is True
        return {"Item": dict(self.item)} if Key == {"auth_identity_key": self.key} else {}

    def update_item(self, *, ExpressionAttributeValues, **_kwargs):
        self.item["normalized_email"] = ExpressionAttributeValues[":email"]
        self.item["email_verified"] = ExpressionAttributeValues[":verified"]


def cognito_user(username="Google_opaque", *, subject="subject-123", email="owner@example.com"):
    return {
        "Username": username,
        "Attributes": [
            {"Name": "sub", "Value": subject},
            {"Name": "email", "Value": email},
            {"Name": "email_verified", "Value": "true"},
        ],
    }


def test_cognito_deletion_resolves_subject_then_verifies_absence():
    client = Cognito([cognito_user()])
    auth = AuthIdentityTable()
    deletion = CognitoSubjectDeletion(
        client, user_pool_id="pool", auth_identities_table=auth,
    )

    deletion.delete_identity(
        account_id=ACCOUNT_ID,
        subject="subject-123",
        auth_identity_key=auth.key,
    )

    assert client.deleted == [("pool", "Google_opaque")]
    assert deletion.identity_and_email_absent(
        account_id=ACCOUNT_ID,
        subject="subject-123",
        auth_identity_key=auth.key,
    ) is True


def test_cognito_deletion_rejects_ambiguous_subject_resolution():
    deletion = CognitoSubjectDeletion(
        Cognito([cognito_user("one"), cognito_user("two")]),
        user_pool_id="pool",
        auth_identities_table=AuthIdentityTable(),
    )

    with pytest.raises(LifecycleV2ExecutionError, match="cognito_subject_ambiguous"):
        deletion.delete_identity(
            account_id=ACCOUNT_ID,
            subject="subject-123",
            auth_identity_key=provider_subject_key("cognito", "subject-123"),
        )


def test_cognito_deletion_refuses_orphan_that_still_owns_the_same_email():
    exact = cognito_user("Google_exact")
    orphan = cognito_user(
        "Google_orphan", subject="different-subject", email="owner@example.com",
    )

    class FilteredCognito(Cognito):
        def list_users(self, *, Filter, **_kwargs):
            if Filter.startswith("sub ="):
                return {"Users": [exact]}
            return {"Users": [exact, orphan]}

    auth = AuthIdentityTable()
    deletion = CognitoSubjectDeletion(
        FilteredCognito([exact, orphan]),
        user_pool_id="pool",
        auth_identities_table=auth,
    )

    with pytest.raises(LifecycleV2ExecutionError, match="cognito_email_ambiguous"):
        deletion.delete_identity(
            account_id=ACCOUNT_ID,
            subject="subject-123",
            auth_identity_key=auth.key,
        )


def test_graph_deletion_removes_exact_session_family_and_installation():
    lifecycle = Table("account_id", "record_key")
    sessions = SessionTable("token_hash")
    sessions.items = {
        "access#one": {"token_hash": "access#one", "family_id": "family-1"},
        "refresh#one": {"token_hash": "refresh#one", "family_id": "family-1"},
        "access#other": {"token_hash": "access#other", "family_id": "family-other"},
    }
    installations = Table("installation_id")
    installations.items["installation-1"] = {"installation_id": "installation-1"}
    resources = [
        resource("app_session_access", "access#one"),
        resource("app_session_family", "family-1"),
        resource("installation", "installation-1"),
    ]
    lifecycle.items[(ACCOUNT_ID, "root")] = {
        "account_id": ACCOUNT_ID, "record_key": "root",
    }
    for item in resources:
        lifecycle.items[(ACCOUNT_ID, item["resource_key"])] = {
            "account_id": ACCOUNT_ID, "record_key": item["resource_key"],
        }
    graph = DynamoKaevoGraphDeletion(
        lifecycle_table=lifecycle,
        app_sessions_table=sessions,
        tables={"app_sessions": sessions, "installations": installations},
    )

    graph.delete_resources(
        account_id=ACCOUNT_ID, operation_id=OPERATION_ID, resources=resources,
    )

    assert graph.resources_absent(
        account_id=ACCOUNT_ID, operation_id=OPERATION_ID, resources=resources,
    ) is True
    assert "access#one" not in sessions.items
    assert "refresh#one" not in sessions.items
    assert "access#other" in sessions.items
    assert "installation-1" not in installations.items


def test_graph_deletion_strongly_deletes_exact_refresh_without_family_projection():
    lifecycle = Table("account_id", "record_key")
    sessions = SessionTable("token_hash")
    sessions.items = {
        "refresh#exact": {
            "token_hash": "refresh#exact",
            "record_type": "refresh",
            "account_id": ACCOUNT_ID,
            "family_id": "family-exact",
        },
    }
    refresh = resource("app_session_refresh", "refresh#exact")
    lifecycle.items[(ACCOUNT_ID, "root")] = {
        "account_id": ACCOUNT_ID, "record_key": "root",
    }
    lifecycle.items[(ACCOUNT_ID, refresh["resource_key"])] = {
        "account_id": ACCOUNT_ID, "record_key": refresh["resource_key"],
    }
    graph = DynamoKaevoGraphDeletion(
        lifecycle_table=lifecycle,
        app_sessions_table=sessions,
        tables={"app_sessions": sessions},
    )

    graph.delete_resources(
        account_id=ACCOUNT_ID, operation_id=OPERATION_ID, resources=[refresh],
    )

    assert graph.resources_absent(
        account_id=ACCOUNT_ID, operation_id=OPERATION_ID, resources=[refresh],
    ) is True
    assert sessions.deletions == [{"token_hash": "refresh#exact"}]


def test_graph_deletion_removes_exact_profile_mapping_primary_key():
    lifecycle = Table("account_id", "record_key")
    mappings = Table("installation_id", "local_profile_source_id")
    key = {
        "installation_id": "installation-exact",
        "local_profile_source_id": "local-profile-exact",
    }
    mappings.items[mappings.key(key)] = {**key, "account_id": ACCOUNT_ID}
    mapping = resource("profile_mapping", "mapping-exact", key)
    lifecycle.items[(ACCOUNT_ID, "root")] = {
        "account_id": ACCOUNT_ID, "record_key": "root",
    }
    lifecycle.items[(ACCOUNT_ID, mapping["resource_key"])] = {
        "account_id": ACCOUNT_ID, "record_key": mapping["resource_key"],
    }
    graph = DynamoKaevoGraphDeletion(
        lifecycle_table=lifecycle,
        tables={"profile_mappings": mappings},
    )

    graph.delete_resources(
        account_id=ACCOUNT_ID, operation_id=OPERATION_ID, resources=[mapping],
    )

    assert graph.resources_absent(
        account_id=ACCOUNT_ID, operation_id=OPERATION_ID, resources=[mapping],
    ) is True
    assert mappings.deletions == [key]


def test_member_deletion_reconciles_exact_owner_guard_after_membership_absence():
    member_account_id = ACCOUNT_ID
    owner_account_id = "acct_owner0123456789abcdef012345"
    lifecycle = Table("account_id", "record_key")
    lifecycle.items[(member_account_id, "root")] = {
        "account_id": member_account_id, "record_key": "root",
    }
    lifecycle.items[(owner_account_id, "root")] = {
        "account_id": owner_account_id,
        "record_key": "root",
        "record_type": "account_lifecycle_root",
        "state": "active",
        "account_role": "owner",
        "owner_deletion_state": "ownership_transfer_required",
        "revision": 2,
    }
    memberships = Table("household_id", "membership_id")
    memberships.items[("hh-1", "owner-membership")] = {
        "household_id": "hh-1",
        "membership_id": "owner-membership",
        "entity_type": "HouseholdMembership",
        "status": "active",
        "canonical_role": "owner",
        "account_id": owner_account_id,
    }
    memberships.items[("hh-1", "member-membership")] = {
        "household_id": "hh-1",
        "membership_id": "member-membership",
        "entity_type": "HouseholdMembership",
        "status": "active",
        "canonical_role": "member",
        "account_id": member_account_id,
    }
    households = Table("household_id")
    households.items["hh-1"] = {
        "household_id": "hh-1",
        "cloud_seat_profile_ids": {"profile-owner", "profile-member"},
    }
    resources = [
        resource("household_membership", "member-membership", {
            "household_id": "hh-1", "profile_id": "profile-member",
        }),
        resource("owner_lifecycle_guard", owner_account_id, {
            "household_id": "hh-1", "owner_account_id": owner_account_id,
        }),
    ]
    for item in resources:
        lifecycle.items[(member_account_id, item["resource_key"])] = {
            "account_id": member_account_id, "record_key": item["resource_key"],
        }
    graph = DynamoKaevoGraphDeletion(
        lifecycle_table=lifecycle,
        tables={
            "household_memberships": memberships,
            "identity_households": households,
        },
    )

    graph.delete_resources(
        account_id=member_account_id, operation_id=OPERATION_ID, resources=resources,
    )

    owner_root = lifecycle.items[(owner_account_id, "root")]
    assert owner_root["owner_deletion_state"] == "sole_member"
    assert owner_root["revision"] == 3
    assert households.items["hh-1"]["cloud_seat_profile_ids"] == {"profile-owner"}
