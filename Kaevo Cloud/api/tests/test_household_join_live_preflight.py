from __future__ import annotations

import datetime as dt
import hashlib
import json
import os

import pytest

from scripts.household_join_live.errors import FixtureSafetyError
from scripts.household_join_live.control_plane import RECORD_NAME
from scripts.household_join_live.preflight import run_preflight


def _metadata():
    return {"RequestId": "safe-request-id", "HTTPHeaders": {"date": "Sun, 27 Jul 2026 10:00:00 GMT"}}


def _write_control_plane_exception(root):
    record = {
        "schema": 2, "state": "CONTROL_PLANE_UNVERIFIABLE_BRANDING_ONLY",
        "account": "295055514343", "profile": "kaevo-dev", "region": "us-west-2", "stack_status": "UPDATE_COMPLETE",
        "allowed_next_operation": "FIXTURE_RUNNER_PREFLIGHT", "expires_utc": "2026-07-27T11:00:00Z",
        "terminal_drift": {"detection_status": "DETECTION_FAILED", "stack_drift_status": "UNKNOWN"},
        "branding_direct_fingerprint": "a" * 64,
        "reason": "CLOUDFORMATION_BRANDING_INTERNAL_FAILURE", "api_role_drift": "IN_SYNC",
        "removed_iam_policy_absent": True, "resource_results_complete": True,
    }
    record["integrity_sha256"] = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    path = root / RECORD_NAME
    path.write_text(json.dumps(record))
    os.chmod(path, 0o600)


class FakeClient:
    def __init__(self, name, join_indexes=()):
        self.name = name
        self.join_indexes = list(join_indexes)
        self.scan_called = False

    def get_caller_identity(self):
        return {"Account": "295055514343", "Arn": "arn:aws:sts::295055514343:assumed-role/dev/test", "ResponseMetadata": _metadata()}

    def describe_stacks(self, **_kwargs):
        return {"Stacks": [{"StackStatus": "UPDATE_COMPLETE", "StackId": "arn:aws:cloudformation:us-west-2:295055514343:stack/kaevo-cloud-dev/safe"}]}

    def list_stack_resources(self, **_kwargs):
        logical = [
            "KaevoHouseholdJoinFunction", "KaevoHouseholdJoinTransactionsTable", "KaevoHouseholdInvitationsTable", "KaevoPrincipalsTable", "KaevoIdentityMembershipsTable", "KaevoIdentityProfilesTable", "KaevoAccountsTable", "KaevoAuthIdentitiesTable", "KaevoHouseholdMembershipsTable", "KaevoProfilesTable", "KaevoProfileBindingsTable", "KaevoProfileMappingsTable", "KaevoEntitlementsTable",
        ]
        return {"StackResourceSummaries": [{"LogicalResourceId": value, "PhysicalResourceId": value + "-physical"} for value in logical]}

    def get_function_configuration(self, **_kwargs):
        variables = {
            "HOUSEHOLD_JOIN_TRANSACTIONS_TABLE": "KaevoHouseholdJoinTransactionsTable-physical", "HOUSEHOLD_INVITATIONS_TABLE": "KaevoHouseholdInvitationsTable-physical", "PRINCIPALS_TABLE": "KaevoPrincipalsTable-physical", "IDENTITY_MEMBERSHIPS_TABLE": "KaevoIdentityMembershipsTable-physical", "IDENTITY_PROFILES_TABLE": "KaevoIdentityProfilesTable-physical", "ACCOUNTS_TABLE": "KaevoAccountsTable-physical", "AUTH_IDENTITIES_TABLE": "KaevoAuthIdentitiesTable-physical", "HOUSEHOLD_MEMBERSHIPS_TABLE": "KaevoHouseholdMembershipsTable-physical", "CLOUD_PROFILES_TABLE": "KaevoProfilesTable-physical", "PROFILE_BINDINGS_TABLE": "KaevoProfileBindingsTable-physical", "PROFILE_MAPPINGS_TABLE": "KaevoProfileMappingsTable-physical", "ENTITLEMENTS_TABLE": "KaevoEntitlementsTable-physical",
        }
        return {"State": "Active", "LastUpdateStatus": "Successful", "Environment": {"Variables": variables}}

    def describe_table(self, *, TableName):
        table = {"TableArn": f"arn:aws:dynamodb:us-west-2:295055514343:table/{TableName}", "TableStatus": "ACTIVE"}
        if TableName.startswith("KaevoHouseholdJoinTransactions"):
            table["KeySchema"] = [{"AttributeName": "join_resume_hash", "KeyType": "HASH"}]
            table["GlobalSecondaryIndexes"] = self.join_indexes
        return {"Table": table}

    def scan(self, **_kwargs):
        self.scan_called = True
        raise AssertionError("scan is prohibited")


class FakeSession:
    profile_name = "kaevo-dev"
    region_name = "us-west-2"

    def __init__(self, **_kwargs):
        self.clients = {name: FakeClient(name) for name in ("sts", "cloudformation", "lambda", "dynamodb")}

    def client(self, name):
        return self.clients[name]


def test_preflight_refuses_live_fixture_when_join_table_has_no_fixture_query_index(tmp_path):
    root = tmp_path / "fixtures"
    root.mkdir(mode=0o700, exist_ok=True)
    with pytest.raises(FixtureSafetyError, match="UNQUERYABLE_WITHOUT_SCAN"):
        run_preflight(session_factory=FakeSession, root=root, now=dt.datetime(2026, 7, 27, 10, 0, tzinfo=dt.timezone.utc))


def test_preflight_accepts_only_a_fixture_owned_join_transaction_gsi(tmp_path):
    class IndexedSession(FakeSession):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.clients["dynamodb"].join_indexes = [{
                "IndexName": "invitation_id-created_at_epoch-index", "IndexStatus": "ACTIVE",
                "KeySchema": [{"AttributeName": "invitation_id", "KeyType": "HASH"}, {"AttributeName": "created_at_epoch", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "KEYS_ONLY"},
            }]

    root = tmp_path / "fixtures"
    root.mkdir(mode=0o700)
    _write_control_plane_exception(root)
    result = run_preflight(session_factory=IndexedSession, root=root, now=dt.datetime(2026, 7, 27, 10, 0, tzinfo=dt.timezone.utc))
    assert result["event"] == "PREFLIGHT_OK"


@pytest.mark.parametrize("index", [
    {"IndexName": "wrong-index", "IndexStatus": "ACTIVE", "KeySchema": [{"AttributeName": "invitation_id", "KeyType": "HASH"}, {"AttributeName": "created_at_epoch", "KeyType": "RANGE"}], "Projection": {"ProjectionType": "KEYS_ONLY"}},
    {"IndexName": "invitation_id-created_at_epoch-index", "IndexStatus": "ACTIVE", "KeySchema": [{"AttributeName": "invitation_code_hash", "KeyType": "HASH"}, {"AttributeName": "created_at_epoch", "KeyType": "RANGE"}], "Projection": {"ProjectionType": "KEYS_ONLY"}},
    {"IndexName": "invitation_id-created_at_epoch-index", "IndexStatus": "ACTIVE", "KeySchema": [{"AttributeName": "invitation_id", "KeyType": "HASH"}, {"AttributeName": "created_at_epoch", "KeyType": "RANGE"}], "Projection": {"ProjectionType": "ALL"}},
    {"IndexName": "invitation_id-created_at_epoch-index", "IndexStatus": "CREATING", "KeySchema": [{"AttributeName": "invitation_id", "KeyType": "HASH"}, {"AttributeName": "created_at_epoch", "KeyType": "RANGE"}], "Projection": {"ProjectionType": "KEYS_ONLY"}},
])
def test_preflight_rejects_any_noncanonical_transaction_gsi(tmp_path, index):
    class InvalidIndexSession(FakeSession):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.clients["dynamodb"].join_indexes = [index]

    root = tmp_path / "fixtures"
    root.mkdir(mode=0o700)
    with pytest.raises(FixtureSafetyError, match="UNQUERYABLE_WITHOUT_SCAN"):
        run_preflight(session_factory=InvalidIndexSession, root=root, now=dt.datetime(2026, 7, 27, 10, 0, tzinfo=dt.timezone.utc))


def test_preflight_refuses_an_insecure_fixture_root(tmp_path):
    root = tmp_path / "fixtures"
    root.mkdir(mode=0o755)
    os.chmod(root, 0o755)
    with pytest.raises(FixtureSafetyError, match="FIXTURE_ROOT_MODE_MISMATCH"):
        run_preflight(session_factory=FakeSession, root=root, now=dt.datetime(2026, 7, 27, 10, 0, tzinfo=dt.timezone.utc))


def _resources():
    return FakeClient("cloudformation").list_stack_resources()["StackResourceSummaries"]


def _preflight_with_pages(tmp_path, pages):
    class PagedCloudFormation(FakeClient):
        def __init__(self):
            super().__init__("cloudformation")
            self.calls = []

        def list_stack_resources(self, **kwargs):
            self.calls.append(kwargs)
            index = 0 if "NextToken" not in kwargs else int(kwargs["NextToken"])
            return pages[index]

    class PagedSession(FakeSession):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.clients["cloudformation"] = PagedCloudFormation()
            self.clients["dynamodb"].join_indexes = [{
                "IndexName": "invitation_id-created_at_epoch-index", "IndexStatus": "ACTIVE",
                "KeySchema": [{"AttributeName": "invitation_id", "KeyType": "HASH"}, {"AttributeName": "created_at_epoch", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "KEYS_ONLY"},
            }]

    root = tmp_path / "fixtures"
    root.mkdir(mode=0o700, exist_ok=True)
    _write_control_plane_exception(root)
    return run_preflight(session_factory=PagedSession, root=root, now=dt.datetime(2026, 7, 27, 10, 0, tzinfo=dt.timezone.utc))


@pytest.mark.parametrize("page_count", [2, 3])
def test_preflight_resolves_required_bindings_across_all_stack_resource_pages(tmp_path, page_count):
    resources = _resources()
    chunks = [resources[index::page_count] for index in range(page_count)]
    pages = [
        {"StackResourceSummaries": chunk, **({"NextToken": str(index + 1)} if index + 1 < page_count else {})}
        for index, chunk in enumerate(chunks)
    ]
    assert _preflight_with_pages(tmp_path, pages)["event"] == "PREFLIGHT_OK"


def test_preflight_rejects_repeated_or_malformed_stack_resource_continuations(tmp_path):
    first = _resources()[:1]
    for token in ("1", 7, ""):
        pages = [{"StackResourceSummaries": first, "NextToken": token}]
        if token == "1":
            pages.append({"StackResourceSummaries": [], "NextToken": "1"})
        with pytest.raises(FixtureSafetyError, match="STACK_RESOURCE_PAGINATION_INVALID"):
            _preflight_with_pages(tmp_path, pages)


def test_preflight_rejects_duplicate_or_missing_required_stack_resource_bindings(tmp_path):
    resources = _resources()
    duplicate = [resources[:1], {"StackResourceSummaries": [resources[0]], "NextToken": None}]
    duplicate[0] = {"StackResourceSummaries": resources[:1], "NextToken": "1"}
    with pytest.raises(FixtureSafetyError, match="STACK_RESOURCE_BINDING_DUPLICATE"):
        _preflight_with_pages(tmp_path, duplicate)
    with pytest.raises(FixtureSafetyError, match="STACK_RESOURCE_BINDING_MISSING"):
        _preflight_with_pages(tmp_path, [{"StackResourceSummaries": resources[:-1]}])


def test_preflight_does_not_convert_stack_page_failure_to_partial_success(tmp_path):
    class FailingCloudFormation(FakeClient):
        def __init__(self):
            super().__init__("cloudformation")

        def list_stack_resources(self, **_kwargs):
            raise RuntimeError("transport failure")

    class FailingSession(FakeSession):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.clients["cloudformation"] = FailingCloudFormation()

    root = tmp_path / "fixtures"
    root.mkdir(mode=0o700)
    with pytest.raises(RuntimeError, match="transport failure"):
        run_preflight(session_factory=FailingSession, root=root, now=dt.datetime(2026, 7, 27, 10, 0, tzinfo=dt.timezone.utc))
