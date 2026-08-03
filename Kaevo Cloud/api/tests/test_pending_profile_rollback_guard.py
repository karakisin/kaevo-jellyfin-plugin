import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


SCRIPT = Path(__file__).parents[2] / "scripts" / "check-pending-profile-rollback.py"
SPEC = importlib.util.spec_from_file_location("pending_profile_rollback_guard", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = guard
SPEC.loader.exec_module(guard)


def table_name(key):
    return guard.EXPECTED_TABLES[key]["expected_name"]


def resolved_tables():
    return {spec["logical_id"]: spec["expected_name"] for spec in guard.EXPECTED_TABLES.values()}


class Table:
    def __init__(self, pages):
        self.pages = list(pages)

    def scan(self, **_kwargs):
        if not self.pages:
            return {"Items": []}
        result = self.pages.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class Resource:
    def __init__(self, pages):
        self.tables = {name: Table(value) for name, value in pages.items()}

    def Table(self, name):
        return self.tables[name]


class CloudFormation:
    def __init__(self, resources=None, status="UPDATE_COMPLETE"):
        self.resources = resources if resources is not None else {
            spec["logical_id"]: spec["expected_name"] for spec in guard.EXPECTED_TABLES.values()
        }
        self.status = status

    def describe_stacks(self, **_kwargs):
        return {"Stacks": [{"StackStatus": self.status}]}

    def list_stack_resources(self, **_kwargs):
        return {"StackResourceSummaries": [
            {"LogicalResourceId": logical, "PhysicalResourceId": physical,
             "ResourceType": "AWS::DynamoDB::Table", "ResourceStatus": "CREATE_COMPLETE"}
            for logical, physical in self.resources.items()
        ]}


class DynamoDB:
    def __init__(self, tables=None, ttl=None):
        self.tables = tables or {
            spec["expected_name"]: {
                "TableName": spec["expected_name"],
                "TableArn": guard.expected_arn(spec["expected_name"]),
                "TableStatus": "ACTIVE",
                "KeySchema": [
                    {"AttributeName": name, "KeyType": kind}
                    for name, kind in spec.get("key_schema", ())
                ],
            }
            for spec in guard.EXPECTED_TABLES.values()
        }
        self.ttl = ttl or {"TimeToLiveDescription": {"TimeToLiveStatus": "ENABLED", "AttributeName": "cleanup_at"}}

    def describe_table(self, *, TableName):
        value = self.tables.get(TableName)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise RuntimeError("missing_table")
        return {"Table": value}

    def describe_time_to_live(self, **_kwargs):
        return self.ttl


class STS:
    def __init__(self, account=guard.EXPECTED_ACCOUNT):
        self.account = account

    def get_caller_identity(self):
        if isinstance(self.account, Exception):
            raise self.account
        return {"Account": self.account}


class Session:
    def __init__(self, *, account=guard.EXPECTED_ACCOUNT, cloudformation=None, dynamodb=None, resource=None):
        self.clients = {
            "sts": STS(account),
            "cloudformation": cloudformation or CloudFormation(),
            "dynamodb": dynamodb or DynamoDB(),
        }
        self._resource = resource or Resource(clean_pages())

    def client(self, name):
        return self.clients[name]

    def resource(self, name):
        assert name == "dynamodb"
        return self._resource


def clean_pages():
    return {
        table_name("identity_memberships"): [{"Items": [{"state": "active"}]}],
        table_name("household_memberships"): [{"Items": [{"status": "active"}]}],
        table_name("join_transactions"): [{"Items": [{"entity_type": "HouseholdJoinResume", "state": "completed"}]}],
    }


def target_session(**kwargs):
    return Session(**kwargs)


def test_valid_target_is_accepted_before_any_scan():
    caller, _resource, resolved = guard.validate_target(target_session(), region=guard.EXPECTED_REGION)
    assert caller["Account"] == guard.EXPECTED_ACCOUNT
    assert resolved == resolved_tables()


def test_sts_failure_fails_closed():
    with pytest.raises(guard.UnsafeRollback, match="sts_failed"):
        guard.validate_target(target_session(account=RuntimeError("sts_unavailable")), region=guard.EXPECTED_REGION)


@pytest.mark.parametrize("account,region,reason", [
    ("000000000000", guard.EXPECTED_REGION, "unexpected_account"),
    (guard.EXPECTED_ACCOUNT, "us-east-1", "unexpected_region"),
])
def test_wrong_account_or_region_fails_closed(account, region, reason):
    with pytest.raises(guard.UnsafeRollback, match=reason):
        guard.validate_target(target_session(account=account), region=region)


@pytest.mark.parametrize("resources,status,reason", [
    ({}, "UPDATE_COMPLETE", "stack_table_name_mismatch"),
    (None, "UPDATE_IN_PROGRESS", "stack_not_healthy"),
])
def test_missing_or_unhealthy_stack_fails_closed(resources, status, reason):
    with pytest.raises(guard.UnsafeRollback, match=reason):
        guard.validate_target(target_session(cloudformation=CloudFormation(resources=resources, status=status)), region=guard.EXPECTED_REGION)


def test_stack_lookup_failure_fails_closed():
    cloudformation = CloudFormation()
    cloudformation.describe_stacks = lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("stack_denied"))
    with pytest.raises(guard.UnsafeRollback, match="stack_validation_failed"):
        guard.validate_target(target_session(cloudformation=cloudformation), region=guard.EXPECTED_REGION)


@pytest.mark.parametrize("mutate,reason", [
    (lambda tables: tables.__setitem__(table_name("identity_memberships"), None), "describe_table_failed"),
    (lambda tables: tables[table_name("household_memberships")].update({"TableName": "similarly-named-table"}), "table_name_mismatch"),
    (lambda tables: tables[table_name("identity_memberships")].update({"TableArn": "arn:aws:dynamodb:us-west-2:000000000000:table/kaevo-cloud-dev-identity-memberships"}), "table_arn_mismatch"),
    (lambda tables: tables[table_name("identity_memberships")].update({"TableArn": "arn:aws:dynamodb:us-east-1:295055514343:table/kaevo-cloud-dev-identity-memberships"}), "table_arn_mismatch"),
    (lambda tables: tables[table_name("identity_memberships")].update({"TableStatus": "UPDATING"}), "table_not_active"),
])
def test_table_identity_failures_block_rollback(mutate, reason):
    dynamodb = DynamoDB()
    mutate(dynamodb.tables)
    with pytest.raises(guard.UnsafeRollback, match=reason):
        guard.validate_target(target_session(dynamodb=dynamodb), region=guard.EXPECTED_REGION)


def test_ttl_mismatch_blocks_rollback():
    dynamodb = DynamoDB(ttl={"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED", "AttributeName": "cleanup_at"}})
    with pytest.raises(guard.UnsafeRollback, match="table_ttl_mismatch"):
        guard.validate_target(target_session(dynamodb=dynamodb), region=guard.EXPECTED_REGION)


@pytest.mark.parametrize("pages,reason", [
    ({table_name("identity_memberships"): [RuntimeError("denied")]}, "denied"),
    ({table_name("identity_memberships"): [{"Items": "not-a-list"}]}, "malformed_scan_response"),
    ({table_name("identity_memberships"): [{"Items": [{"state": "unknown"}]}]}, "unknown_membership_state"),
    ({table_name("join_transactions"): [{"Items": [{"entity_type": "HouseholdJoinResume", "state": "unknown"}]}]}, "unknown_transaction_state"),
])
def test_scan_errors_and_unknown_states_fail_closed(pages, reason):
    merged = clean_pages()
    merged.update(pages)
    with pytest.raises((guard.UnsafeRollback, RuntimeError), match=reason):
        guard.run_pass(Resource(merged), resolved_tables())


def test_pagination_failure_blocks_rollback():
    pages = clean_pages()
    pages[table_name("identity_memberships")] = [
        {"Items": [{"state": "active"}], "LastEvaluatedKey": {"principal_id": "same"}},
        {"Items": [{"state": "active"}], "LastEvaluatedKey": {"principal_id": "same"}},
    ]
    with pytest.raises(guard.UnsafeRollback, match="pagination_cycle_detected"):
        guard.run_pass(Resource(pages), resolved_tables())


def test_pending_membership_or_transaction_blocks_rollback():
    pages = clean_pages()
    pages[table_name("household_memberships")] = [{"Items": [{"status": "pending_profile"}]}]
    pages[table_name("join_transactions")] = [{"Items": [{"entity_type": "HouseholdJoinResume", "state": "membership_accepted"}]}]
    counts = guard.run_pass(Resource(pages), resolved_tables())
    assert counts.pending_normalized_memberships == 1
    assert counts.profile_setup_transactions == 1


def invoke_main(monkeypatch, session, *, quiesced=True, stack=guard.EXPECTED_STACK, interval=1):
    monkeypatch.setattr(guard, "parse_args", lambda: SimpleNamespace(
        profile="isolated-test", region=guard.EXPECTED_REGION, stack_name=stack,
        interval_seconds=interval,
        quiesce_confirmation="pending-profile-writes-quiesced" if quiesced else "absent",
    ))
    monkeypatch.setattr(guard.boto3, "Session", lambda **_kwargs: session)
    monkeypatch.setattr(guard.time, "sleep", lambda _seconds: None)
    return guard.main()


def test_missing_quiescence_or_wrong_stack_blocks_main(monkeypatch, capsys):
    assert invoke_main(monkeypatch, target_session(), quiesced=False) == 2
    assert "UNSAFE_FOR_ROLLBACK" in capsys.readouterr().out
    assert invoke_main(monkeypatch, target_session(), stack="wrong-stack") == 2


def test_pass_disagreement_blocks_rollback(monkeypatch, capsys):
    pages = clean_pages()
    pages[table_name("household_memberships")] = [
        {"Items": [{"status": "active"}]}, {"Items": [{"status": "pending_profile"}]},
    ]
    assert invoke_main(monkeypatch, target_session(resource=Resource(pages))) == 3
    assert "pass_disagreement" in capsys.readouterr().out


def test_two_clean_passes_are_safe_and_output_no_record_data(monkeypatch, capsys):
    pages = clean_pages()
    for name, values in clean_pages().items():
        pages[name].extend(values)
    assert invoke_main(monkeypatch, target_session(resource=Resource(pages))) == 0
    output = capsys.readouterr().out
    assert "SAFE_FOR_ROLLBACK" in output
    assert "caller_account=295055514343" in output
    assert "profile_id" not in output
    assert "HouseholdJoinResume" not in output


def test_help_and_argument_contract(monkeypatch):
    monkeypatch.setattr("sys.argv", [str(SCRIPT), "--help"])
    with pytest.raises(SystemExit, match="0"):
        guard.parse_args()
