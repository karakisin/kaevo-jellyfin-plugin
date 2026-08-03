import json

import boto3

from botocore.exceptions import ClientError

import household_join_handler as join


class ExactTable:
    def __init__(self, item=None, error=None):
        self.item = item
        self.error = error
        self.calls = []

    def get_item(self, *, Key, **_kwargs):
        self.calls.append(dict(Key))
        if self.error:
            raise self.error
        return {"Item": dict(self.item)} if self.item is not None else {}


def payload(result):
    return json.loads(result["body"])


def cancellation(reasons, code="TransactionCanceledException"):
    return ClientError({"Error": {"Code": code}, "CancellationReasons": reasons}, "TransactWriteItems")


def operation(label, table, *, expected=None):
    value = {"label": label, "table": table, "key": {"safe": label}}
    if expected is not None:
        value["expected"] = expected
    return value


def reasons_at(index, count=1):
    return [{"Code": "ConditionalCheckFailed"} if item == index else {"Code": "None"} for item in range(count)]


def test_consumed_invitation_condition_maps_to_already_used():
    result = join._completion_transaction_conflict(
        cancellation(reasons_at(0)), [operation("invitation", ExactTable({"state": "consumed", "expires_at": join.epoch_now() + 60}))], join.epoch_now(),
    )
    assert result["statusCode"] == 409
    assert payload(result)["state"] == "invitation_already_used"


def test_expired_invitation_condition_maps_to_expired():
    result = join._completion_transaction_conflict(
        cancellation(reasons_at(0)), [operation("invitation", ExactTable({"state": "pending", "expires_at": join.epoch_now() - 1}))], join.epoch_now(),
    )
    assert result["statusCode"] == 410
    assert payload(result)["state"] == "invitation_expired"


def test_pending_invitation_condition_never_maps_to_already_used():
    result = join._completion_transaction_conflict(
        cancellation(reasons_at(0)), [operation("invitation", ExactTable({"state": "pending", "expires_at": join.epoch_now() + 60}))], join.epoch_now(),
    )
    assert result["statusCode"] == 409
    assert payload(result)["state"] == "transaction_wrong_state"


def test_join_wrong_state_is_safe_conflict():
    result = join._completion_transaction_conflict(
        cancellation(reasons_at(0)), [operation("join_transaction", ExactTable({"state": "initiated", "expires_at": join.epoch_now() + 60}))], join.epoch_now(),
    )
    assert result["statusCode"] == 409
    assert payload(result)["state"] == "transaction_wrong_state"


def test_expired_join_transaction_is_explicit():
    result = join._completion_transaction_conflict(
        cancellation(reasons_at(0)), [operation("join_transaction", ExactTable({"state": "awaiting_authorization", "expires_at": join.epoch_now() - 1}))], join.epoch_now(),
    )
    assert result["statusCode"] == 410
    assert payload(result)["state"] == "transaction_expired"


def test_matching_normalized_membership_maps_to_already_member():
    result = join._completion_transaction_conflict(
        cancellation(reasons_at(0)),
        [operation("normalized_membership", ExactTable({"entity_type": "HouseholdMembership", "account_id": "safe-account", "status": "pending_profile"}), expected={"account_id": "safe-account"})],
        join.epoch_now(),
    )
    assert result["statusCode"] == 409
    assert payload(result)["state"] == "already_member"


def test_conflicting_normalized_membership_requires_manual_review():
    result = join._completion_transaction_conflict(
        cancellation(reasons_at(0)),
        [operation("normalized_membership", ExactTable({"entity_type": "HouseholdMembership", "account_id": "other-safe-account", "status": "active"}), expected={"account_id": "safe-account"})],
        join.epoch_now(),
    )
    assert result["statusCode"] == 409
    assert payload(result)["state"] == "manual_review_required"


def test_missing_or_malformed_cancellation_reasons_fail_closed():
    operations = [operation("invitation", ExactTable({"state": "consumed"}))]
    assert payload(join._completion_transaction_conflict(cancellation(None), operations, join.epoch_now()))["state"] == "transaction_wrong_state"
    assert payload(join._completion_transaction_conflict(cancellation([], "TransactionCanceledException"), operations, join.epoch_now()))["state"] == "transaction_wrong_state"


def test_multiple_or_unknown_failure_reasons_fail_closed():
    operations = [operation("invitation", ExactTable({"state": "consumed"})), operation("unrecognized", ExactTable())]
    assert payload(join._completion_transaction_conflict(cancellation(reasons_at(0, 2) + [{"Code": "None"}]), operations, join.epoch_now()))["state"] == "transaction_wrong_state"
    assert payload(join._completion_transaction_conflict(cancellation([{"Code": "ConditionalCheckFailed"}, {"Code": "ConditionalCheckFailed"}]), operations, join.epoch_now()))["state"] == "transaction_wrong_state"


def test_profile_setup_transaction_conflict_logs_only_the_safe_failed_operation(capsys):
    operations = [
        {"label": "cloud_profile", "transaction": {"Put": {"TableName": "safe", "Item": {}}}},
        {"label": "profile_mapping", "transaction": {"Put": {"TableName": "safe", "Item": {}}}},
    ]
    result = join._profile_setup_transaction_failure(cancellation(reasons_at(1, 2)), operations)
    assert result["statusCode"] == 409
    assert payload(result)["state"] == "manual_review_required"
    assert json.loads(capsys.readouterr().out) == {
        "event": "household_join_profile_setup_transaction_failure",
        "operation_count": 2,
        "safe_error_category": "conditional_conflict",
        "failed_transaction_operation": "profile_mapping",
    }


def test_profile_setup_non_cancellation_is_server_error_without_service_message(capsys):
    error = ClientError({"Error": {"Code": "ValidationException", "Message": "sensitive-value"}}, "TransactWriteItems")
    result = join._profile_setup_transaction_failure(error, [{"label": "profile_mapping", "transaction": {}}])
    assert result["statusCode"] == 500
    assert payload(result)["state"] == "server_error"
    rendered = capsys.readouterr().out
    assert "sensitive-value" not in rendered
    assert json.loads(rendered)["safe_error_category"] == "transaction_validation"


def test_follow_up_read_failure_is_server_error():
    error = ClientError({"Error": {"Code": "InternalServerError"}}, "GetItem")
    result = join._completion_transaction_conflict(cancellation(reasons_at(0)), [operation("invitation", ExactTable(error=error))], join.epoch_now())
    assert result["statusCode"] == 500
    assert payload(result)["state"] == "server_error"


def test_non_transaction_service_failure_is_server_error_with_safe_diagnostic(capsys):
    result = join._completion_transaction_conflict(cancellation([], "InternalServerError"), [operation("invitation", ExactTable())], join.epoch_now())
    assert result["statusCode"] == 500
    assert payload(result)["state"] == "server_error"
    diagnostic = json.loads(capsys.readouterr().out)
    assert diagnostic == {
        "event": "household_join_complete_transaction_failure",
        "safe_error_category": "InternalServerError",
        "operation_count": 1,
    }


def test_unknown_transaction_service_failure_never_logs_raw_error_text(capsys):
    error = ClientError({"Error": {"Code": "UnexpectedServiceFailure", "Message": "sensitive-value"}}, "TransactWriteItems")
    result = join._completion_transaction_conflict(error, [operation("invitation", ExactTable())], join.epoch_now())
    assert result["statusCode"] == 500
    rendered = capsys.readouterr().out
    assert "sensitive-value" not in rendered
    assert "UnexpectedServiceFailure" not in rendered
    assert json.loads(rendered)["safe_error_category"] == "other_client_error"


def test_access_denied_is_reduced_to_safe_action_target_and_policy_labels(monkeypatch, capsys):
    monkeypatch.setattr(join, "ACCOUNTS_TABLE", "safe-accounts")
    error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": (
                    "User: arn:aws:sts::123456789012:assumed-role/sensitive-role/session "
                    "is not authorized to perform: dynamodb:TransactWriteItems on resource: "
                    "arn:aws:dynamodb:us-west-2:123456789012:table/safe-accounts "
                    "because no identity-based policy allows the dynamodb:TransactWriteItems action"
                ),
            },
        },
        "TransactWriteItems",
    )
    result = join._completion_transaction_conflict(
        error, [operation("account", ExactTable())], join.epoch_now(),
    )
    assert result["statusCode"] == 500
    rendered = capsys.readouterr().out
    assert "sensitive-role" not in rendered
    assert "123456789012" not in rendered
    diagnostic = json.loads(rendered)
    assert diagnostic == {
        "event": "household_join_complete_transaction_failure",
        "safe_error_category": "AccessDeniedException",
        "operation_count": 1,
        "denied_action_category": "dynamodb_transact_write_items",
        "denied_target_category": "account",
        "denied_policy_category": "identity_policy_missing",
    }


def test_validation_failure_is_classified_without_logging_service_text(capsys):
    error = ClientError(
        {"Error": {"Code": "ValidationException", "Message": "reserved keyword: sensitive-value"}},
        "TransactWriteItems",
    )
    result = join._completion_transaction_conflict(error, [operation("invitation", ExactTable())], join.epoch_now())
    assert result["statusCode"] == 500
    rendered = capsys.readouterr().out
    assert "sensitive-value" not in rendered
    assert "reserved keyword" not in rendered
    assert json.loads(rendered)["safe_error_category"] == "reserved_attribute_name"


def test_validation_probe_returns_only_the_first_safe_operation_label(monkeypatch):
    class ProbeClient:
        def transact_write_items(self, *, TransactItems):
            operation = next(iter(TransactItems[0]))
            if operation == "Put":
                raise ClientError({"Error": {"Code": "ValidationException"}}, "TransactWriteItems")
            raise ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")

    monkeypatch.setattr(join, "JOIN_TABLE", "safe-joins")
    monkeypatch.setattr(join, "dynamodb", type("Dynamo", (), {"meta": type("Meta", (), {"client": ProbeClient()})()})())
    result = join._completion_validation_probe([
        operation("account", ExactTable()) | {"transaction": {"Put": {"TableName": "safe-table", "Item": {"key": "safe"}}}},
    ])
    assert result == "account"


def test_resource_client_serializes_native_values_once_for_transaction_wire_shape(monkeypatch):
    class StopBeforeNetwork(Exception):
        pass

    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    client = boto3.resource(
        "dynamodb", region_name="us-west-2",
        aws_access_key_id="testing", aws_secret_access_key="testing",
    ).meta.client
    observed = {}

    def capture(*, params, **_kwargs):
        payload = json.loads(params["body"])
        update = payload["TransactItems"][0]["Update"]
        observed["key_kind"] = next(iter(update["Key"]["join_resume_hash"]))
        observed["value_kind"] = next(iter(update["ExpressionAttributeValues"][":state"]))
        raise StopBeforeNetwork

    client.meta.events.register_first("before-call.dynamodb.TransactWriteItems", capture)
    with __import__("pytest").raises(StopBeforeNetwork):
        client.transact_write_items(TransactItems=[{
            "Update": {
                "TableName": "safe-table",
                "Key": {"join_resume_hash": "safe-hash"},
                "UpdateExpression": "SET #state = :state",
                "ExpressionAttributeNames": {"#state": "state"},
                "ExpressionAttributeValues": {":state": "membership_accepted"},
            },
        }])
    assert observed == {"key_kind": "S", "value_kind": "S"}


def test_classifier_never_logs_or_returns_raw_cancellation_data():
    source = join._completion_transaction_conflict.__doc__ or ""
    assert "never parses exception text" in source
    result = join._completion_transaction_conflict(
        cancellation([{ "Code": "ConditionalCheckFailed", "Message": "sensitive-value", "Item": {"private": "value"}}]),
        [operation("invitation", ExactTable({"state": "pending", "expires_at": join.epoch_now() + 60}))], join.epoch_now(),
    )
    rendered = json.dumps(result)
    assert "sensitive-value" not in rendered
    assert "private" not in rendered
