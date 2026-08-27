from copy import deepcopy
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from account_lifecycle_v2 import LifecycleV2Error
from account_lifecycle_v2_service import (
    AccountLifecycleV2Service,
    DynamoLifecycleV2Repository,
    LifecycleV2StorageError,
)


ACCOUNT_ID = "acct_0123456789abcdef01234567"
OPERATION_ID = "ald2_0123456789abcdef0123456789abcdef"


def registry(capability="enabled"):
    return [
        {
            "account_id": ACCOUNT_ID,
            "record_key": "root",
            "record_type": "account_lifecycle_root",
            "schema_version": 2,
            "revision": 4,
            "state": "active",
            "account_role": "owner",
            "owner_deletion_state": "sole_member",
        },
        {
            "account_id": ACCOUNT_ID,
            "record_key": "resource#account#self",
            "record_type": "account_lifecycle_resource",
            "resource_type": "account",
            "resource_id": ACCOUNT_ID,
            "resource_key": "resource#account#self",
            "state": "active",
        },
        {
            "account_id": ACCOUNT_ID,
            "record_key": "resource#cognito#subject",
            "record_type": "account_lifecycle_resource",
            "resource_type": "cognito_subject",
            "resource_id": "subject-opaque-123",
            "resource_key": "resource#cognito#subject",
            "state": "active",
        },
        {
            "account_id": ACCOUNT_ID,
            "record_key": "resource#profile#one",
            "record_type": "account_lifecycle_resource",
            "resource_type": "cloud_profile",
            "resource_id": "profile_0123456789abcdef",
            "resource_key": "resource#profile#one",
            "state": "active",
        },
        {
            "account_id": ACCOUNT_ID,
            "record_key": "resource#provider#one",
            "record_type": "account_lifecycle_resource",
            "resource_type": "provider_binding",
            "resource_id": "provider_binding_0123456789abcdef",
            "resource_key": "resource#provider#one",
            "state": "active",
            "attributes": {"two_way_profile_deletion": capability},
        },
    ]


class Repository:
    def __init__(self, records=None):
        self.records = deepcopy(records or registry())
        self.operations = {}
        self.queued = []
        self.auth_identity_active = True

    def account_id_for_subject(self, subject):
        assert subject == "subject-opaque-123"
        if not self.auth_identity_active:
            raise LifecycleV2StorageError("auth_identity_not_active")
        return ACCOUNT_ID

    def registry_records(self, account_id):
        assert account_id == ACCOUNT_ID
        return deepcopy(self.records)

    def put_preflight(self, plan, now):
        self.operations[plan.operation_id] = {
            **plan.public_summary(),
            "phase": "awaiting_confirmation",
            "retryable": False,
        }

    def queue_operation(self, account_id, operation_id, plan_digest, now):
        item = self.operations[operation_id]
        assert account_id == ACCOUNT_ID
        assert item["plan_digest"] == plan_digest
        item["phase"] = "queued"
        item["retryable"] = True
        self.queued.append(operation_id)
        return deepcopy(item)

    def operation(self, account_id, operation_id):
        assert account_id == ACCOUNT_ID
        return deepcopy(self.operations.get(operation_id))

    def operation_for_subject(self, operation_id, subject):
        assert subject == "subject-opaque-123"
        return deepcopy(self.operations.get(operation_id))

    def ensure_session_resources(
        self, account_id, *, subject, family_id, installation_id, access_record_id, now,
    ):
        self.session_resources = {
            "account_id": account_id,
            "family_id": family_id,
            "installation_id": installation_id,
            "access_record_id": access_record_id,
            "now": now,
        }


def service(repository):
    return AccountLifecycleV2Service(
        repository,
        operation_id_factory=lambda: OPERATION_ID,
        clock=lambda: 1_800_000_000,
    )


def test_preflight_authority_comes_only_from_server_registry():
    repository = Repository()
    result = service(repository).preflight(
        subject="subject-opaque-123", requested_scope="everything",
    )

    assert result["account_id"] == ACCOUNT_ID
    assert result["profile_count"] == 1
    assert result["provider_binding_count"] == 1
    assert result["provider_capability"] == "enabled"
    assert OPERATION_ID in repository.operations


def test_current_session_resources_are_registered_by_exact_server_ids():
    repository = Repository()
    lifecycle = service(repository)

    account_id = lifecycle.register_session_resources(
        subject="subject-opaque-123",
        session={
            "account_id": ACCOUNT_ID,
            "family_id": "family-exact",
            "installation_id": "installation-exact",
            "token_hash": "access#exact-hash",
        },
    )

    assert account_id == ACCOUNT_ID
    assert repository.session_resources == {
        "account_id": ACCOUNT_ID,
        "family_id": "family-exact",
        "installation_id": "installation-exact",
        "access_record_id": "access#exact-hash",
        "now": 1_800_000_000,
    }


def test_current_session_cannot_register_resources_for_another_account():
    with pytest.raises(LifecycleV2Error, match="protected_session_account_mismatch"):
        service(Repository()).register_session_resources(
            subject="subject-opaque-123",
            session={
                "account_id": "acct_other-account-identity",
                "family_id": "family-exact",
                "installation_id": "installation-exact",
                "token_hash": "access#exact-hash",
            },
        )


def test_confirmation_queues_same_frozen_plan_and_is_idempotent_at_repository_boundary():
    repository = Repository()
    lifecycle = service(repository)
    preflight = lifecycle.preflight(
        subject="subject-opaque-123", requested_scope="everything",
    )

    result = lifecycle.confirm(
        subject="subject-opaque-123",
        operation_id=preflight["operation_id"],
        plan_digest=preflight["plan_digest"],
        confirmation="DELETE",
    )

    assert result["phase"] == "queued"
    assert result["account_id"] == ACCOUNT_ID
    assert repository.queued == [OPERATION_ID]


def test_confirmation_never_accepts_profile_or_email_as_authority():
    repository = Repository()
    lifecycle = service(repository)
    preflight = lifecycle.preflight(
        subject="subject-opaque-123", requested_scope="everything",
    )

    with pytest.raises(LifecycleV2Error, match="deletion_confirmation_invalid"):
        lifecycle.confirm(
            subject="subject-opaque-123",
            operation_id=preflight["operation_id"],
            plan_digest=preflight["plan_digest"],
            confirmation="profile_0123456789abcdef",
        )


def test_confirmation_rejects_a_historical_awaiting_kaevo_only_plan():
    repository = Repository()
    repository.operations[OPERATION_ID] = {
        "operation_id": OPERATION_ID,
        "account_id": ACCOUNT_ID,
        "scope": "kaevo_only",
        "provider_capability": "not_applicable",
        "plan_digest": "aldp2_historical",
        "phase": "awaiting_confirmation",
    }

    with pytest.raises(LifecycleV2Error, match="deletion_scope_retired"):
        service(repository).confirm(
            subject="subject-opaque-123",
            operation_id=OPERATION_ID,
            plan_digest="aldp2_historical",
            confirmation="DELETE",
        )

    assert repository.queued == []


def test_everything_stays_unselectable_when_connector_capability_is_not_enabled():
    repository = Repository(registry(capability="unavailable"))
    result = service(repository).preflight(
        subject="subject-opaque-123", requested_scope="everything",
    )

    assert result["provider_capability"] == "unavailable"
    assert result["can_confirm"] is False

    with pytest.raises(LifecycleV2Error, match="provider_deletion_not_enabled"):
        service(repository).confirm(
            subject="subject-opaque-123",
            operation_id=result["operation_id"],
            plan_digest=result["plan_digest"],
            confirmation="DELETE",
        )


def test_terminal_status_remains_readable_after_auth_identity_is_deleted():
    repository = Repository()
    lifecycle = service(repository)
    repository.operations[OPERATION_ID] = {
        "operation_id": OPERATION_ID,
        "account_id": ACCOUNT_ID,
        "scope": "kaevo_only",
        "provider_capability": "not_applicable",
        "plan_digest": "aldp2_historical",
        "phase": "completed",
        "retryable": False,
        "proof": {
            "cognito_identity_absent": True,
            "cognito_email_absent": True,
            "kaevo_graph_absent": True,
            "jellyfin_identity_absent": None,
            "seerr_identity_absent": None,
        },
    }
    repository.auth_identity_active = False

    result = lifecycle.status(
        subject="subject-opaque-123", operation_id=OPERATION_ID,
    )

    assert result["phase"] == "completed"
    assert result["proof"]["cognito_identity_absent"] is True
    assert result["proof"]["cognito_email_absent"] is True


class EmptyLifecycleTable:
    def query(self, **kwargs):
        assert kwargs["ConsistentRead"] is True
        return {"Items": []}


def test_empty_lifecycle_partition_requires_explicit_migration():
    repository = DynamoLifecycleV2Repository(
        lifecycle_table=EmptyLifecycleTable(),
        auth_identities_table=SimpleNamespace(),
    )

    with pytest.raises(LifecycleV2StorageError, match="lifecycle_root_missing"):
        repository.registry_records(ACCOUNT_ID)


class TransactionTable:
    name = "lifecycle"

    def __init__(self):
        self.items = {
            (ACCOUNT_ID, "root"): {
                "account_id": ACCOUNT_ID,
                "record_key": "root",
                "record_type": "account_lifecycle_root",
                "state": "active",
                "account_role": "owner",
                "owner_deletion_state": "sole_member",
                "revision": 4,
            },
            (ACCOUNT_ID, f"operation#{OPERATION_ID}"): {
                "account_id": ACCOUNT_ID,
                "record_key": f"operation#{OPERATION_ID}",
                "record_type": "account_lifecycle_operation",
                "operation_id": OPERATION_ID,
                "scope": "everything",
                "provider_capability": "enabled",
                "plan_digest": "aldp2_exact",
                "lifecycle_revision": 4,
                "phase": "awaiting_confirmation",
            },
        }
        self.transactions = []
        self.meta = SimpleNamespace(client=self)

    def get_item(self, *, Key, ConsistentRead):
        assert ConsistentRead is True
        item = self.items.get((Key["account_id"], Key["record_key"]))
        return {"Item": deepcopy(item)} if item else {}

    def transact_write_items(self, *, TransactItems):
        self.transactions.append(deepcopy(TransactItems))
        operation = self.items[(ACCOUNT_ID, f"operation#{OPERATION_ID}")]
        operation["phase"] = "queued"
        operation["retryable"] = True


class ProductionExpressionTransactionTable(TransactionTable):
    """Reject DynamoDB reserved words the same way Production does."""

    def transact_write_items(self, *, TransactItems):
        operation_update = TransactItems[1]["Update"]
        condition = operation_update["ConditionExpression"]
        names = operation_update.get("ExpressionAttributeNames") or {}
        if "#scope = :everything" in condition and names.get("#scope") != "scope":
            raise ClientError({
                "Error": {
                    "Code": "ValidationException",
                    "Message": (
                        "Invalid ConditionExpression: Attribute name is a reserved "
                        "keyword; reserved keyword: scope"
                    ),
                },
            }, "TransactWriteItems")
        super().transact_write_items(TransactItems=TransactItems)


class FailingTransactionTable(TransactionTable):
    def transact_write_items(self, *, TransactItems):
        raise ClientError({
            "Error": {
                "Code": "ValidationException",
                "Message": "unrelated transaction validation failure",
            },
        }, "TransactWriteItems")


def test_confirmation_atomically_checks_frozen_root_revision_before_queueing():
    table = TransactionTable()
    repository = DynamoLifecycleV2Repository(
        lifecycle_table=table,
        auth_identities_table=SimpleNamespace(),
    )

    queued = repository.queue_operation(
        ACCOUNT_ID, OPERATION_ID, "aldp2_exact", 1_800_000_000,
    )

    assert queued["phase"] == "queued"
    transaction = table.transactions[0]
    root_check = transaction[0]["ConditionCheck"]
    assert root_check["Key"] == {"account_id": ACCOUNT_ID, "record_key": "root"}
    assert root_check["ExpressionAttributeValues"][":revision"] == 4
    assert "account_role = :owner" in root_check["ConditionExpression"]
    operation_update = transaction[1]["Update"]
    assert operation_update["ExpressionAttributeValues"][":revision"] == 4
    assert "lifecycle_revision = :revision" in operation_update["ConditionExpression"]


def test_confirmation_transaction_aliases_reserved_scope_attribute_for_production():
    table = ProductionExpressionTransactionTable()
    repository = DynamoLifecycleV2Repository(
        lifecycle_table=table,
        auth_identities_table=SimpleNamespace(),
    )

    queued = repository.queue_operation(
        ACCOUNT_ID, OPERATION_ID, "aldp2_exact", 1_800_000_000,
    )

    assert queued["phase"] == "queued"
    operation_update = table.transactions[0][1]["Update"]
    assert "#scope = :everything" in operation_update["ConditionExpression"]
    assert "provider_capability IN (:enabled, :not_applicable)" in (
        operation_update["ConditionExpression"]
    )
    assert operation_update["ExpressionAttributeNames"]["#scope"] == "scope"


def test_confirmation_does_not_mask_non_conflict_transaction_failures_as_http_409():
    repository = DynamoLifecycleV2Repository(
        lifecycle_table=FailingTransactionTable(),
        auth_identities_table=SimpleNamespace(),
    )

    with pytest.raises(LifecycleV2StorageError, match="operation_queue_failed"):
        repository.queue_operation(
            ACCOUNT_ID, OPERATION_ID, "aldp2_exact", 1_800_000_000,
        )


class AccountResourceScanTable:
    def __init__(self, items):
        self.items = deepcopy(items)

    def scan(self, **kwargs):
        assert kwargs["ConsistentRead"] is True
        account_id = kwargs["ExpressionAttributeValues"][":account_id"]
        return {
            "Items": [
                deepcopy(item) for item in self.items
                if item.get("account_id") == account_id
            ],
        }


class RuntimeResourceLifecycleTable:
    name = "lifecycle"

    def __init__(self):
        self.items = [{
            "account_id": ACCOUNT_ID,
            "record_key": "root",
            "record_type": "account_lifecycle_root",
            "state": "active",
            "revision": 2,
        }, {
            "account_id": ACCOUNT_ID,
            "record_key": "resource#app_session_access#legacy",
            "record_type": "account_lifecycle_resource",
            "resource_type": "app_session_access",
            "resource_id": "access#legacy",
            "state": "active",
        }, {
            "account_id": ACCOUNT_ID,
            "record_key": "resource#app_session_refresh#legacy",
            "record_type": "account_lifecycle_resource",
            "resource_type": "app_session_refresh",
            "resource_id": "refresh#legacy",
            "state": "active",
        }]
        self.transactions = []
        self.meta = SimpleNamespace(client=self)

    def query(self, **kwargs):
        assert kwargs["ConsistentRead"] is True
        return {"Items": deepcopy(self.items)}

    def transact_write_items(self, *, TransactItems):
        self.transactions.append(deepcopy(TransactItems))
        for action in TransactItems:
            if "Delete" in action:
                key = action["Delete"]["Key"]
                self.items = [
                    item for item in self.items
                    if not (
                        item.get("account_id") == key["account_id"]
                        and item.get("record_key") == key["record_key"]
                    )
                ]
            elif "Put" in action:
                self.items.append(deepcopy(action["Put"]["Item"]))
            elif "Update" in action:
                values = action["Update"]["ExpressionAttributeValues"]
                root = next(item for item in self.items if item["record_key"] == "root")
                root["revision"] = values[":next"]
                root["updated_at_epoch"] = values[":now"]


def test_preflight_registry_uses_stable_families_for_every_exact_account_session():
    lifecycle = RuntimeResourceLifecycleTable()
    installations = AccountResourceScanTable([
        {
            "installation_id": "installation-current",
            "account_id": ACCOUNT_ID,
            "principal_id": "subject-opaque-123",
        },
        {
            "installation_id": "installation-older",
            "account_id": ACCOUNT_ID,
            "principal_id": "subject-opaque-123",
        },
        {
            "installation_id": "installation-other-account",
            "account_id": "acct_other0123456789abcdef012345",
            "principal_id": "subject-other",
        },
    ])
    sessions = AccountResourceScanTable([
        {
            "token_hash": "access#current",
            "record_type": "access",
            "family_id": "family-current",
            "installation_id": "installation-current",
            "account_id": ACCOUNT_ID,
        },
        {
            "token_hash": "refresh#current-active",
            "record_type": "refresh",
            "state": "active",
            "family_id": "family-current",
            "installation_id": "installation-current",
            "account_id": ACCOUNT_ID,
        },
        {
            "token_hash": "refresh#current-consumed",
            "record_type": "refresh",
            "state": "consumed",
            "family_id": "family-current",
            "installation_id": "installation-current",
            "account_id": ACCOUNT_ID,
        },
        {
            "token_hash": "refresh#older-active",
            "record_type": "refresh",
            "state": "active",
            "family_id": "family-older",
            "installation_id": "installation-older",
            "account_id": ACCOUNT_ID,
        },
        {
            "token_hash": "refresh#other-account",
            "record_type": "refresh",
            "family_id": "family-other",
            "installation_id": "installation-other-account",
            "account_id": "acct_other0123456789abcdef012345",
        },
    ])
    mappings = AccountResourceScanTable([
        {
            "mapping_id": "mapping-current",
            "installation_id": "installation-current",
            "local_profile_source_id": "local-profile-current",
            "account_id": ACCOUNT_ID,
        },
        {
            "mapping_id": "mapping-older",
            "installation_id": "installation-older",
            "local_profile_source_id": "local-profile-older",
            "account_id": ACCOUNT_ID,
        },
        {
            "mapping_id": "mapping-other-account",
            "installation_id": "installation-other-account",
            "local_profile_source_id": "local-profile-other",
            "account_id": "acct_other0123456789abcdef012345",
        },
    ])
    repository = DynamoLifecycleV2Repository(
        lifecycle_table=lifecycle,
        auth_identities_table=SimpleNamespace(),
        installations_table=installations,
        app_sessions_table=sessions,
        profile_mappings_table=mappings,
    )

    repository.ensure_session_resources(
        ACCOUNT_ID,
        subject="subject-opaque-123",
        family_id="family-current",
        installation_id="installation-current",
        access_record_id="access#current",
        now=1_800_000_000,
    )

    puts = [
        item["Put"]["Item"] for item in lifecycle.transactions[0]
        if "Put" in item
    ]
    deletes = [
        item["Delete"]["Key"]["record_key"] for item in lifecycle.transactions[0]
        if "Delete" in item
    ]
    identifiers = {
        (item["resource_type"], item["resource_id"]) for item in puts
    }
    assert identifiers == {
        ("installation", "installation-current"),
        ("installation", "installation-older"),
        ("app_session_family", "family-current"),
        ("app_session_family", "family-older"),
        ("profile_mapping", "mapping-current"),
        ("profile_mapping", "mapping-older"),
    }
    assert deletes == [
        "resource#app_session_access#legacy",
        "resource#app_session_refresh#legacy",
    ]
    mapping_resources = {
        item["resource_id"]: item["attributes"]
        for item in puts if item["resource_type"] == "profile_mapping"
    }
    assert mapping_resources == {
        "mapping-current": {
            "installation_id": "installation-current",
            "local_profile_source_id": "local-profile-current",
        },
        "mapping-older": {
            "installation_id": "installation-older",
            "local_profile_source_id": "local-profile-older",
        },
    }

    revision_after_first_registration = next(
        item["revision"] for item in lifecycle.items if item["record_key"] == "root"
    )
    transactions_after_first_registration = len(lifecycle.transactions)

    # A protected-session rotation adds a new token row in the same immutable
    # family. It must not mutate the lifecycle revision or frozen plan.
    sessions.items.append({
        "token_hash": "access#rotated",
        "record_type": "access",
        "family_id": "family-current",
        "installation_id": "installation-current",
        "account_id": ACCOUNT_ID,
    })
    repository.ensure_session_resources(
        ACCOUNT_ID,
        subject="subject-opaque-123",
        family_id="family-current",
        installation_id="installation-current",
        access_record_id="access#rotated",
        now=1_800_000_001,
    )

    assert len(lifecycle.transactions) == transactions_after_first_registration
    assert next(
        item["revision"] for item in lifecycle.items if item["record_key"] == "root"
    ) == revision_after_first_registration


def test_api_role_can_strongly_enumerate_exact_account_runtime_resources():
    template = (
        __import__("pathlib").Path(__file__).resolve().parents[2]
        / "infra" / "template.yaml"
    ).read_text()
    lifecycle_api = template.split(
        "  KaevoAccountLifecycleV2ApiFunction:", 1,
    )[1].split("  KaevoAccountLifecycleV2ApiLogGroup:", 1)[0]
    assert "Sid: EnumerateExactAccountLifecycleV2RuntimeResources" in lifecycle_api
    assert "- dynamodb:Scan" in lifecycle_api
    assert "- !GetAtt KaevoInstallationsTable.Arn" in lifecycle_api
    assert "- !GetAtt KaevoAppSessionsTable.Arn" in lifecycle_api
    assert "- !GetAtt KaevoProfileMappingsTable.Arn" in lifecycle_api
