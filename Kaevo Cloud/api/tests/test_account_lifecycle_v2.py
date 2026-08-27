import pytest

from account_lifecycle_v2 import (
    LifecycleV2Error,
    freeze_deletion_plan,
    require_phase_transition,
)


ACCOUNT_ID = "acct_0123456789abcdef01234567"
OPERATION_ID = "ald2_0123456789abcdef0123456789abcdef"


def registry(*, provider_state="enabled", duplicate_profiles=False):
    records = [{
        "record_type": "account_lifecycle_root",
        "account_id": ACCOUNT_ID,
        "schema_version": 2,
        "revision": 7,
        "state": "active",
        "account_role": "owner",
        "owner_deletion_state": "sole_member",
    }]
    resources = [
        ("account#self", "account", ACCOUNT_ID, {}),
        ("auth#cognito", "cognito_subject", "subject-immutable", {}),
        ("household#owner", "household", "hh_immutable", {}),
        ("profile#owner", "cloud_profile", "profile_immutable", {}),
        ("binding#provider", "provider_binding", "provider_binding_immutable", {
            "two_way_profile_deletion": provider_state,
            "connector_id": "connector_immutable",
            "jellyfin_user_id": "jellyfin_user_immutable",
            "seerr_user_id": 42,
        }),
    ]
    if duplicate_profiles:
        resources.append(("profile#legacy", "identity_profile", "profile_immutable", {}))
    records.extend({
        "record_type": "account_lifecycle_resource",
        "account_id": ACCOUNT_ID,
        "resource_key": key,
        "resource_type": kind,
        "resource_id": identifier,
        "state": "active",
        "attributes": attributes,
    } for key, kind, identifier, attributes in resources)
    return records


def test_plan_is_server_owned_and_ignores_device_profile_projection():
    plan = freeze_deletion_plan(
        operation_id=OPERATION_ID,
        authenticated_account_id=ACCOUNT_ID,
        requested_scope="everything",
        registry_records=registry(duplicate_profiles=True),
    )
    assert plan.profile_ids == ("profile_immutable",)
    assert plan.provider_binding_ids == ("provider_binding_immutable",)
    assert plan.provider_capability.value == "enabled"


def test_everything_reports_disabled_provider_deletion_without_losing_dynamic_status():
    plan = freeze_deletion_plan(
        operation_id=OPERATION_ID,
        authenticated_account_id=ACCOUNT_ID,
        requested_scope="everything",
        registry_records=registry(provider_state="disabled"),
    )

    assert plan.public_summary()["provider_capability"] == "disabled"
    assert plan.public_summary()["can_confirm"] is False


def test_kaevo_only_scope_is_retired_for_every_new_plan():
    with pytest.raises(LifecycleV2Error, match="deletion_scope_retired"):
        freeze_deletion_plan(
            operation_id=OPERATION_ID,
            authenticated_account_id=ACCOUNT_ID,
            requested_scope="kaevo_only",
            registry_records=registry(provider_state="disabled"),
        )


def test_everything_is_available_when_no_provider_accounts_exist():
    records = [
        item for item in registry(provider_state="enabled")
        if item.get("resource_type") != "provider_binding"
    ]
    plan = freeze_deletion_plan(
        operation_id=OPERATION_ID,
        authenticated_account_id=ACCOUNT_ID,
        requested_scope="everything",
        registry_records=records,
    )

    assert plan.public_summary()["provider_capability"] == "not_applicable"
    assert plan.public_summary()["can_confirm"] is True


def test_plan_rejects_email_or_display_name_as_authority_fields():
    records = registry()
    records[1]["email"] = "not-an-authority@example.com"
    with pytest.raises(LifecycleV2Error, match="presentation_field_used_as_authority"):
        freeze_deletion_plan(
            operation_id=OPERATION_ID,
            authenticated_account_id=ACCOUNT_ID,
            requested_scope="everything",
            registry_records=records,
        )


def test_owner_deletion_requires_a_transactional_sole_member_guard():
    records = registry()
    records[0]["owner_deletion_state"] = "ownership_transfer_required"

    with pytest.raises(LifecycleV2Error, match="ownership_transfer_required"):
        freeze_deletion_plan(
            operation_id=OPERATION_ID,
            authenticated_account_id=ACCOUNT_ID,
            requested_scope="everything",
            registry_records=records,
        )


def test_member_deletion_cannot_claim_the_shared_household_as_its_resource():
    records = registry()
    records[0]["account_role"] = "member"
    records[0]["owner_deletion_state"] = "member"

    with pytest.raises(LifecycleV2Error, match="member_cannot_own_household_resource"):
        freeze_deletion_plan(
            operation_id=OPERATION_ID,
            authenticated_account_id=ACCOUNT_ID,
            requested_scope="everything",
            registry_records=records,
        )


def test_member_can_delete_only_its_account_graph():
    records = [
        item for item in registry()
        if item.get("resource_type") != "household"
    ]
    records[0]["account_role"] = "member"
    records[0]["owner_deletion_state"] = "member"

    plan = freeze_deletion_plan(
        operation_id=OPERATION_ID,
        authenticated_account_id=ACCOUNT_ID,
        requested_scope="everything",
        registry_records=records,
    )

    assert all(resource.resource_type != "household" for resource in plan.resources)


def test_plan_digest_is_stable_for_the_same_frozen_registry():
    first = freeze_deletion_plan(
        operation_id=OPERATION_ID,
        authenticated_account_id=ACCOUNT_ID,
        requested_scope="everything",
        registry_records=registry(),
    )
    second = freeze_deletion_plan(
        operation_id=OPERATION_ID,
        authenticated_account_id=ACCOUNT_ID,
        requested_scope="everything",
        registry_records=reversed(registry()),
    )
    assert first.plan_digest == second.plan_digest


def test_plan_digest_is_semantic_and_stable_across_reissued_operations():
    first = freeze_deletion_plan(
        operation_id="ald2_11111111111111111111111111111111",
        authenticated_account_id=ACCOUNT_ID,
        requested_scope="everything",
        registry_records=registry(),
    )
    reissued = freeze_deletion_plan(
        operation_id="ald2_22222222222222222222222222222222",
        authenticated_account_id=ACCOUNT_ID,
        requested_scope="everything",
        registry_records=registry(),
    )

    assert first.operation_id != reissued.operation_id
    assert first.plan_digest == reissued.plan_digest


def test_operation_state_machine_cannot_skip_absence_proof():
    assert require_phase_transition("queued", "deleting_seerr").value == "deleting_seerr"
    assert require_phase_transition(
        "retry_required", "deleting_kaevo_graph",
    ).value == "deleting_kaevo_graph"
    with pytest.raises(LifecycleV2Error, match="operation_phase_transition_invalid"):
        require_phase_transition("deleting_seerr", "completed")
