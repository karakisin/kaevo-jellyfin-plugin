from account_lifecycle_v2_membership import (
    member_registry_records,
    owner_shared_guard_transaction_action,
)


def test_member_registry_contains_only_member_owned_resources():
    records = member_registry_records(
        account_id="acct_member0123456789abcdef",
        subject="subject-member",
        auth_identity_key="cognito#subject-member",
        household_id="hh_owner0123456789abcdef",
        membership_id="membership-member",
        profile_id="profile_member0123456789abcdef",
        profile_binding_id="binding-member",
        owner_account_id="acct_owner0123456789abcdef",
        now=1_800_000_000,
    )

    assert records[0]["account_role"] == "member"
    assert records[0]["owner_deletion_state"] == "member"
    resource_types = {
        item["resource_type"] for item in records
        if item.get("record_type") == "account_lifecycle_resource"
    }
    assert "household" not in resource_types
    assert resource_types == {
        "account", "auth_identity", "cognito_subject", "principal",
        "identity_membership", "household_membership", "identity_profile",
        "cloud_profile", "profile_binding",
        "owner_lifecycle_guard",
    }


def test_owner_guard_changes_in_the_same_transaction_revision():
    action = owner_shared_guard_transaction_action(
        table_name="lifecycle",
        owner_account_id="acct_owner0123456789abcdef",
        expected_revision=7,
        now=1_800_000_000,
    )["Update"]

    assert action["Key"]["record_key"] == "root"
    assert action["ExpressionAttributeValues"][":current"] == 7
    assert action["ExpressionAttributeValues"][":next"] == 8
    assert action["ExpressionAttributeValues"][":shared"] == "ownership_transfer_required"
