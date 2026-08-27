import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[2] / "scripts" / "remove-production-retained-account-alias.py"
SPEC = importlib.util.spec_from_file_location("remove_production_retained_account_alias", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


ACCOUNT = "acct_1"
HOUSEHOLD = "hh_1"
PROFILE = "profile_1"
RETAINED = "11111111-1111-1111-1111-111111111111"
ALIAS = "22222222-2222-2222-2222-222222222222"


def identity(subject, status):
    return {
        "auth_identity_key": MODULE.provider_subject_key("cognito", subject),
        "entity_type": "AuthIdentity",
        "status": status,
        "account_id": ACCOUNT,
    }


def principal(subject):
    return {
        "principal_id": subject,
        "account_id": ACCOUNT,
        "household_id": HOUSEHOLD,
    }


def membership(subject, profile=PROFILE):
    return {
        "principal_id": subject,
        "account_id": ACCOUNT,
        "household_id": HOUSEHOLD,
        "profile_id": profile,
    }


def session(token_hash="access#one", subject=ALIAS, account=ACCOUNT, record_type="access"):
    return {
        "token_hash": token_hash,
        "record_type": record_type,
        "state": "active",
        "account_id": account,
        "principal_id": subject,
    }


def build(**overrides):
    values = {
        "alias_identity": identity(ALIAS, "revoked"),
        "alias_principal": principal(ALIAS),
        "alias_membership": membership(ALIAS),
        "retained_identity": identity(RETAINED, "active"),
        "retained_principal": principal(RETAINED),
        "retained_membership": membership(RETAINED),
        "identity_profile": {
            "profile_id": PROFILE,
            "account_id": ACCOUNT,
            "household_id": HOUSEHOLD,
            "owner_principal_id": RETAINED,
            "state": "active",
        },
        "identity_household": {
            "household_id": HOUSEHOLD,
            "owner_principal_id": RETAINED,
            "state": "active",
        },
        "alias_sessions": [
            session(),
            session("refresh#two", record_type="refresh"),
        ],
        "auth_identities_table": "auth",
        "principals_table": "principals",
        "identity_memberships_table": "memberships",
        "app_sessions_table": "sessions",
        "security_audit_table": "audit",
        "retained_subject": RETAINED,
        "alias_subject": ALIAS,
        "account_id": ACCOUNT,
        "household_id": HOUSEHOLD,
        "profile_id": PROFILE,
        "audit_item": {"event_id": "event-1"},
    }
    values.update(overrides)
    return MODULE.build_alias_cleanup_transaction(**values)


def test_cleanup_deletes_only_revoked_alias_records_and_writes_audit():
    transaction = build()

    assert len(transaction) == 6
    assert transaction[0]["Delete"]["Key"] == {
        "auth_identity_key": MODULE.provider_subject_key("cognito", ALIAS),
    }
    assert transaction[1]["Delete"]["Key"] == {"principal_id": ALIAS}
    assert transaction[2]["Delete"]["Key"] == {"principal_id": ALIAS}
    assert transaction[3]["Delete"]["Key"] == {"token_hash": "access#one"}
    assert transaction[4]["Delete"]["Key"] == {"token_hash": "refresh#two"}
    assert transaction[5]["Put"]["TableName"] == "audit"


def test_cleanup_rejects_an_active_alias_identity():
    with pytest.raises(MODULE.AliasCleanupError, match="AuthIdentity authority"):
        build(alias_identity=identity(ALIAS, "active"))


def test_cleanup_rejects_a_cross_profile_alias_membership():
    with pytest.raises(MODULE.AliasCleanupError, match="membership authority"):
        build(alias_membership=membership(ALIAS, profile="profile_other"))


def test_cleanup_rejects_the_retained_subject_as_the_alias():
    with pytest.raises(MODULE.AliasCleanupError, match="overlapping"):
        build(alias_subject=RETAINED)


def test_cleanup_rejects_an_alias_that_still_owns_the_profile():
    with pytest.raises(MODULE.AliasCleanupError, match="canonical owner pointer"):
        build(identity_profile={
            "profile_id": PROFILE,
            "account_id": ACCOUNT,
            "household_id": HOUSEHOLD,
            "owner_principal_id": ALIAS,
        "state": "active",
    })


def test_cleanup_rejects_a_session_owned_by_another_subject():
    with pytest.raises(MODULE.AliasCleanupError, match="app-session authority"):
        build(alias_sessions=[session(subject=RETAINED)])


def test_cleanup_rejects_a_session_owned_by_another_account():
    with pytest.raises(MODULE.AliasCleanupError, match="app-session authority"):
        build(alias_sessions=[session(account="acct_other")])


def test_cleanup_rejects_more_sessions_than_one_transaction_can_delete():
    sessions = [session(f"access#{index}") for index in range(97)]
    with pytest.raises(MODULE.AliasCleanupError, match="transaction limit"):
        build(alias_sessions=sessions)


def test_cleanup_serializes_native_values_for_the_dynamodb_client():
    serialized = MODULE._serialize_transaction(build(alias_sessions=[]))

    assert serialized[0]["Delete"]["Key"]["auth_identity_key"]["S"]
    assert serialized[0]["Delete"]["ExpressionAttributeValues"][":revoked"] == {"S": "revoked"}
    assert serialized[-1]["Put"]["Item"]["event_id"] == {"S": "event-1"}
