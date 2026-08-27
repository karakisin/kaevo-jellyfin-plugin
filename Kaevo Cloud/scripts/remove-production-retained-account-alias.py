#!/usr/bin/env python3
"""Remove one disabled, revoked Cognito alias from a retained Production account.

This one-time repair is intentionally narrower than account deletion. It keeps
the retained account, household, and profile, while deleting only an older
Cognito subject whose AuthIdentity is already revoked and whose principal and
membership duplicate the retained subject's exact authority. The command is a
read-only snapshot unless ``--apply`` is supplied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Mapping

import boto3
from boto3.dynamodb.conditions import Attr
from boto3.dynamodb.types import TypeSerializer


SOURCE_ROOT = Path(__file__).parents[1] / "api" / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from account_foundation import provider_subject_key  # noqa: E402
from security_audit import load_audit_key, prepare_audit_item  # noqa: E402


class AliasCleanupError(RuntimeError):
    """Raised when the frozen alias cleanup scope is not exact."""


def _matches_authority(
    record: Mapping[str, Any],
    *,
    subject: str,
    account_id: str,
    household_id: str,
    profile_id: str | None,
) -> bool:
    return (
        str(record.get("principal_id") or "") == subject
        and str(record.get("account_id") or "") == account_id
        and str(record.get("household_id") or "") == household_id
        and (
            profile_id is None
            or str(record.get("profile_id") or "") == profile_id
        )
    )


def build_alias_cleanup_transaction(
    *,
    alias_identity: Mapping[str, Any],
    alias_principal: Mapping[str, Any],
    alias_membership: Mapping[str, Any],
    retained_identity: Mapping[str, Any],
    retained_principal: Mapping[str, Any],
    retained_membership: Mapping[str, Any],
    identity_profile: Mapping[str, Any],
    identity_household: Mapping[str, Any],
    alias_sessions: list[Mapping[str, Any]],
    auth_identities_table: str,
    principals_table: str,
    identity_memberships_table: str,
    app_sessions_table: str,
    security_audit_table: str,
    retained_subject: str,
    alias_subject: str,
    account_id: str,
    household_id: str,
    profile_id: str,
    audit_item: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if not all((
        auth_identities_table, principals_table, identity_memberships_table,
        app_sessions_table, security_audit_table, retained_subject,
        alias_subject, account_id, household_id, profile_id,
    )) or retained_subject == alias_subject:
        raise AliasCleanupError("incomplete or overlapping cleanup scope")

    alias_key = provider_subject_key("cognito", alias_subject)
    retained_key = provider_subject_key("cognito", retained_subject)
    if any((
        str(alias_identity.get("auth_identity_key") or "") != alias_key,
        alias_identity.get("entity_type") != "AuthIdentity",
        alias_identity.get("status") != "revoked",
        str(alias_identity.get("account_id") or "") != account_id,
        str(retained_identity.get("auth_identity_key") or "") != retained_key,
        retained_identity.get("entity_type") != "AuthIdentity",
        retained_identity.get("status") != "active",
        str(retained_identity.get("account_id") or "") != account_id,
    )):
        raise AliasCleanupError("AuthIdentity authority does not match")
    if not _matches_authority(
        alias_principal, subject=alias_subject, account_id=account_id,
        household_id=household_id, profile_id=None,
    ) or not _matches_authority(
        retained_principal, subject=retained_subject, account_id=account_id,
        household_id=household_id, profile_id=None,
    ):
        raise AliasCleanupError("principal authority does not match")
    if not _matches_authority(
        alias_membership, subject=alias_subject, account_id=account_id,
        household_id=household_id, profile_id=profile_id,
    ) or not _matches_authority(
        retained_membership, subject=retained_subject, account_id=account_id,
        household_id=household_id, profile_id=profile_id,
    ):
        raise AliasCleanupError("identity membership authority does not match")
    if any((
        str(identity_profile.get("profile_id") or "") != profile_id,
        str(identity_profile.get("account_id") or "") != account_id,
        str(identity_profile.get("household_id") or "") != household_id,
        str(identity_profile.get("owner_principal_id") or "") != retained_subject,
        identity_profile.get("state") != "active",
        str(identity_household.get("household_id") or "") != household_id,
        str(identity_household.get("owner_principal_id") or "") != retained_subject,
        identity_household.get("state") != "active",
    )):
        raise AliasCleanupError("canonical owner pointer does not match retained subject")
    if not str(audit_item.get("event_id") or ""):
        raise AliasCleanupError("audit item is incomplete")

    session_keys: list[str] = []
    for session in alias_sessions:
        token_hash = str(session.get("token_hash") or "")
        session_subject = str(
            session.get("principal_id")
            or session.get("subject")
            or session.get("owner_principal_id")
            or ""
        )
        if any((
            not token_hash,
            str(session.get("account_id") or "") != account_id,
            session_subject != alias_subject,
            str(session.get("record_type") or "") not in {"access", "refresh"},
        )):
            raise AliasCleanupError("alias app-session authority does not match")
        session_keys.append(token_hash)
    if len(set(session_keys)) != len(session_keys):
        raise AliasCleanupError("alias app-session key is duplicated")
    # DynamoDB transactions are limited to 100 actions. Keep four slots for
    # the three exact alias records plus the audit event and fail closed rather
    # than partially revoking an oversized session family.
    if len(session_keys) > 96:
        raise AliasCleanupError("alias app-session cleanup exceeds transaction limit")

    transaction = [
        {"Delete": {
            "TableName": auth_identities_table,
            "Key": {"auth_identity_key": alias_key},
            "ConditionExpression": (
                "entity_type = :entity AND #status = :revoked "
                "AND account_id = :account_id"
            ),
            "ExpressionAttributeNames": {"#status": "status"},
            "ExpressionAttributeValues": {
                ":entity": "AuthIdentity", ":revoked": "revoked",
                ":account_id": account_id,
            },
        }},
        {"Delete": {
            "TableName": principals_table,
            "Key": {"principal_id": alias_subject},
            "ConditionExpression": (
                "account_id = :account_id AND household_id = :household_id"
            ),
            "ExpressionAttributeValues": {
                ":account_id": account_id, ":household_id": household_id,
            },
        }},
        {"Delete": {
            "TableName": identity_memberships_table,
            "Key": {"principal_id": alias_subject},
            "ConditionExpression": (
                "account_id = :account_id AND household_id = :household_id "
                "AND profile_id = :profile_id"
            ),
            "ExpressionAttributeValues": {
                ":account_id": account_id, ":household_id": household_id,
                ":profile_id": profile_id,
            },
        }},
    ]
    transaction.extend({"Delete": {
        "TableName": app_sessions_table,
        "Key": {"token_hash": token_hash},
        "ConditionExpression": (
            "account_id = :account_id AND "
            "(principal_id = :alias OR #subject = :alias "
            "OR owner_principal_id = :alias)"
        ),
        "ExpressionAttributeNames": {"#subject": "subject"},
        "ExpressionAttributeValues": {
            ":account_id": account_id,
            ":alias": alias_subject,
        },
    }} for token_hash in session_keys)
    transaction.append({"Put": {
        "TableName": security_audit_table,
        "Item": dict(audit_item),
        "ConditionExpression": "attribute_not_exists(event_id)",
    }})
    return transaction


def _serialize_transaction(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    serializer = TypeSerializer()
    result: list[dict[str, Any]] = []
    for action in items:
        name, body = next(iter(action.items()))
        converted = dict(body)
        for field in ("Item", "Key", "ExpressionAttributeValues"):
            if field in converted:
                converted[field] = {
                    key: serializer.serialize(value)
                    for key, value in converted[field].items()
                }
        result.append({name: converted})
    return result


def _single_cognito_user(cognito: Any, pool_id: str, subject: str) -> dict[str, Any]:
    escaped = subject.replace("\\", "\\\\").replace('"', '\\"')
    users = cognito.list_users(
        UserPoolId=pool_id, Filter=f'sub = "{escaped}"', Limit=2,
    ).get("Users", [])
    if len(users) != 1:
        raise AliasCleanupError("Cognito subject is absent or ambiguous")
    username = str(users[0].get("Username") or "")
    if not username:
        raise AliasCleanupError("Cognito username is missing")
    result = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    result["Username"] = username
    return result


def _attributes(user: Mapping[str, Any]) -> dict[str, str]:
    return {
        str(item.get("Name") or ""): str(item.get("Value") or "")
        for item in user.get("UserAttributes", [])
        if isinstance(item, Mapping)
    }


def _alias_sessions(table: Any, alias_subject: str) -> list[dict[str, Any]]:
    condition = (
        Attr("principal_id").eq(alias_subject)
        | Attr("subject").eq(alias_subject)
        | Attr("owner_principal_id").eq(alias_subject)
    )
    response = table.scan(FilterExpression=condition)
    sessions = list(response.get("Items") or [])
    while response.get("LastEvaluatedKey"):
        response = table.scan(
            FilterExpression=condition,
            ExclusiveStartKey=response["LastEvaluatedKey"],
        )
        sessions.extend(response.get("Items") or [])
    return sessions


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", required=True)
    parser.add_argument("--api-function", required=True)
    parser.add_argument("--user-pool-id", required=True)
    parser.add_argument("--auth-identities-table", required=True)
    parser.add_argument("--principals-table", required=True)
    parser.add_argument("--identity-memberships-table", required=True)
    parser.add_argument("--app-sessions-table", required=True)
    parser.add_argument("--identity-profiles-table", required=True)
    parser.add_argument("--identity-households-table", required=True)
    parser.add_argument("--security-audit-table", required=True)
    parser.add_argument("--retained-subject", required=True)
    parser.add_argument("--alias-subject", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--household-id", required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.snapshot.exists():
        raise AliasCleanupError("snapshot already exists; refusing to overwrite")

    dynamodb = boto3.resource("dynamodb", region_name=args.region)
    cognito = boto3.client("cognito-idp", region_name=args.region)
    alias_key = provider_subject_key("cognito", args.alias_subject)
    retained_key = provider_subject_key("cognito", args.retained_subject)
    records = {
        "alias_identity": dynamodb.Table(args.auth_identities_table).get_item(
            Key={"auth_identity_key": alias_key}, ConsistentRead=True,
        ).get("Item"),
        "alias_principal": dynamodb.Table(args.principals_table).get_item(
            Key={"principal_id": args.alias_subject}, ConsistentRead=True,
        ).get("Item"),
        "alias_membership": dynamodb.Table(args.identity_memberships_table).get_item(
            Key={"principal_id": args.alias_subject}, ConsistentRead=True,
        ).get("Item"),
        "retained_identity": dynamodb.Table(args.auth_identities_table).get_item(
            Key={"auth_identity_key": retained_key}, ConsistentRead=True,
        ).get("Item"),
        "retained_principal": dynamodb.Table(args.principals_table).get_item(
            Key={"principal_id": args.retained_subject}, ConsistentRead=True,
        ).get("Item"),
        "retained_membership": dynamodb.Table(args.identity_memberships_table).get_item(
            Key={"principal_id": args.retained_subject}, ConsistentRead=True,
        ).get("Item"),
        "identity_profile": dynamodb.Table(args.identity_profiles_table).get_item(
            Key={"profile_id": args.profile_id}, ConsistentRead=True,
        ).get("Item"),
        "identity_household": dynamodb.Table(args.identity_households_table).get_item(
            Key={"household_id": args.household_id}, ConsistentRead=True,
        ).get("Item"),
        "alias_sessions": _alias_sessions(
            dynamodb.Table(args.app_sessions_table), args.alias_subject,
        ),
    }
    exact_record_names = (
        "alias_identity", "alias_principal", "alias_membership",
        "retained_identity", "retained_principal", "retained_membership",
        "identity_profile", "identity_household",
    )
    if not all(isinstance(records[name], Mapping) for name in exact_record_names):
        raise AliasCleanupError("required DynamoDB record is missing")

    alias_user = _single_cognito_user(cognito, args.user_pool_id, args.alias_subject)
    retained_user = _single_cognito_user(cognito, args.user_pool_id, args.retained_subject)
    alias_attributes = _attributes(alias_user)
    retained_attributes = _attributes(retained_user)
    alias_email = alias_attributes.get("email", "").strip().lower()
    retained_email = retained_attributes.get("email", "").strip().lower()
    if any((
        not alias_email, not retained_email, alias_email == retained_email,
        alias_attributes.get("email_verified", "").lower() != "true",
        retained_attributes.get("email_verified", "").lower() != "true",
        alias_user.get("Enabled") is not False,
        retained_user.get("Enabled") is not True,
    )):
        raise AliasCleanupError("Cognito retained/alias boundary does not match")
    if str(records["alias_identity"].get("normalized_email") or "").lower() not in {"", alias_email}:
        raise AliasCleanupError("revoked AuthIdentity email does not match Cognito")

    variables = boto3.client("lambda", region_name=args.region).get_function_configuration(
        FunctionName=args.api_function,
    ).get("Environment", {}).get("Variables", {})
    for name in ("KAEVO_ENV", "EXPECTED_COGNITO_ISSUER", "AUDIT_REFERENCE_SECRET_ARN"):
        value = str(variables.get(name) or "")
        if not value:
            raise AliasCleanupError(f"missing audit environment: {name}")
        os.environ[name] = value
    audit_key = load_audit_key(client=boto3.client("secretsmanager", region_name=args.region))
    now = int(time.time())
    audit_item = prepare_audit_item(
        scope_id=args.household_id,
        event_type="retained_account_alias_removed",
        actor_subject=args.retained_subject,
        target_id=args.alias_subject,
        target_type="cognito_alias_subject",
        result="success",
        reason_code="account_lifecycle_v2_legacy_alias_cleanup",
        request_id=f"{args.alias_subject}:{now}",
        now=now,
        key=audit_key,
    )
    transaction = build_alias_cleanup_transaction(
        **records,
        auth_identities_table=args.auth_identities_table,
        principals_table=args.principals_table,
        identity_memberships_table=args.identity_memberships_table,
        app_sessions_table=args.app_sessions_table,
        security_audit_table=args.security_audit_table,
        retained_subject=args.retained_subject,
        alias_subject=args.alias_subject,
        account_id=args.account_id,
        household_id=args.household_id,
        profile_id=args.profile_id,
        audit_item=audit_item,
    )
    snapshot = {
        "records": records,
        "retained_subject": args.retained_subject,
        "alias_subject": args.alias_subject,
        "retained_email_sha256": hashlib.sha256(retained_email.encode()).hexdigest(),
        "alias_email_sha256": hashlib.sha256(alias_email.encode()).hexdigest(),
        "alias_cognito_username": str(alias_user.get("Username") or ""),
        "alias_cognito_enabled": alias_user.get("Enabled"),
        "alias_sessions": records["alias_sessions"],
    }
    args.snapshot.parent.mkdir(parents=True, exist_ok=True)
    args.snapshot.write_text(json.dumps(snapshot, indent=2, sort_keys=True, default=str) + "\n")
    print(
        "RETAINED_ACCOUNT_ALIAS_CLEANUP_PLAN_APPROVED "
        f"writes={len(transaction)} sessions={len(records['alias_sessions'])} "
        f"apply={str(args.apply).lower()}"
    )
    if not args.apply:
        return

    username = str(alias_user.get("Username") or "")
    cognito.admin_delete_user(UserPoolId=args.user_pool_id, Username=username)
    if cognito.list_users(
        UserPoolId=args.user_pool_id,
        Filter=f'sub = "{args.alias_subject}"',
        Limit=2,
    ).get("Users"):
        raise AliasCleanupError("Cognito subject absence was not confirmed")
    escaped_email = alias_email.replace("\\", "\\\\").replace('"', '\\"')
    if cognito.list_users(
        UserPoolId=args.user_pool_id,
        Filter=f'email = "{escaped_email}"',
        Limit=2,
    ).get("Users"):
        raise AliasCleanupError("Cognito email absence was not confirmed")
    boto3.client("dynamodb", region_name=args.region).transact_write_items(
        TransactItems=_serialize_transaction(transaction),
    )
    print("RETAINED_ACCOUNT_ALIAS_CLEANUP_APPLIED cognito_email_absent=true")


if __name__ == "__main__":
    main()
