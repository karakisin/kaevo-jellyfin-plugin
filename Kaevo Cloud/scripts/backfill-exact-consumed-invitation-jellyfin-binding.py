#!/usr/bin/env python3
"""Backfill one exact consumed-invitation Jellyfin edge without DynamoDB Scan.

The script identifies the retained Owner by exact Cognito email, follows that
Owner's exact household graph, queries only that household's invitation and
membership partitions, and conditionally updates one canonical profile. It
prints counts and boolean evidence only; identifiers and DynamoDB keys are
never emitted.
"""

from __future__ import annotations

import argparse
import hmac
import re
import sys

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError


def same(left: object, right: object) -> bool:
    return hmac.compare_digest(str(left or ""), str(right or ""))


def normalized_user_id(value: object) -> str:
    compact = str(value or "").strip().replace("-", "")
    return compact.lower() if re.fullmatch(r"[0-9a-fA-F]{32}", compact) else ""


def query_all(table, **query):
    records = []
    while True:
        page = table.query(**query)
        records.extend(page.get("Items", []))
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            return records
        query["ExclusiveStartKey"] = last_key


def exact_household_invitations(table, household_id: str):
    candidates = query_all(
        table,
        IndexName="household_id-index",
        KeyConditionExpression=Key("household_id").eq(household_id),
        ConsistentRead=False,
    )
    exact = []
    for candidate in candidates:
        code_hash = str(candidate.get("code_hash") or "")
        if not code_hash:
            continue
        item = table.get_item(
            Key={"code_hash": code_hash}, ConsistentRead=True
        ).get("Item")
        if isinstance(item, dict) and same(item.get("household_id"), household_id):
            exact.append(item)
    return exact


def exact_household_profiles(memberships_table, profiles_table, household_id: str):
    memberships = query_all(
        memberships_table,
        KeyConditionExpression=Key("household_id").eq(household_id),
        ConsistentRead=True,
    )
    records = {}
    for membership in memberships:
        profile_id = str(membership.get("profile_id") or "")
        if not profile_id:
            continue
        profile = profiles_table.get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True
        ).get("Item")
        if (
            isinstance(profile, dict)
            and same(profile.get("profile_id"), profile_id)
            and same(profile.get("household_id"), household_id)
        ):
            records[profile_id] = profile
    return list(records.values())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--api-function", required=True)
    parser.add_argument("--owner-email", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-candidates", type=int, default=1)
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    lambdas = session.client("lambda")
    env = lambdas.get_function_configuration(
        FunctionName=args.api_function
    ).get("Environment", {}).get("Variables", {})
    required = (
        "COGNITO_USER_POOL_ID",
        "PRINCIPALS_TABLE",
        "IDENTITY_PROFILES_TABLE",
        "HOUSEHOLD_INVITATIONS_TABLE",
        "HOUSEHOLD_MEMBERSHIPS_TABLE",
        "HOME_CONNECTORS_TABLE",
    )
    if any(not env.get(name) for name in required):
        print("FOUNDATION_CONFIGURATION_COMPLETE=false")
        return 2

    cognito = session.client("cognito-idp")
    escaped_email = args.owner_email.replace("\\", "\\\\").replace('"', '\\"')
    users = cognito.list_users(
        UserPoolId=env["COGNITO_USER_POOL_ID"],
        Filter=f'email = "{escaped_email}"',
        Limit=2,
    ).get("Users", [])
    print(f"OWNER_MATCH_COUNT={len(users)}")
    if len(users) != 1:
        return 3
    attributes = {
        str(item.get("Name") or ""): str(item.get("Value") or "")
        for item in users[0].get("Attributes", [])
    }
    owner_subject = attributes.get("sub", "")
    if not owner_subject:
        print("OWNER_AUTHORITY_VALID=false")
        return 3

    resource = session.resource("dynamodb")
    principals = resource.Table(env["PRINCIPALS_TABLE"])
    profiles = resource.Table(env["IDENTITY_PROFILES_TABLE"])
    invitations = resource.Table(env["HOUSEHOLD_INVITATIONS_TABLE"])
    memberships = resource.Table(env["HOUSEHOLD_MEMBERSHIPS_TABLE"])
    connectors = resource.Table(env["HOME_CONNECTORS_TABLE"])

    owner = principals.get_item(
        Key={"principal_id": owner_subject}, ConsistentRead=True
    ).get("Item")
    household_id = str((owner or {}).get("household_id") or "")
    owner_role = str(
        (owner or {}).get("household_access_role")
        or (owner or {}).get("canonical_role")
        or (owner or {}).get("role")
        or ""
    ).lower()
    owner_valid = bool(
        isinstance(owner, dict)
        and owner.get("state") == "active"
        and not bool(owner.get("revoked"))
        and household_id
        and owner_role == "owner"
    )
    print(f"OWNER_AUTHORITY_VALID={str(owner_valid).lower()}")
    if not owner_valid:
        return 4

    invitation_records = exact_household_invitations(invitations, household_id)
    profile_records = exact_household_profiles(memberships, profiles, household_id)
    profiles_by_id = {
        str(item.get("profile_id") or ""): item for item in profile_records
    }
    candidates = []
    diagnostics = {
        "CONSUMED_ACTIVE_BINDING_COUNT": 0,
        "BINDING_WITH_CANONICAL_PROFILE_COUNT": 0,
        "BINDING_WITH_MEMBER_MATCH_COUNT": 0,
        "BINDING_WITH_OWNER_MATCH_COUNT": 0,
        "BINDING_WITH_UNBOUND_PROFILE_COUNT": 0,
        "BINDING_WITH_ACTIVE_CONNECTOR_COUNT": 0,
    }
    for invitation in invitation_records:
        profile_id = str(invitation.get("profile_id") or "")
        member_subject = str(invitation.get("member_principal_id") or "")
        connector_id = str(invitation.get("jellyfin_connector_id") or "")
        user_id = normalized_user_id(invitation.get("jellyfin_user_id"))
        profile = profiles_by_id.get(profile_id)
        consumed_active = bool(
            invitation.get("state") == "consumed"
            and invitation.get("jellyfin_binding_state") == "active"
            and profile_id
            and member_subject
            and connector_id
            and user_id
        )
        if consumed_active:
            diagnostics["CONSUMED_ACTIVE_BINDING_COUNT"] += 1
        canonical_profile = bool(
            consumed_active
            and isinstance(profile, dict)
            and profile.get("state") == "active"
            and same(profile.get("household_id"), household_id)
        )
        if canonical_profile:
            diagnostics["BINDING_WITH_CANONICAL_PROFILE_COUNT"] += 1
        member_match = bool(
            canonical_profile
            and same(profile.get("member_principal_id"), member_subject)
        )
        if member_match:
            diagnostics["BINDING_WITH_MEMBER_MATCH_COUNT"] += 1
        owner_match = bool(
            member_match
            and same(profile.get("owner_principal_id"), owner_subject)
            and not same(member_subject, owner_subject)
        )
        if owner_match:
            diagnostics["BINDING_WITH_OWNER_MATCH_COUNT"] += 1
        unbound_profile = bool(
            owner_match
            and str(profile.get("jellyfin_binding_state") or "") != "active"
            and not normalized_user_id(profile.get("jellyfin_user_id"))
            and not str(profile.get("jellyfin_connector_id") or "")
        )
        if unbound_profile:
            diagnostics["BINDING_WITH_UNBOUND_PROFILE_COUNT"] += 1
        if not (
            consumed_active and canonical_profile and member_match
            and owner_match and unbound_profile
        ):
            continue

        connector = connectors.get_item(
            Key={"connector_id": connector_id}, ConsistentRead=True
        ).get("Item")
        connector_valid = bool(
            isinstance(connector, dict)
            and same(connector.get("connector_id"), connector_id)
            and same(connector.get("household_id"), household_id)
            and connector.get("state") == "active"
            and connector.get("binding_status") == "bound"
            and connector.get("auth_state") == "v3_active"
            and not bool(connector.get("revoked"))
        )
        if connector_valid:
            diagnostics["BINDING_WITH_ACTIVE_CONNECTOR_COUNT"] += 1
            candidates.append((profile, invitation, connector_id, user_id))

    print(f"HOUSEHOLD_PROFILE_COUNT={len(profile_records)}")
    for label, count in diagnostics.items():
        print(f"{label}={count}")
    print(f"CANDIDATE_COUNT={len(candidates)}")
    if len(candidates) != args.expected_candidates:
        print("EXACT_BACKFILL_SAFE=false")
        return 5

    profile, invitation, connector_id, user_id = candidates[0]
    profile_id = str(profile["profile_id"])
    member_subject = str(profile["member_principal_id"])

    conflicts = 0
    for other in profile_records:
        if str(other.get("profile_id") or "") == profile_id:
            continue
        if (
            other.get("jellyfin_binding_state") == "active"
            and same(other.get("jellyfin_connector_id"), connector_id)
            and same(normalized_user_id(other.get("jellyfin_user_id")), user_id)
        ):
            conflicts += 1
    for other in invitation_records:
        if str(other.get("code_hash") or "") == str(invitation.get("code_hash") or ""):
            continue
        if (
            other.get("state") in {"pending", "consumed"}
            and other.get("jellyfin_binding_state") == "active"
            and same(other.get("jellyfin_connector_id"), connector_id)
            and same(normalized_user_id(other.get("jellyfin_user_id")), user_id)
        ):
            conflicts += 1
    unique = conflicts == 0
    print("CANDIDATE_AUTHORITY_EXACT=true")
    print(f"CANDIDATE_PROVIDER_EDGE_UNIQUE={str(unique).lower()}")
    print(f"EXACT_BACKFILL_SAFE={str(unique).lower()}")
    if not unique:
        return 6
    if not args.apply:
        print("WRITE_APPLIED=false")
        return 0

    try:
        profiles.update_item(
            Key={"profile_id": profile_id},
            UpdateExpression=(
                "SET jellyfin_connector_id = :connector_id, "
                "jellyfin_user_id = :user_id, "
                "jellyfin_binding_state = :binding_state, "
                "jellyfin_binding_updated_at = :updated_at"
            ),
            ConditionExpression=(
                "household_id = :household_id AND "
                "member_principal_id = :member_subject AND #state = :active AND "
                "attribute_not_exists(jellyfin_connector_id) AND "
                "attribute_not_exists(jellyfin_user_id) AND "
                "attribute_not_exists(jellyfin_binding_state)"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":connector_id": connector_id,
                ":user_id": user_id,
                ":binding_state": "active",
                ":updated_at": str(invitation.get("jellyfin_binding_updated_at") or invitation.get("consumed_at") or ""),
                ":household_id": household_id,
                ":member_subject": member_subject,
                ":active": "active",
            },
        )
    except ClientError as error:
        if str(error.response.get("Error", {}).get("Code") or "") == "ConditionalCheckFailedException":
            print("WRITE_APPLIED=false")
            print("WRITE_CONDITION_MATCHED=false")
            return 7
        raise

    exact = profiles.get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True
    ).get("Item")
    verified = bool(
        isinstance(exact, dict)
        and exact.get("state") == "active"
        and same(exact.get("household_id"), household_id)
        and same(exact.get("member_principal_id"), member_subject)
        and exact.get("jellyfin_binding_state") == "active"
        and same(exact.get("jellyfin_connector_id"), connector_id)
        and same(normalized_user_id(exact.get("jellyfin_user_id")), user_id)
    )
    print("WRITE_APPLIED=true")
    print(f"EXACT_ABSENCE_REPLACED_WITH_BINDING={str(verified).lower()}")
    return 0 if verified else 8


if __name__ == "__main__":
    sys.exit(main())
