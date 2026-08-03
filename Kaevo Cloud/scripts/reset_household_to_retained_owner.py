#!/usr/bin/env python3
"""Reset one verified Kaevo household to its retained Owner without DynamoDB Scan.

This is an operator-only recovery tool.  It accepts the retained Cognito email,
derives the Owner's authority graph from exact keys, and refuses to proceed if
that graph is ambiguous.  It never prints identifiers, credentials, or email
addresses.  By default it is a read-only manifest; ``--apply`` is required for
any mutation.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from collections import Counter
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key


def cognito_identity_key(subject: str) -> str:
    digest = hashlib.sha256(f"cognito\x00{subject}".encode("utf-8")).hexdigest()
    return f"v1#cognito#{digest}"


def pages(table: Any, **query: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    while True:
        result = table.query(**query)
        records.extend(result.get("Items", []))
        key = result.get("LastEvaluatedKey")
        if not key:
            return records
        query["ExclusiveStartKey"] = key


def resources(session: boto3.Session, stack: str) -> dict[str, str]:
    cloudformation = session.client("cloudformation")
    found: dict[str, str] = {}
    for page in cloudformation.get_paginator("list_stack_resources").paginate(StackName=stack):
        for item in page["StackResourceSummaries"]:
            found[item["LogicalResourceId"]] = item["PhysicalResourceId"]
    return found


def retained_subject(session: boto3.Session, user_pool: str, email: str) -> str:
    users = session.client("cognito-idp").list_users(
        UserPoolId=user_pool, Filter=f'email = "{email}"', Limit=3,
    ).get("Users", [])
    exact = []
    for user in users:
        attributes = {item["Name"]: item["Value"] for item in user.get("Attributes", [])}
        if attributes.get("email", "").casefold() == email.casefold():
            exact.append(attributes)
    if len(exact) != 1 or not exact[0].get("sub"):
        raise RuntimeError("retained_owner_email_is_not_unique")
    return str(exact[0]["sub"])


def build_plan(session: boto3.Session, stack: str, email: str) -> dict[str, Any]:
    names = resources(session, stack)
    required = {
        "KaevoUserPool", "KaevoPrincipalsTable", "KaevoIdentityMembershipsTable",
        "KaevoIdentityProfilesTable", "KaevoHouseholdMembershipsTable",
        "KaevoProfilesTable", "KaevoProfileBindingsTable", "KaevoProfileMappingsTable",
        "KaevoEntitlementsTable", "KaevoInstallationsTable", "KaevoHomeConnectorsTable",
        "KaevoAuthIdentitiesTable", "KaevoAccountsTable", "KaevoHouseholdInvitationsTable",
        "KaevoHouseholdJoinTransactionsTable",
    }
    missing = sorted(required - set(names))
    if missing:
        raise RuntimeError("required_authority_storage_missing")
    dynamodb = session.resource("dynamodb")
    table = {key: dynamodb.Table(value) for key, value in names.items() if key.startswith("Kaevo")}
    subject = retained_subject(session, names["KaevoUserPool"], email)
    principal = table["KaevoPrincipalsTable"].get_item(
        Key={"principal_id": subject}, ConsistentRead=True,
    ).get("Item")
    identity_membership = table["KaevoIdentityMembershipsTable"].get_item(
        Key={"principal_id": subject}, ConsistentRead=True,
    ).get("Item")
    if not isinstance(principal, dict) or not isinstance(identity_membership, dict):
        raise RuntimeError("retained_owner_authority_missing")
    if principal.get("state") != "active" or principal.get("role") != "owner":
        raise RuntimeError("retained_owner_is_not_active_owner")
    account_id = str(principal.get("account_id") or "")
    household_id = str(principal.get("household_id") or "")
    profile_id = str(identity_membership.get("profile_id") or "")
    owner_profile = table["KaevoIdentityProfilesTable"].get_item(
        Key={"profile_id": profile_id}, ConsistentRead=True,
    ).get("Item")
    if not all((account_id, household_id, profile_id)) or not isinstance(owner_profile, dict):
        raise RuntimeError("retained_owner_context_incomplete")
    if (
        owner_profile.get("state") != "active"
        or str(owner_profile.get("account_id") or "") != account_id
        or str(owner_profile.get("household_id") or "") != household_id
    ):
        raise RuntimeError("retained_owner_profile_conflict")

    cognito = session.client("cognito-idp")
    cognito_users = []
    for page in cognito.get_paginator("list_users").paginate(
        UserPoolId=names["KaevoUserPool"],
    ):
        cognito_users.extend(page.get("Users", []))
    nonretained_usernames: set[str] = set()
    exact_nonowner_subjects: set[str] = set()
    exact_nonowner_accounts: set[str] = set()
    exact_nonowner_profiles: set[str] = set()
    retained_account_alias_identity_keys: set[str] = set()
    retained_account_alias_subjects: set[str] = set()
    for user in cognito_users:
        attributes = {item["Name"]: item["Value"] for item in user.get("Attributes", [])}
        if attributes.get("email", "").casefold() == email.casefold():
            continue
        subject_candidate = str(attributes.get("sub") or "")
        username = str(user.get("Username") or "")
        if not subject_candidate or not username:
            raise RuntimeError("nonretained_cognito_identity_incomplete")
        candidate_principal = table["KaevoPrincipalsTable"].get_item(
            Key={"principal_id": subject_candidate}, ConsistentRead=True,
        ).get("Item")
        candidate_membership = table["KaevoIdentityMembershipsTable"].get_item(
            Key={"principal_id": subject_candidate}, ConsistentRead=True,
        ).get("Item")
        candidate_identity = table["KaevoAuthIdentitiesTable"].get_item(
            Key={"auth_identity_key": cognito_identity_key(subject_candidate)},
            ConsistentRead=True,
        ).get("Item")
        candidate_account_id = str(
            (candidate_principal or {}).get("account_id")
            or (candidate_identity or {}).get("account_id")
            or ""
        )
        if candidate_account_id == account_id:
            alias_profile_ids = {
                str(value)
                for value in list((candidate_principal or {}).get("profile_ids") or [])
                if str(value)
            }
            alias_membership_profile = str(
                (candidate_membership or {}).get("profile_id") or ""
            )
            if alias_membership_profile:
                alias_profile_ids.add(alias_membership_profile)
            if candidate_principal or candidate_membership:
                if (
                    not isinstance(candidate_principal, dict)
                    or not isinstance(candidate_membership, dict)
                    or str(candidate_principal.get("household_id") or "") != household_id
                    or str(candidate_membership.get("household_id") or "") != household_id
                ):
                    raise RuntimeError("retained_account_alias_has_conflicting_authority")
                for alias_profile_id in alias_profile_ids - {profile_id}:
                    alias_profile = table["KaevoIdentityProfilesTable"].get_item(
                        Key={"profile_id": alias_profile_id}, ConsistentRead=True,
                    ).get("Item")
                    if not isinstance(alias_profile, dict):
                        alias_profile = table["KaevoProfilesTable"].get_item(
                            Key={"profile_id": alias_profile_id}, ConsistentRead=True,
                        ).get("Item")
                    if (
                        not isinstance(alias_profile, dict)
                        or str(alias_profile.get("household_id") or "") != household_id
                        or (
                            alias_profile.get("account_id")
                            and str(alias_profile.get("account_id") or "") != account_id
                        )
                    ):
                        raise RuntimeError("retained_account_alias_profile_conflict")
                    exact_nonowner_profiles.add(alias_profile_id)
                retained_account_alias_subjects.add(subject_candidate)
            identity_key = str((candidate_identity or {}).get("auth_identity_key") or "")
            if not identity_key and not (candidate_principal and candidate_membership):
                raise RuntimeError("retained_account_alias_identity_missing")
            if identity_key:
                retained_account_alias_identity_keys.add(identity_key)
            nonretained_usernames.add(username)
            continue
        candidate_households = {
            str(record.get("household_id") or "")
            for record in (candidate_principal, candidate_membership)
            if isinstance(record, dict) and record.get("household_id")
        }
        if candidate_households - {household_id}:
            raise RuntimeError("nonretained_identity_belongs_to_unrelated_household")
        if isinstance(candidate_principal, dict) and candidate_principal.get("role") == "owner":
            raise RuntimeError("nonretained_owner_would_be_deleted")
        candidate_profile_ids = {
            str(value)
            for value in list((candidate_principal or {}).get("profile_ids") or [])
            if str(value)
        }
        membership_profile_id = str((candidate_membership or {}).get("profile_id") or "")
        if membership_profile_id:
            candidate_profile_ids.add(membership_profile_id)
        if candidate_profile_ids:
            for candidate_profile_id in candidate_profile_ids:
                candidate_profile = table["KaevoIdentityProfilesTable"].get_item(
                    Key={"profile_id": candidate_profile_id}, ConsistentRead=True,
                ).get("Item")
                if not isinstance(candidate_profile, dict):
                    candidate_profile = table["KaevoProfilesTable"].get_item(
                        Key={"profile_id": candidate_profile_id}, ConsistentRead=True,
                    ).get("Item")
                if isinstance(candidate_profile, dict) and (
                    str(candidate_profile.get("household_id") or "") != household_id
                    or candidate_profile_id == profile_id
                ):
                    raise RuntimeError("nonretained_profile_authority_conflict")
            exact_nonowner_profiles.update(candidate_profile_ids)
        if candidate_account_id:
            if candidate_account_id == account_id:
                raise RuntimeError("retained_account_would_be_deleted")
            if not isinstance(candidate_identity, dict):
                raise RuntimeError("nonretained_account_identity_missing")
            candidate_bindings = pages(
                table["KaevoProfileBindingsTable"],
                KeyConditionExpression=Key("account_id").eq(candidate_account_id),
                ConsistentRead=True,
            )
            for binding in candidate_bindings:
                binding_profile_id = str(binding.get("profile_id") or "")
                if not binding_profile_id:
                    raise RuntimeError("nonretained_profile_binding_incomplete")
                binding_profile = table["KaevoIdentityProfilesTable"].get_item(
                    Key={"profile_id": binding_profile_id}, ConsistentRead=True,
                ).get("Item")
                if (
                    not isinstance(binding_profile, dict)
                    or str(binding_profile.get("household_id") or "") != household_id
                    or binding_profile_id == profile_id
                ):
                    raise RuntimeError("nonretained_profile_binding_conflict")
                exact_nonowner_profiles.add(binding_profile_id)
            exact_nonowner_accounts.add(candidate_account_id)
        elif any((candidate_principal, candidate_membership, candidate_identity)):
            raise RuntimeError("nonretained_identity_graph_incomplete")
        if candidate_principal or candidate_membership:
            exact_nonowner_subjects.add(subject_candidate)
        nonretained_usernames.add(username)

    household_rows = pages(
        table["KaevoHouseholdMembershipsTable"],
        KeyConditionExpression=Key("household_id").eq(household_id), ConsistentRead=True,
    )
    owner_rows = [
        row for row in household_rows
        if row.get("entity_type") == "HouseholdMembership"
        and str(row.get("account_id") or "") == account_id
        and str(row.get("profile_id") or "") == profile_id
        and row.get("status") == "active"
    ]
    if len(owner_rows) != 1:
        raise RuntimeError("retained_owner_normalized_membership_not_unique")
    stale_memberships = [
        row for row in household_rows
        if row.get("entity_type") == "HouseholdMembership" and row not in owner_rows
    ]
    target_accounts = {str(row.get("account_id") or "") for row in stale_memberships}
    target_accounts.update(exact_nonowner_accounts)
    target_accounts.discard("")
    legacy_hits = pages(
        table["KaevoProfilesTable"],
        IndexName="household_id-created_at_epoch-index",
        KeyConditionExpression=Key("household_id").eq(household_id), ConsistentRead=False,
    )
    legacy_profiles = []
    for hit in legacy_hits:
        key = str(hit.get("profile_id") or "")
        record = table["KaevoProfilesTable"].get_item(Key={"profile_id": key}, ConsistentRead=True).get("Item")
        if isinstance(record, dict) and str(record.get("household_id") or "") == household_id:
            legacy_profiles.append(record)
    target_profiles = {str(row.get("profile_id") or "") for row in stale_memberships}
    target_profiles.update(exact_nonowner_profiles)
    target_profiles.update(str(row.get("profile_id") or "") for row in legacy_profiles)
    target_profiles.discard("")
    target_profiles.discard(profile_id)

    invitations = pages(
        table["KaevoHouseholdInvitationsTable"], IndexName="household_id-index",
        KeyConditionExpression=Key("household_id").eq(household_id), ConsistentRead=False,
    )
    invitation_exact = []
    transactions = []
    for invitation in invitations:
        code_hash = str(invitation.get("code_hash") or "")
        exact = table["KaevoHouseholdInvitationsTable"].get_item(
            Key={"code_hash": code_hash}, ConsistentRead=True,
        ).get("Item")
        if not isinstance(exact, dict) or str(exact.get("household_id") or "") != household_id:
            raise RuntimeError("invitation_index_authority_conflict")
        invitation_exact.append(exact)
        invitation_id = str(exact.get("invitation_id") or "")
        if invitation_id:
            transactions.extend(pages(
                table["KaevoHouseholdJoinTransactionsTable"],
                IndexName="invitation_id-created_at_epoch-index",
                KeyConditionExpression=Key("invitation_id").eq(invitation_id), ConsistentRead=False,
            ))

    installations = pages(
        table["KaevoInstallationsTable"], IndexName="household_id-created_at_epoch-index",
        KeyConditionExpression=Key("household_id").eq(household_id), ConsistentRead=False,
    )
    mappings = []
    for installation in installations:
        installation_id = str(installation.get("installation_id") or "")
        mappings.extend(pages(
            table["KaevoProfileMappingsTable"],
            KeyConditionExpression=Key("installation_id").eq(installation_id), ConsistentRead=True,
        ))
    bindings = []
    for candidate_account in target_accounts | {account_id}:
        bindings.extend(pages(
            table["KaevoProfileBindingsTable"],
            KeyConditionExpression=Key("account_id").eq(candidate_account), ConsistentRead=True,
        ))
    connectors = pages(
        table["KaevoHomeConnectorsTable"], IndexName="household_id-updated_at-index",
        KeyConditionExpression=Key("household_id").eq(household_id), ConsistentRead=False,
    )
    if any(str(record.get("profile_id") or "") != profile_id for record in connectors):
        raise RuntimeError("connector_ownership_ambiguous")
    return {
        "names": names, "table": table, "subject": subject, "account_id": account_id,
        "household_id": household_id, "profile_id": profile_id, "stale_memberships": stale_memberships,
        "target_accounts": target_accounts, "target_profiles": target_profiles,
        "legacy_profiles": [row for row in legacy_profiles if str(row.get("profile_id") or "") in target_profiles],
        "invitations": invitation_exact, "transactions": transactions,
        "mappings": [row for row in mappings if str(row.get("cloud_profile_id") or "") in target_profiles],
        "bindings": [row for row in bindings if str(row.get("profile_id") or "") in target_profiles],
        "installations": [
            row for row in installations
            if str(row.get("account_id") or "") != account_id
            or str(row.get("principal_id") or "")
                in exact_nonowner_subjects | retained_account_alias_subjects
            or str(row.get("profile_id") or "") in target_profiles
        ],
        "connector_count": len(connectors),
        "nonretained_cognito_usernames": nonretained_usernames,
        "exact_nonowner_subjects": exact_nonowner_subjects,
        "retained_account_alias_identity_keys": retained_account_alias_identity_keys,
        "retained_account_alias_subjects": retained_account_alias_subjects,
    }


def report(plan: dict[str, Any]) -> None:
    print("RESET_MANIFEST=READY")
    print("retained_owner_authority=verified")
    print(f"stale_memberships={len(plan['stale_memberships'])}")
    print(f"profiles_to_remove={len(plan['target_profiles'])}")
    print(f"legacy_profiles_to_remove={len(plan['legacy_profiles'])}")
    print(f"mappings_to_remove={len(plan['mappings'])}")
    print(f"bindings_to_remove={len(plan['bindings'])}")
    print(f"invitations_to_remove={len(plan['invitations'])}")
    print(f"join_recovery_records_to_remove={len(plan['transactions'])}")
    print(f"nonowner_accounts_to_remove={len(plan['target_accounts'] - {plan['account_id']})}")
    print(f"nonretained_cognito_users_to_remove={len(plan['nonretained_cognito_usernames'])}")
    print(f"retained_account_aliases_to_remove={len(plan['retained_account_alias_identity_keys'])}")
    print(f"preserved_connectors={plan['connector_count']}")


def execute(plan: dict[str, Any], session: boto3.Session, email: str) -> None:
    """Delete only the exact records captured by ``build_plan``.

    The retained account, principal, normalized membership, profile, connector,
    and its Cognito user are never added to a delete operation.
    """
    table = plan["table"]
    target_profiles = set(plan["target_profiles"])
    target_accounts = set(plan["target_accounts"]) - {plan["account_id"]}
    household_id = plan["household_id"]
    cognito = session.client("cognito-idp")

    # Resolve every Cognito target before mutating the graph.  A legacy
    # provider field must never turn a partial cleanup into a reason to guess
    # which user to delete after the reverse membership evidence is gone.
    cognito_usernames: set[str] = set()
    account_identities: dict[str, list[dict[str, Any]]] = {}
    all_users = []
    for page in cognito.get_paginator("list_users").paginate(
        UserPoolId=plan["names"]["KaevoUserPool"],
    ):
        all_users.extend(page.get("Users", []))
    users_by_subject = {
        str({item["Name"]: item["Value"] for item in user.get("Attributes", [])}.get("sub") or ""): user
        for user in all_users
    }
    for account_id in target_accounts:
        identities = pages(
            table["KaevoAuthIdentitiesTable"], IndexName="account_id-created_at_epoch-index",
            KeyConditionExpression=Key("account_id").eq(account_id), ConsistentRead=False,
        )
        if not identities:
            raise RuntimeError("target_account_has_no_auth_identity")
        account_identities[account_id] = identities
        for identity in identities:
            if str(identity.get("account_id") or "") != account_id:
                raise RuntimeError("auth_identity_account_conflict")
            if str(identity.get("provider") or "") != "cognito":
                continue
            subject = str(identity.get("provider_subject") or "")
            user = users_by_subject.get(subject)
            if not user:
                # A dangling Cognito auth-identity row is still exact account
                # data and is deleted below. There is no Cognito user left to
                # target, so absence is already satisfied.
                continue
            attributes = {item["Name"]: item["Value"] for item in user.get("Attributes", [])}
            if attributes.get("email", "").casefold() == email.casefold():
                raise RuntimeError("retained_email_would_be_deleted")
            cognito_usernames.add(str(user["Username"]))
    if not cognito_usernames.issubset(plan["nonretained_cognito_usernames"]):
        raise RuntimeError("resolved_cognito_targets_exceed_manifest")
    cognito_usernames.update(plan["nonretained_cognito_usernames"])

    for identity_key in plan["retained_account_alias_identity_keys"]:
        identity = table["KaevoAuthIdentitiesTable"].get_item(
            Key={"auth_identity_key": identity_key}, ConsistentRead=True,
        ).get("Item")
        if (
            not isinstance(identity, dict)
            or str(identity.get("account_id") or "") != plan["account_id"]
            or str(identity.get("provider") or "") != "cognito"
        ):
            raise RuntimeError("retained_account_alias_changed_after_manifest")
    for alias_subject in plan["retained_account_alias_subjects"]:
        alias_principal = table["KaevoPrincipalsTable"].get_item(
            Key={"principal_id": alias_subject}, ConsistentRead=True,
        ).get("Item")
        alias_membership = table["KaevoIdentityMembershipsTable"].get_item(
            Key={"principal_id": alias_subject}, ConsistentRead=True,
        ).get("Item")
        if (
            not isinstance(alias_principal, dict)
            or not isinstance(alias_membership, dict)
            or str(alias_principal.get("account_id") or "") != plan["account_id"]
            or str(alias_principal.get("household_id") or "") != household_id
            or str(alias_membership.get("profile_id") or "")
                not in target_profiles | {plan["profile_id"]}
        ):
            raise RuntimeError("retained_account_alias_authority_changed_after_manifest")

    # Recovery records first: an old invitation must never recreate a deleted
    # profile after the identity graph has been reset.
    seen_transactions: set[str] = set()
    for transaction in plan["transactions"]:
        key = str(transaction.get("join_resume_hash") or "")
        if key and key not in seen_transactions:
            table["KaevoHouseholdJoinTransactionsTable"].delete_item(Key={"join_resume_hash": key})
            seen_transactions.add(key)
    for invitation in plan["invitations"]:
        key = str(invitation.get("code_hash") or "")
        if key:
            table["KaevoHouseholdInvitationsTable"].delete_item(Key={"code_hash": key})

    for mapping in plan["mappings"]:
        installation_id = str(mapping.get("installation_id") or "")
        source_id = str(mapping.get("local_profile_source_id") or "")
        if installation_id and source_id:
            table["KaevoProfileMappingsTable"].delete_item(Key={
                "installation_id": installation_id, "local_profile_source_id": source_id,
            })
    for binding in plan["bindings"]:
        account_id = str(binding.get("account_id") or "")
        profile_id = str(binding.get("profile_id") or "")
        if account_id and profile_id in target_profiles:
            table["KaevoProfileBindingsTable"].delete_item(Key={
                "account_id": account_id, "profile_id": profile_id,
            })

    for profile_id in target_profiles:
        normalized = table["KaevoIdentityProfilesTable"].get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if normalized:
            if str(normalized.get("household_id") or "") != household_id:
                raise RuntimeError("normalized_profile_household_conflict")
            table["KaevoIdentityProfilesTable"].delete_item(Key={"profile_id": profile_id})
        legacy = table["KaevoProfilesTable"].get_item(
            Key={"profile_id": profile_id}, ConsistentRead=True,
        ).get("Item")
        if legacy:
            if str(legacy.get("household_id") or "") != household_id:
                raise RuntimeError("legacy_profile_household_conflict")
            table["KaevoProfilesTable"].delete_item(Key={"profile_id": profile_id})
        table["KaevoEntitlementsTable"].delete_item(Key={"profile_id": profile_id})
        if "KaevoProfileSettingsTable" in table:
            table["KaevoProfileSettingsTable"].delete_item(Key={"profile_id": profile_id})
        if "KaevoDevicesTable" in table:
            for device in pages(
                table["KaevoDevicesTable"], IndexName="profile_id-updated_at-index",
                KeyConditionExpression=Key("profile_id").eq(profile_id), ConsistentRead=False,
            ):
                device_id = str(device.get("device_id") or "")
                if device_id:
                    table["KaevoDevicesTable"].delete_item(Key={"device_id": device_id})

    # Remove stale normalized membership projections only after their profile
    # data and mappings have been removed.  The repaired Owner row is excluded
    # from this plan by construction.
    for membership in plan["stale_memberships"]:
        membership_id = str(membership.get("membership_id") or "")
        if membership_id:
            table["KaevoHouseholdMembershipsTable"].delete_item(Key={
                "household_id": household_id, "membership_id": membership_id,
            })

    for account_id in target_accounts:
        identities = account_identities[account_id]
        for identity in identities:
            key = str(identity.get("auth_identity_key") or "")
            if key:
                table["KaevoAuthIdentitiesTable"].delete_item(Key={"auth_identity_key": key})
        principal = None
        for identity in identities:
            subject = str(identity.get("provider_subject") or "")
            candidate = table["KaevoPrincipalsTable"].get_item(
                Key={"principal_id": subject}, ConsistentRead=True,
            ).get("Item") if subject else None
            if candidate:
                principal = candidate
                if str(candidate.get("account_id") or "") != account_id or str(candidate.get("household_id") or "") != household_id:
                    raise RuntimeError("principal_authority_conflict")
                table["KaevoIdentityMembershipsTable"].delete_item(Key={"principal_id": subject})
                table["KaevoPrincipalsTable"].delete_item(Key={"principal_id": subject})
        account = table["KaevoAccountsTable"].get_item(Key={"account_id": account_id}, ConsistentRead=True).get("Item")
        if account:
            table["KaevoAccountsTable"].delete_item(Key={"account_id": account_id})

    for installation in plan["installations"]:
        installation_id = str(installation.get("installation_id") or "")
        if installation_id:
            table["KaevoInstallationsTable"].delete_item(Key={"installation_id": installation_id})
    for alias_subject in plan["retained_account_alias_subjects"]:
        table["KaevoIdentityMembershipsTable"].delete_item(
            Key={"principal_id": alias_subject},
        )
        table["KaevoPrincipalsTable"].delete_item(
            Key={"principal_id": alias_subject},
        )
    for identity_key in plan["retained_account_alias_identity_keys"]:
        table["KaevoAuthIdentitiesTable"].delete_item(
            Key={"auth_identity_key": identity_key},
        )
    for username in sorted(cognito_usernames):
        cognito.admin_delete_user(UserPoolId=plan["names"]["KaevoUserPool"], Username=username)
    print("RESET_APPLY=COMPLETE")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--retained-email", required=True)
    parser.add_argument("--profile", default="kaevo-deploy")
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--stack", default="kaevo-cloud-dev")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    plan = build_plan(boto3.Session(profile_name=args.profile, region_name=args.region), args.stack, args.retained_email)
    report(plan)
    if args.apply:
        execute(plan, boto3.Session(profile_name=args.profile, region_name=args.region), args.retained_email)


if __name__ == "__main__":
    main()
