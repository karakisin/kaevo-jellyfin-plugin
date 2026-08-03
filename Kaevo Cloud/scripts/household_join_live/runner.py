"""Manifest-first creator for one disposable Household Join fixture.

This module is integration tooling only.  It never imports the Lambda handler,
does not discover records with Scan, and emits no secret or raw resource value.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_API_SRC = Path(__file__).resolve().parents[2] / "api" / "src"
if str(_API_SRC) not in sys.path:
    sys.path.insert(0, str(_API_SRC))

from account_foundation import CanonicalRole
from identity_authority import derive_authoritative_claims
from household_membership import (
    build_account_household_guard,
    build_household_membership_record,
    build_household_owner_guard,
)
from profile_binding import build_profile_creation

from api.tests.household_join_fixture import (
    ProtectedFixtureManifest,
    canonical_invitation_code,
    invitation_code_hash,
)

from .constants import (
    AWS_ACCOUNT_ID,
    AWS_PROFILE,
    AWS_REGION,
    FIXTURE_ROOT,
    JOIN_LOGICAL_ID,
    JOIN_TRANSACTIONS_LOGICAL_ID,
    STACK_NAME,
)
from .errors import FixtureSafetyError
from .preflight import run_preflight


_RESOURCE_LOGICAL_IDS = {
    "accounts": "KaevoAccountsTable",
    "households": "KaevoIdentityHouseholdsTable",
    "identity_profiles": "KaevoIdentityProfilesTable",
    "cloud_profiles": "KaevoProfilesTable",
    "profile_bindings": "KaevoProfileBindingsTable",
    "entitlements": "KaevoEntitlementsTable",
    "principals": "KaevoPrincipalsTable",
    "identity_memberships": "KaevoIdentityMembershipsTable",
    "household_memberships": "KaevoHouseholdMembershipsTable",
    "invitations": "KaevoHouseholdInvitationsTable",
    "joins": JOIN_TRANSACTIONS_LOGICAL_ID,
}

_RESOURCE_KEYS = {
    "owner_account": ("accounts", ("account_id",)),
    "owner_household": ("households", ("household_id",)),
    "owner_identity_profile": ("identity_profiles", ("profile_id",)),
    "owner_cloud_profile": ("cloud_profiles", ("profile_id",)),
    "owner_profile_binding": ("profile_bindings", ("account_id", "profile_id")),
    "owner_entitlement": ("entitlements", ("profile_id",)),
    "owner_principal": ("principals", ("principal_id",)),
    "owner_identity_membership": ("identity_memberships", ("principal_id",)),
    "owner_membership": ("household_memberships", ("household_id", "membership_id")),
    "owner_account_guard": ("household_memberships", ("household_id", "membership_id")),
    "owner_guard": ("household_memberships", ("household_id", "membership_id")),
    "invitation": ("invitations", ("code_hash",)),
}

_PLAN = tuple(("cognito_user", "credentials", *_RESOURCE_KEYS.keys()))


def _now() -> tuple[str, int]:
    instant = datetime.now(UTC)
    return instant.isoformat().replace("+00:00", "Z"), int(instant.timestamp())


def _safe_marker() -> str:
    return f"fixture-b-{uuid.uuid4().hex}"


def _assert_no_unfinished_fixture(root: str | Path) -> None:
    for path in Path(root).glob("*/manifest.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as error:
            raise FixtureSafetyError("FIXTURE_MANIFEST_UNREADABLE") from error
        cleanup_state = str((payload.get("cleanup") or {}).get("state") or "")
        fixture_state = str((payload.get("fixture") or {}).get("state") or "")
        if cleanup_state != "ABSENCE_VERIFIED" and fixture_state not in {"ABORTED_BEFORE_WRITE", "ABORTED"}:
            raise FixtureSafetyError("UNFINISHED_FIXTURE_PRESENT")


def _private_json_write(path: Path, payload: dict[str, str]) -> None:
    if path.exists():
        raise FixtureSafetyError("FIXTURE_CREDENTIAL_PATH_EXISTS")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        raise
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise FixtureSafetyError("FIXTURE_CREDENTIAL_MODE_INVALID")


def _replace_private_json(path: Path, payload: dict[str, str]) -> None:
    staging = path.with_name(path.name + ".rotating")
    _private_json_write(staging, payload)
    try:
        os.replace(staging, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if staging.exists():
            staging.unlink()
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise FixtureSafetyError("FIXTURE_CREDENTIAL_MODE_INVALID")


def _stack_resources(session: Any) -> dict[str, str]:
    resources: dict[str, str] = {}
    paginator = session.client("cloudformation").get_paginator("list_stack_resources")
    for page in paginator.paginate(StackName=STACK_NAME):
        for entry in page.get("StackResourceSummaries") or []:
            logical = entry.get("LogicalResourceId")
            physical = entry.get("PhysicalResourceId")
            if logical in set(_RESOURCE_LOGICAL_IDS.values()) and isinstance(physical, str) and physical:
                resources[logical] = physical
    required = set(_RESOURCE_LOGICAL_IDS.values())
    if set(resources) != required:
        raise FixtureSafetyError("FIXTURE_TABLE_BINDING_MISSING")
    return resources


def _join_function_name(session: Any) -> str:
    paginator = session.client("cloudformation").get_paginator("list_stack_resources")
    matches: list[str] = []
    for page in paginator.paginate(StackName=STACK_NAME):
        for entry in page.get("StackResourceSummaries") or []:
            if entry.get("LogicalResourceId") == JOIN_LOGICAL_ID and isinstance(entry.get("PhysicalResourceId"), str):
                matches.append(entry["PhysicalResourceId"])
    if len(matches) != 1:
        raise FixtureSafetyError("FIXTURE_JOIN_FUNCTION_BINDING_MISSING")
    return matches[0]


def _table_fingerprints(session: Any, resources: dict[str, str]) -> dict[str, str]:
    client = session.client("dynamodb")
    fingerprints: dict[str, str] = {}
    for logical, physical in resources.items():
        table = client.describe_table(TableName=physical).get("Table") or {}
        arn = str(table.get("TableArn") or "")
        if table.get("TableStatus") != "ACTIVE" or f":dynamodb:{AWS_REGION}:{AWS_ACCOUNT_ID}:table/" not in arn:
            raise FixtureSafetyError("FIXTURE_TABLE_NOT_READY")
        fingerprints[logical] = arn.rsplit("/", 1)[-1]
    return fingerprints


def _native_tables(session: Any, resources: dict[str, str]) -> dict[str, Any]:
    dynamodb = session.resource("dynamodb")
    return {key: dynamodb.Table(resources[logical]) for key, logical in _RESOURCE_LOGICAL_IDS.items()}


def _record_put(
    *,
    manifest: ProtectedFixtureManifest,
    tables: dict[str, Any],
    resource: str,
    item: dict[str, Any],
    marker: str,
) -> None:
    table_key, key_fields = _RESOURCE_KEYS[resource]
    exact_key = {field: item[field] for field in key_fields}
    try:
        tables[table_key].put_item(Item=item, ConditionExpression="attribute_not_exists(" + key_fields[0] + ")")
    except Exception as error:
        raise FixtureSafetyError(f"FIXTURE_{resource.upper()}_CREATE_FAILED") from error
    try:
        manifest.record_resource(resource, exact_key, source_operation=f"{resource}_created", bindings={"fixture_marker": marker})
    except Exception as error:
        try:
            tables[table_key].delete_item(
                Key=exact_key,
                ConditionExpression="fixture_marker = :marker",
                ExpressionAttributeValues={":marker": marker},
            )
        except Exception:
            pass
        raise FixtureSafetyError("FIXTURE_MANIFEST_WRITE_FAILED_AFTER_RESOURCE_CREATE") from error


def _owner_graph(marker: str) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    created, epoch = _now()
    owner_account_id = f"acct_fixture_{uuid.uuid4().hex}"
    household_id = f"hh_fixture_{uuid.uuid4().hex}"
    owner_subject = f"fixture_owner_{uuid.uuid4().hex}"
    owner_creation = build_profile_creation(
        household_id=household_id,
        account_id=owner_account_id,
        display_name="Fixture B Owner",
        profile_type="adult",
        age_classification="adult",
        now_iso=created,
        now_epoch=epoch,
    )
    owner_profile_id = str(owner_creation.profile["profile_id"])
    principal = {
        "principal_id": owner_subject, "account_id": owner_account_id, "household_id": household_id,
        "role": "owner", "authz_version": 1, "profile_ids": [owner_profile_id],
        "state": "active", "revoked": False, "created_at": created, "fixture_marker": marker,
    }
    identity_membership = {
        "principal_id": owner_subject, "account_id": owner_account_id, "household_id": household_id,
        "profile_id": owner_profile_id, "role": "owner", "authz_version": 1,
        "state": "active", "created_at": created, "fixture_marker": marker,
    }
    household = {
        "household_id": household_id, "account_id": owner_account_id, "owner_principal_id": owner_subject,
        "state": "active", "created_at": created, "fixture_marker": marker,
    }
    account = {
        "account_id": owner_account_id, "entity_type": "Account", "status": "active", "schema_version": 1,
        "created_at": created, "updated_at": created, "created_at_epoch": epoch, "fixture_marker": marker,
    }
    identity_profile = {
        "profile_id": owner_profile_id, "account_id": owner_account_id, "household_id": household_id,
        "owner_principal_id": owner_subject, "profile_type": "adult", "state": "active",
        "created_at": created, "fixture_marker": marker,
    }
    profile = {**owner_creation.profile, "fixture_marker": marker}
    binding = {**owner_creation.binding, "fixture_marker": marker}
    entitlement = {
        "profile_id": owner_profile_id,
        "entitlements_json": json.dumps({"plan": "fixture-b", "family": True}, separators=(",", ":"), sort_keys=True),
        "created_at": created, "updated_at": created, "fixture_marker": marker,
    }
    claims = derive_authoritative_claims(owner_subject, principal, identity_membership, household, identity_profile)
    membership = {**build_household_membership_record(claims, CanonicalRole.OWNER, now_iso=created, now_epoch=epoch), "fixture_marker": marker}
    account_guard = {**build_account_household_guard(claims, membership_id=membership["membership_id"], now_iso=created, now_epoch=epoch), "fixture_marker": marker}
    owner_guard = {**build_household_owner_guard(claims, membership_id=membership["membership_id"], now_iso=created, now_epoch=epoch), "fixture_marker": marker}
    graph = {
        "owner_account": account,
        "owner_household": household,
        "owner_identity_profile": identity_profile,
        "owner_cloud_profile": profile,
        "owner_profile_binding": binding,
        "owner_entitlement": entitlement,
        "owner_principal": principal,
        "owner_identity_membership": identity_membership,
        "owner_membership": membership,
        "owner_account_guard": account_guard,
        "owner_guard": owner_guard,
    }
    return graph, {"household_id": household_id, "owner_profile_id": owner_profile_id}


def create_fixture_b(*, session_factory, root: str = FIXTURE_ROOT, marker: str | None = None) -> dict[str, str]:
    """Create exactly one new, journaled development fixture without logging secrets."""
    run_preflight(session_factory=session_factory, root=root)
    _assert_no_unfinished_fixture(root)
    marker = marker or _safe_marker()
    if not marker.startswith("fixture-b-"):
        raise FixtureSafetyError("FIXTURE_MARKER_SCOPE_INVALID")
    session = session_factory(profile_name=AWS_PROFILE, region_name=AWS_REGION)
    resources = _stack_resources(session)
    manifest = ProtectedFixtureManifest.create(
        Path(root),
        marker=marker,
        account_id=AWS_ACCOUNT_ID,
        region=AWS_REGION,
        table_arn_fingerprints=_table_fingerprints(session, resources),
        fixture_type="fixture_b_household_join",
        expected_resource_plan=_PLAN,
    )
    manifest.transition_fixture_state("CREATING", source_operation="fixture_creation_started")
    tables = _native_tables(session, resources)
    variables = (
        session.client("lambda")
        .get_function_configuration(FunctionName=_join_function_name(session))
        .get("Environment", {})
        .get("Variables", {})
    )
    pool_id = str(variables.get("COGNITO_USER_POOL_ID") or variables.get("USER_POOL_ID") or "")
    if not pool_id:
        raise FixtureSafetyError("FIXTURE_COGNITO_POOL_MISSING")
    token = secrets.token_urlsafe(18)
    email = f"fixture-b-{token.lower()}@example.test"
    password = f"Ka!{secrets.token_urlsafe(18)}9"
    cognito = session.client("cognito-idp")
    try:
        created_user = cognito.admin_create_user(
            UserPoolId=pool_id,
            Username=email,
            MessageAction="SUPPRESS",
            UserAttributes=[{"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}],
        )
        user = created_user.get("User") or {}
        username = str(user.get("Username") or email)
        cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    except Exception as error:
        raise FixtureSafetyError("FIXTURE_COGNITO_CREATE_FAILED") from error
    try:
        manifest.record_resource("cognito_user", {"username": username}, source_operation="cognito_user_created", bindings={"fixture_marker": marker, "email": email})
    except Exception as error:
        try:
            cognito.admin_delete_user(UserPoolId=pool_id, Username=username)
        except Exception:
            pass
        raise FixtureSafetyError("FIXTURE_MANIFEST_WRITE_FAILED_AFTER_COGNITO_CREATE") from error
    invitation_code = canonical_invitation_code(secrets.token_hex(5).upper()[:5] + "-" + secrets.token_hex(5).upper()[:5])
    credential_path = manifest.path.parent / "credentials.json"
    _private_json_write(credential_path, {"invitation_code": invitation_code, "email": email, "password": password})
    manifest.record_resource("credentials", {"path": str(credential_path)}, source_operation="credentials_written", bindings={"fixture_marker": marker})
    graph, refs = _owner_graph(marker)
    for resource, item in graph.items():
        _record_put(manifest=manifest, tables=tables, resource=resource, item=item, marker=marker)
    created, epoch = _now()
    invitation = {
        "code_hash": invitation_code_hash(invitation_code),
        "invitation_id": f"invite_{secrets.token_urlsafe(18)}",
        "account_id": graph["owner_account"]["account_id"],
        "household_id": refs["household_id"],
        "owner_principal_id": graph["owner_principal"]["principal_id"],
        "owner_profile_id": refs["owner_profile_id"],
        "role": "adult",
        "profile_type": "adult",
        "state": "pending",
        "code_expires_at": epoch + 3600,
        "expires_at": epoch + 3600,
        "created_at": created,
        "created_at_epoch": epoch,
        "fixture_marker": marker,
    }
    _record_put(manifest=manifest, tables=tables, resource="invitation", item=invitation, marker=marker)
    manifest.transition_fixture_state("READY_FOR_DEVICE", source_operation="fixture_ready_for_device")
    return {"event": "FIXTURE_READY_FOR_DEVICE", "marker": marker, "manifest_path": str(manifest.path)}


def repair_fixture_b_viewer(*, session_factory, manifest_path: str | Path) -> dict[str, str]:
    """Rotate an untouched fixture invitation when its private viewer is incomplete."""
    path = Path(manifest_path)
    run_preflight(session_factory=session_factory, root=str(path.parents[1]))
    manifest = ProtectedFixtureManifest.load(path, account_id=AWS_ACCOUNT_ID, region=AWS_REGION)
    if (manifest.payload.get("fixture") or {}).get("state") != "READY_FOR_DEVICE":
        raise FixtureSafetyError("FIXTURE_NOT_READY_FOR_VIEWER_REPAIR")
    invitation_entry = (manifest.payload.get("resources") or {}).get("invitation") or {}
    old_key = invitation_entry.get("key") or {}
    marker = str(manifest.payload.get("fixture_marker") or "")
    credential_path = path.parent / "credentials.json"
    if not marker or set(old_key) != {"code_hash"} or not credential_path.is_file():
        raise FixtureSafetyError("FIXTURE_VIEWER_REPAIR_BINDING_MISSING")
    credentials = json.loads(credential_path.read_text(encoding="utf-8"))
    if not isinstance(credentials, dict) or not all(isinstance(credentials.get(field), str) and credentials[field] for field in ("email", "password")):
        raise FixtureSafetyError("FIXTURE_CREDENTIAL_VIEWER_INVALID")
    session = session_factory(profile_name=AWS_PROFILE, region_name=AWS_REGION)
    resources = _stack_resources(session)
    tables = _native_tables(session, resources)
    old = tables["invitations"].get_item(Key=old_key, ConsistentRead=True).get("Item")
    if not isinstance(old, dict) or old.get("fixture_marker") != marker or old.get("state") != "pending":
        raise FixtureSafetyError("FIXTURE_INVITATION_ROTATION_NOT_SAFE")
    from .discovery import query_invitation_transactions

    transaction_keys = query_invitation_transactions(
        dynamodb_client=session.client("dynamodb"),
        table_name=resources[_RESOURCE_LOGICAL_IDS["joins"]],
        invitation_id=str(old.get("invitation_id") or ""),
    )
    if transaction_keys:
        raise FixtureSafetyError("FIXTURE_INVITATION_ALREADY_USED")
    replacement_code = canonical_invitation_code(secrets.token_hex(5).upper()[:5] + "-" + secrets.token_hex(5).upper()[:5])
    replacement = dict(old)
    replacement["code_hash"] = invitation_code_hash(replacement_code)
    replacement["rotated_at_epoch"] = int(time.time())
    replacement_key = {"code_hash": replacement["code_hash"]}
    client = tables["invitations"].meta.client
    try:
        client.transact_write_items(TransactItems=[
            {"Delete": {
                "TableName": resources[_RESOURCE_LOGICAL_IDS["invitations"]],
                "Key": old_key,
                "ConditionExpression": "fixture_marker = :marker AND #state = :pending",
                "ExpressionAttributeNames": {"#state": "state"},
                "ExpressionAttributeValues": {":marker": marker, ":pending": "pending"},
            }},
            {"Put": {
                "TableName": resources[_RESOURCE_LOGICAL_IDS["invitations"]],
                "Item": replacement,
                "ConditionExpression": "attribute_not_exists(code_hash)",
            }},
        ])
        manifest.replace_resource(
            "invitation",
            expected_key=old_key,
            replacement_key=replacement_key,
            source_operation="invitation_rotated_for_protected_viewer",
            bindings={"fixture_marker": marker},
        )
    except Exception as error:
        raise FixtureSafetyError("FIXTURE_INVITATION_ROTATION_FAILED") from error
    _replace_private_json(
        credential_path,
        {"invitation_code": replacement_code, "email": credentials["email"], "password": credentials["password"]},
    )
    return {"event": "FIXTURE_VIEWER_REPAIRED", "manifest_path": str(path)}
