"""Isolated HTTP entry point for Account Lifecycle V2.

This Lambda does not import the V1 monolithic handler.  API Gateway verifies
the JWT; this entry point additionally verifies the token class and resolves
the account from AuthIdentity before invoking the lifecycle service.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Mapping

import boto3

from account_lifecycle_v2 import LifecycleV2Error
from account_lifecycle_v2_service import (
    AccountLifecycleV2Service,
    DynamoLifecycleV2Repository,
    LifecycleV2StorageError,
)
from account_lifecycle_v2_session import (
    LifecycleV2SessionError,
    ProtectedLifecycleV2SessionAuthenticator,
    lifecycle_request_path,
)
from account_lifecycle_v2_status_token import (
    LifecycleV2StatusTokenCodec,
    LifecycleV2StatusTokenError,
)
from account_lifecycle_v2_registry_sync import ExactLifecycleV2ProviderRegistrySync


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)
_OPERATION_PATH = re.compile(
    r"^/v4/account-lifecycle/deletions/(ald2_[A-Za-z0-9_-]{24,96})(/confirm)?$"
)


def _response(status: int, body: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {
            "content-type": "application/json",
            "cache-control": "no-store",
        },
        "body": json.dumps(body, separators=(",", ":"), sort_keys=True),
    }


def _header(event: Mapping[str, Any], name: str) -> str:
    target = name.lower()
    for key, value in (event.get("headers") or {}).items():
        if str(key).lower() == target:
            return str(value or "")
    return ""


def _method(event: Mapping[str, Any]) -> str:
    return str(
        event.get("requestContext", {}).get("http", {}).get("method")
        or event.get("httpMethod")
        or ""
    ).upper()


def _path(event: Mapping[str, Any]) -> str:
    return lifecycle_request_path(event)


def _body(event: Mapping[str, Any]) -> dict[str, Any]:
    raw = event.get("body")
    if raw in (None, ""):
        return {}
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 4096:
        raise LifecycleV2Error("request_body_invalid")
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise LifecycleV2Error("request_body_invalid") from error
    if not isinstance(parsed, dict):
        raise LifecycleV2Error("request_body_invalid")
    return parsed


def handle(
    event: Mapping[str, Any],
    *,
    service: AccountLifecycleV2Service,
    session: Mapping[str, Any] | None = None,
    status_codec: LifecycleV2StatusTokenCodec | None = None,
    enqueue=None,
    provider_sync=None,
    now: int | None = None,
) -> dict[str, Any]:
    method = _method(event)
    path = _path(event)
    body = _body(event) if method == "POST" else {}

    if method == "POST" and path == "/v4/account-lifecycle/deletion-preflights":
        if not isinstance(session, Mapping):
            raise LifecycleV2SessionError("protected_session_required")
        service.register_session_resources(
            subject=str(session.get("principal_id") or ""),
            session=session,
            now=now,
        )
        if provider_sync is not None:
            account_id = str(session.get("account_id") or "")
            provider_sync.synchronize(
                account_id=account_id,
                registry_records=service.repository.registry_records(account_id),
            )
        result = service.preflight(
            subject=str(session.get("principal_id") or ""),
            requested_scope=str(body.get("scope") or ""),
        )
        if str(result.get("account_id") or "") != str(session.get("account_id") or ""):
            raise LifecycleV2SessionError("protected_session_account_mismatch")
        return _response(201, result)

    match = _OPERATION_PATH.fullmatch(path)
    if match and method == "POST" and match.group(2) == "/confirm":
        if not isinstance(session, Mapping) or status_codec is None:
            raise LifecycleV2SessionError("protected_session_required")
        if str(body.get("operation_id") or "") != match.group(1):
            raise LifecycleV2Error("operation_id_mismatch")
        result = service.confirm(
            subject=str(session.get("principal_id") or ""),
            operation_id=match.group(1),
            plan_digest=str(body.get("plan_digest") or ""),
            confirmation=str(body.get("confirmation") or ""),
        )
        if str(result.get("account_id") or "") != str(session.get("account_id") or ""):
            raise LifecycleV2SessionError("protected_session_account_mismatch")
        if enqueue is not None:
            enqueue(result)
        return _response(202, {
            **result,
            "status_token": status_codec.issue(
                operation_id=match.group(1),
                account_id=str(result["account_id"]),
            ),
        })

    if match and method == "GET" and match.group(2) is None:
        if status_codec is None:
            raise LifecycleV2StatusTokenError("status_token_configuration_invalid")
        token = _header(event, "x-kaevo-lifecycle-status")
        payload = status_codec.verify(token, expected_operation_id=match.group(1))
        return _response(200, service.status_for_account(
            account_id=str(payload["account_id"]), operation_id=match.group(1),
        ))

    return _response(404, {"state": "not_found"})


def _service() -> AccountLifecycleV2Service:
    dynamodb = boto3.resource("dynamodb")
    lifecycle_table = os.environ.get("ACCOUNT_LIFECYCLE_V2_TABLE", "").strip()
    auth_table = os.environ.get("AUTH_IDENTITIES_TABLE", "").strip()
    sessions_table = os.environ.get("APP_SESSIONS_TABLE", "").strip()
    installations_table = os.environ.get("INSTALLATIONS_TABLE", "").strip()
    profile_mappings_table = os.environ.get("PROFILE_MAPPINGS_TABLE", "").strip()
    if (
        not lifecycle_table or not auth_table or not sessions_table
        or not installations_table or not profile_mappings_table
    ):
        raise LifecycleV2StorageError("lifecycle_configuration_missing")
    return AccountLifecycleV2Service(DynamoLifecycleV2Repository(
        lifecycle_table=dynamodb.Table(lifecycle_table),
        auth_identities_table=dynamodb.Table(auth_table),
        installations_table=dynamodb.Table(installations_table),
        app_sessions_table=dynamodb.Table(sessions_table),
        profile_mappings_table=dynamodb.Table(profile_mappings_table),
    ))


def _authenticator() -> ProtectedLifecycleV2SessionAuthenticator:
    dynamodb = boto3.resource("dynamodb")
    sessions = os.environ.get("APP_SESSIONS_TABLE", "").strip()
    installations = os.environ.get("INSTALLATIONS_TABLE", "").strip()
    public_base_url = os.environ.get("PUBLIC_API_BASE_URL", "").strip()
    if not sessions or not installations or not public_base_url:
        raise LifecycleV2StorageError("lifecycle_configuration_missing")
    return ProtectedLifecycleV2SessionAuthenticator(
        app_sessions_table=dynamodb.Table(sessions),
        installations_table=dynamodb.Table(installations),
        public_base_url=public_base_url,
    )


def _status_codec() -> LifecycleV2StatusTokenCodec:
    return LifecycleV2StatusTokenCodec(
        os.environ.get("ACCOUNT_LIFECYCLE_V2_STATUS_SIGNING_KEY", ""),
    )


def _provider_sync(service: AccountLifecycleV2Service):
    dynamodb = boto3.resource("dynamodb")
    profiles = os.environ.get("IDENTITY_PROFILES_TABLE", "").strip()
    connectors = os.environ.get("HOME_CONNECTORS_TABLE", "").strip()
    if not profiles or not connectors:
        raise LifecycleV2StorageError("lifecycle_configuration_missing")
    return ExactLifecycleV2ProviderRegistrySync(
        lifecycle_table=service.repository.lifecycle_table,
        identity_profiles_table=dynamodb.Table(profiles),
        home_connectors_table=dynamodb.Table(connectors),
        clock=lambda: int(time.time()),
    )


def _enqueue(operation: Mapping[str, Any]) -> None:
    queue_url = os.environ.get("ACCOUNT_LIFECYCLE_V2_QUEUE_URL", "").strip()
    account_id = str(operation.get("account_id") or "")
    operation_id = str(operation.get("operation_id") or "")
    if not queue_url or not account_id or not operation_id:
        raise LifecycleV2StorageError("lifecycle_queue_configuration_missing")
    boto3.client("sqs").send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps({
            "schema_version": 2,
            "account_id": account_id,
            "operation_id": operation_id,
        }, separators=(",", ":"), sort_keys=True),
    )


def lambda_handler(event: Mapping[str, Any], _context: Any) -> dict[str, Any]:
    try:
        service = _service()
        session = None
        if _method(event) == "POST":
            session = _authenticator().authenticate(event)
        return handle(
            event,
            service=service,
            session=session,
            status_codec=_status_codec(),
            enqueue=_enqueue,
            provider_sync=_provider_sync(service),
        )
    except LifecycleV2SessionError as error:
        LOGGER.info(
            "account_lifecycle_v2_session_rejected reason=%s method=%s path=%s stage=%s",
            error.reason,
            _method(event),
            _path(event),
            str((event.get("requestContext") or {}).get("stage") or ""),
        )
        return _response(401, {"state": "not_authorized"})
    except LifecycleV2StatusTokenError as error:
        LOGGER.info(
            "account_lifecycle_v2_status_token_rejected reason=%s method=%s path=%s",
            error.reason,
            _method(event),
            _path(event),
        )
        return _response(401, {"state": "not_authorized"})
    except LifecycleV2Error as error:
        status = 409 if error.reason == "provider_deletion_not_enabled" else 400
        return _response(status, {"state": error.reason})
    except LifecycleV2StorageError as error:
        if error.reason == "lifecycle_root_missing":
            return _response(409, {"state": "lifecycle_migration_required"})
        if error.reason == "operation_not_found":
            return _response(404, {"state": "operation_not_found"})
        if error.reason == "operation_confirmation_conflict":
            return _response(409, {"state": "operation_confirmation_conflict"})
        LOGGER.warning("account_lifecycle_v2_storage_failure reason=%s", error.reason)
        return _response(503, {"state": "temporarily_unavailable"})
    except Exception:
        LOGGER.exception("account_lifecycle_v2_unhandled")
        return _response(503, {"state": "temporarily_unavailable"})
