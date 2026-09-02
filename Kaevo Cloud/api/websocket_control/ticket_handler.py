from __future__ import annotations

import re
import secrets

from botocore.exceptions import ClientError

from connector_control import connector_control_handler as connector_control
from websocket_control import common


CONTROL_TICKET_ROUTE = re.compile(r"^/v3/home-connectors/([^/]+)/control-ticket$")
EXACT_CLAIM_ROUTE = re.compile(r"^/v3/remote-requests/([^/]+)/claim$")


def _protocol_version(body: dict) -> int:
    value = body.get("connector_control_protocol")
    if isinstance(value, bool):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def issue_ticket(event: dict, connector_id: str):
    body = connector_control.parse_json_body(event)
    if body is None:
        return common.json_response(400, "bad_request", code="invalid_json")
    connector = connector_control.authenticate_connector(event, connector_id, body)
    if not connector:
        return connector_control._auth_failure()
    protocol_version = _protocol_version(body)
    if protocol_version < common.MINIMUM_CONTROL_PROTOCOL_VERSION:
        result = common.json_response(
            426,
            "upgrade_required",
            minimum_connector_control_protocol=common.MINIMUM_CONTROL_PROTOCOL_VERSION,
            retry_after_seconds=60,
        )
        result["headers"]["Retry-After"] = "60"
        return result
    household_binding = str(connector.get("family_binding") or "")
    if not household_binding or common.connections_table is None or not common.CONTROL_WEBSOCKET_URL:
        return common.json_response(503, "control_channel_unavailable")

    ticket = secrets.token_urlsafe(48)
    now = common.epoch_now()
    try:
        common.connections_table.put_item(
            Item={
                "record_key": f"ticket#{common.ticket_digest(ticket)}",
                "record_type": "connector_control_ticket",
                "connector_id": connector_id,
                "household_binding": household_binding,
                "environment": common.KAEVO_ENV,
                "connector_control_protocol": common.CONTROL_PROTOCOL_VERSION,
                "created_at": now,
                "expires_at": now + common.TICKET_TTL_SECONDS,
            },
            ConditionExpression="attribute_not_exists(record_key)",
        )
    except ClientError:
        return common.json_response(503, "control_channel_unavailable")

    common.LOGGER.info("control_ticket_issued connector=%s", common.connector_fingerprint(connector_id))
    return common.json_response(
        201,
        "issued",
        connection_ticket=ticket,
        control_websocket_url=common.CONTROL_WEBSOCKET_URL,
        connector_control_protocol=common.CONTROL_PROTOCOL_VERSION,
        minimum_connector_control_protocol=common.MINIMUM_CONTROL_PROTOCOL_VERSION,
        keepalive_seconds=common.KEEPALIVE_SECONDS,
        expires_at=now + common.TICKET_TTL_SECONDS,
    )


def claim_exact(event: dict, request_id: str):
    body = connector_control.parse_json_body(event)
    if body is None:
        return common.json_response(400, "bad_request", code="invalid_json")
    if _protocol_version(body) < common.MINIMUM_CONTROL_PROTOCOL_VERSION:
        return common.json_response(
            426,
            "upgrade_required",
            minimum_connector_control_protocol=common.MINIMUM_CONTROL_PROTOCOL_VERSION,
        )
    if connector_control.remote_requests_table is None:
        return common.json_response(503, "dependency_failure")
    try:
        item = connector_control.remote_requests_table.get_item(
            Key={"request_id": request_id}, ConsistentRead=True,
        ).get("Item")
    except ClientError:
        return common.json_response(503, "dependency_failure")
    if not item:
        return common.json_response(404, "not_found", request_id=request_id)
    connector_id = str(item.get("connector_id") or "")
    body_connector_id = str(body.get("connector_id") or "")
    if not connector_id or not body_connector_id or body_connector_id != connector_id:
        return common.json_response(403, "connector_mismatch")
    if not connector_control.authenticate_connector(event, connector_id, body):
        return connector_control._auth_failure()
    if int(item.get("expires_at") or 0) < common.epoch_now():
        return common.json_response(410, "request_expired", request_id=request_id)

    now = connector_control.utc_now_iso()
    try:
        claimed = connector_control.remote_requests_table.update_item(
            Key={"request_id": request_id},
            ConditionExpression="#status = :pending AND expires_at >= :now_epoch AND connector_id = :connector_id",
            UpdateExpression=(
                "SET #status = :in_progress, claimed_at = :now, updated_at = :now, "
                "status_created_at = :sort"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":pending": "pending",
                ":in_progress": "in_progress",
                ":now": now,
                ":now_epoch": common.epoch_now(),
                ":connector_id": connector_id,
                ":sort": connector_control._status_sort_key("in_progress", now, request_id),
            },
            ReturnValues="ALL_NEW",
        ).get("Attributes", {})
    except ClientError as error:
        if str(error.response.get("Error", {}).get("Code") or "") == "ConditionalCheckFailedException":
            return common.json_response(409, "request_not_pending", request_id=request_id)
        return common.json_response(503, "dependency_failure")
    connector_control._mirror_binding_operation(claimed, "connector_claimed")
    return connector_control.response(
        200,
        "claimed",
        request=connector_control.public_remote_request(claimed),
    )


def lambda_handler(event, _context):
    path = connector_control.normalized_path(event)
    if connector_control.method_for(event) != "POST":
        return common.json_response(405, "method_not_allowed")
    ticket_match = CONTROL_TICKET_ROUTE.fullmatch(path)
    if ticket_match:
        return issue_ticket(event, ticket_match.group(1))
    claim_match = EXACT_CLAIM_ROUTE.fullmatch(path)
    if claim_match:
        return claim_exact(event, claim_match.group(1))
    return common.json_response(404, "not_found")
