from __future__ import annotations

import json

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from websocket_control import common


def _connection_id(event: dict) -> str:
    return str((event.get("requestContext") or {}).get("connectionId") or "")


def _authorization_ticket(event: dict) -> str:
    authorization = common.request_header(event, "authorization")
    prefix = "Bearer "
    return authorization[len(prefix):].strip() if authorization.startswith(prefix) else ""


def connect(event: dict):
    if common.connections_table is None or common.home_connectors_table is None:
        return common.websocket_response(503)
    connection_id = _connection_id(event)
    ticket = _authorization_ticket(event)
    if not connection_id or not ticket:
        return common.websocket_response(401)
    ticket_key = f"ticket#{common.ticket_digest(ticket)}"
    now = common.epoch_now()
    try:
        ticket_record = common.connections_table.update_item(
            Key={"record_key": ticket_key},
            ConditionExpression=(
                "record_type = :record_type AND environment = :environment "
                "AND expires_at >= :now AND attribute_not_exists(used_at)"
            ),
            UpdateExpression="SET used_at = :now, connection_id = :connection_id",
            ExpressionAttributeValues={
                ":record_type": "connector_control_ticket",
                ":environment": common.KAEVO_ENV,
                ":now": now,
                ":connection_id": connection_id,
            },
            ReturnValues="ALL_NEW",
        ).get("Attributes", {})
    except ClientError as error:
        code = str(error.response.get("Error", {}).get("Code") or "")
        return common.websocket_response(401 if code == "ConditionalCheckFailedException" else 503)

    connector_id = str(ticket_record.get("connector_id") or "")
    household_binding = str(ticket_record.get("household_binding") or "")
    protocol = int(ticket_record.get("connector_control_protocol") or 0)
    if not connector_id or not household_binding or protocol < common.MINIMUM_CONTROL_PROTOCOL_VERSION:
        return common.websocket_response(401)
    connector = common.home_connectors_table.get_item(
        Key={"connector_id": connector_id}, ConsistentRead=True,
    ).get("Item", {})
    if (
        str(connector.get("state") or "") != "active"
        or str(connector.get("auth_state") or "") != "v3_active"
        or bool(connector.get("revoked"))
        or not common.constant_time_binding_equal(
            str(connector.get("family_binding") or ""), household_binding,
        )
    ):
        return common.websocket_response(401)
    expires_at = now + common.CONNECTION_TTL_SECONDS
    connection_record = {
        "record_key": f"connector#{connector_id}",
        "record_type": "active_connector_control_connection",
        "connector_id": connector_id,
        "household_binding": household_binding,
        "environment": common.KAEVO_ENV,
        "connection_id": connection_id,
        "connector_control_protocol": protocol,
        "connected_at": now,
        "last_seen_at": now,
        "expires_at": expires_at,
    }
    reverse_record = {
        **connection_record,
        "record_key": f"connection#{connection_id}",
        "record_type": "connector_control_connection_lookup",
    }
    try:
        common.connections_table.put_item(Item=connection_record)
        common.connections_table.put_item(Item=reverse_record)
    except ClientError:
        return common.websocket_response(503)
    common.LOGGER.info("control_connected connector=%s", common.connector_fingerprint(connector_id))
    return common.websocket_response(200)


def disconnect(event: dict):
    if common.connections_table is None:
        return common.websocket_response(200)
    connection_id = _connection_id(event)
    if not connection_id:
        return common.websocket_response(200)
    reverse = common.connections_table.get_item(
        Key={"record_key": f"connection#{connection_id}"}, ConsistentRead=True,
    ).get("Item", {})
    connector_id = str(reverse.get("connector_id") or "")
    if connector_id:
        common.delete_connection_if_current(connector_id, connection_id)
        common.LOGGER.info("control_disconnected connector=%s", common.connector_fingerprint(connector_id))
    return common.websocket_response(200)


def _authorized_connection(event: dict):
    if common.connections_table is None or common.home_connectors_table is None:
        return None
    connection_id = _connection_id(event)
    if not connection_id:
        return None
    reverse = common.connections_table.get_item(
        Key={"record_key": f"connection#{connection_id}"}, ConsistentRead=True,
    ).get("Item")
    if not reverse or int(reverse.get("expires_at") or 0) < common.epoch_now():
        return None
    if str(reverse.get("environment") or "") != common.KAEVO_ENV:
        return None
    connector_id = str(reverse.get("connector_id") or "")
    connector = common.home_connectors_table.get_item(
        Key={"connector_id": connector_id}, ConsistentRead=True,
    ).get("Item", {})
    if (
        not connector_id
        or str(connector.get("state") or "") != "active"
        or str(connector.get("auth_state") or "") != "v3_active"
        or bool(connector.get("revoked"))
        or not common.constant_time_binding_equal(
            str(connector.get("family_binding") or ""),
            str(reverse.get("household_binding") or ""),
        )
    ):
        return None
    return reverse


def ping_or_recover(event: dict):
    connection = _authorized_connection(event)
    if not connection:
        return common.websocket_response(401)
    connection_id = str(connection["connection_id"])
    connector_id = str(connection["connector_id"])
    body = json.loads(event.get("body") or "{}")
    action = str(body.get("action") or "")
    if int(body.get("connector_control_protocol") or 0) < common.MINIMUM_CONTROL_PROTOCOL_VERSION:
        return common.websocket_response(426)
    now = common.epoch_now()
    common.connections_table.update_item(
        Key={"record_key": f"connector#{connector_id}"},
        ConditionExpression="connection_id = :connection_id",
        UpdateExpression="SET last_seen_at = :now, expires_at = :expires_at",
        ExpressionAttributeValues={
            ":connection_id": connection_id,
            ":now": now,
            ":expires_at": now + common.CONNECTION_TTL_SECONDS,
        },
    )
    common.connections_table.update_item(
        Key={"record_key": f"connection#{connection_id}"},
        ConditionExpression="connector_id = :connector_id",
        UpdateExpression="SET last_seen_at = :now, expires_at = :expires_at",
        ExpressionAttributeValues={
            ":connector_id": connector_id,
            ":now": now,
            ":expires_at": now + common.CONNECTION_TTL_SECONDS,
        },
    )
    client = common.management_client(event)
    if action == "ping":
        client.post_to_connection(
            ConnectionId=connection_id,
            Data=json.dumps({
                "type": "pong",
                "connector_control_protocol": common.CONTROL_PROTOCOL_VERSION,
            }, separators=(",", ":")).encode("utf-8"),
        )
        return common.websocket_response(200)
    if action != "recover" or common.remote_requests_table is None:
        return common.websocket_response(400)

    items = common.remote_requests_table.query(
        IndexName="connector_id-status_created_at-index",
        KeyConditionExpression=(
            Key("connector_id").eq(connector_id)
            & Key("status_created_at").begins_with("pending#")
        ),
        ScanIndexForward=True,
        Limit=8,
    ).get("Items", [])
    for item in items:
        if int(item.get("expires_at") or 0) >= now:
            common.post_opaque_notification(client, connection_id, str(item["request_id"]))
    return common.websocket_response(200)


def lambda_handler(event, _context):
    route_key = str((event.get("requestContext") or {}).get("routeKey") or "")
    try:
        if route_key == "$connect":
            return connect(event)
        if route_key == "$disconnect":
            return disconnect(event)
        if route_key in {"ping", "recover"}:
            return ping_or_recover(event)
        return common.websocket_response(400)
    except (ClientError, ValueError, TypeError, json.JSONDecodeError):
        return common.websocket_response(503)
