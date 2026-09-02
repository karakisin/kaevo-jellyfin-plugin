from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time

import boto3
from botocore.exceptions import ClientError


CONTROL_PROTOCOL_VERSION = 2
MINIMUM_CONTROL_PROTOCOL_VERSION = 2
TICKET_TTL_SECONDS = 90
CONNECTION_TTL_SECONDS = 2 * 60 * 60 + 5 * 60
KEEPALIVE_SECONDS = 300

KAEVO_ENV = os.environ.get("KAEVO_ENV", "dev").strip().lower()
CONNECTIONS_TABLE_NAME = os.environ.get("CONNECTIONS_TABLE", "")
HOME_CONNECTORS_TABLE_NAME = os.environ.get("HOME_CONNECTORS_TABLE", "")
REMOTE_REQUESTS_TABLE_NAME = os.environ.get("REMOTE_REQUESTS_TABLE", "")
CONTROL_WEBSOCKET_URL = os.environ.get("CONTROL_WEBSOCKET_URL", "").rstrip("/")

dynamodb = boto3.resource("dynamodb")
connections_table = dynamodb.Table(CONNECTIONS_TABLE_NAME) if CONNECTIONS_TABLE_NAME else None
home_connectors_table = dynamodb.Table(HOME_CONNECTORS_TABLE_NAME) if HOME_CONNECTORS_TABLE_NAME else None
remote_requests_table = dynamodb.Table(REMOTE_REQUESTS_TABLE_NAME) if REMOTE_REQUESTS_TABLE_NAME else None
LOGGER = logging.getLogger("kaevo.websocket_control")


def epoch_now() -> int:
    return int(time.time())


def ticket_digest(ticket: str) -> str:
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


def connector_fingerprint(connector_id: str) -> str:
    return hashlib.sha256(f"connector:{connector_id}".encode("utf-8")).hexdigest()[:20]


def json_response(status_code: int, state: str, **fields):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        },
        "body": json.dumps({"state": state, **fields}, separators=(",", ":")),
    }


def websocket_response(status_code: int = 200):
    return {"statusCode": status_code}


def request_header(event: dict, name: str) -> str:
    target = name.lower()
    return str(next((value for key, value in (event.get("headers") or {}).items() if key.lower() == target), "") or "")


def management_client(event: dict):
    request_context = event.get("requestContext") or {}
    domain = str(request_context.get("domainName") or "")
    stage = str(request_context.get("stage") or "")
    if not domain or not stage:
        raise ValueError("websocketManagementEndpointMissing")
    return boto3.client("apigatewaymanagementapi", endpoint_url=f"https://{domain}/{stage}")


def post_opaque_notification(client, connection_id: str, request_id: str) -> None:
    payload = json.dumps({
        "type": "remote_request_available",
        "request_id": request_id,
        "connector_control_protocol": CONTROL_PROTOCOL_VERSION,
    }, separators=(",", ":")).encode("utf-8")
    client.post_to_connection(ConnectionId=connection_id, Data=payload)


def delete_connection_if_current(connector_id: str, connection_id: str) -> None:
    if connections_table is None:
        return
    try:
        connections_table.delete_item(
            Key={"record_key": f"connector#{connector_id}"},
            ConditionExpression="connection_id = :connection_id",
            ExpressionAttributeValues={":connection_id": connection_id},
        )
    except ClientError as error:
        if str(error.response.get("Error", {}).get("Code") or "") != "ConditionalCheckFailedException":
            raise
    connections_table.delete_item(Key={"record_key": f"connection#{connection_id}"})


def constant_time_binding_equal(left: str, right: str) -> bool:
    return bool(left and right) and hmac.compare_digest(str(left), str(right))
