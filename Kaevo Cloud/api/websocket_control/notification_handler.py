from __future__ import annotations

from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError

from websocket_control import common


DESERIALIZER = TypeDeserializer()


def _deserialize_image(image: dict) -> dict:
    return {key: DESERIALIZER.deserialize(value) for key, value in image.items()}


def notify_pending_request(record: dict) -> None:
    event_name = str(record.get("eventName") or "")
    if event_name not in {"INSERT", "MODIFY"}:
        return
    new_image = ((record.get("dynamodb") or {}).get("NewImage") or {})
    if not new_image:
        return
    item = _deserialize_image(new_image)
    if str(item.get("status") or "") != "pending":
        return
    connector_id = str(item.get("connector_id") or "")
    request_id = str(item.get("request_id") or "")
    if not connector_id or not request_id or common.connections_table is None or common.home_connectors_table is None:
        return
    now = common.epoch_now()
    connector = common.home_connectors_table.get_item(
        Key={"connector_id": connector_id}, ConsistentRead=True,
    ).get("Item", {})
    connection = common.connections_table.get_item(
        Key={"record_key": f"connector#{connector_id}"}, ConsistentRead=True,
    ).get("Item", {})
    if (
        str(connector.get("state") or "") != "active"
        or str(connector.get("auth_state") or "") != "v3_active"
        or bool(connector.get("revoked"))
        or str(connection.get("environment") or "") != common.KAEVO_ENV
        or int(connection.get("expires_at") or 0) < now
        or not common.constant_time_binding_equal(
            str(connector.get("family_binding") or ""),
            str(connection.get("household_binding") or ""),
        )
    ):
        return
    connection_id = str(connection.get("connection_id") or "")
    if not connection_id:
        return
    endpoint = common.CONTROL_WEBSOCKET_URL.replace("wss://", "https://", 1)
    client = common.boto3.client("apigatewaymanagementapi", endpoint_url=endpoint)
    try:
        common.post_opaque_notification(client, connection_id, request_id)
        common.LOGGER.info(
            "control_notified connector=%s",
            common.connector_fingerprint(connector_id),
        )
    except client.exceptions.GoneException:
        common.delete_connection_if_current(connector_id, connection_id)


def lambda_handler(event, _context):
    failures = []
    for record in event.get("Records") or []:
        try:
            notify_pending_request(record)
        except ClientError:
            sequence_number = str(((record.get("dynamodb") or {}).get("SequenceNumber") or ""))
            if sequence_number:
                failures.append({"itemIdentifier": sequence_number})
    return {"batchItemFailures": failures}
