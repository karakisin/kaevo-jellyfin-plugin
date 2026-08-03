"""No-scan discovery of app-created Join transactions."""

from __future__ import annotations

from collections.abc import Mapping

from .constants import JOIN_TRANSACTION_INVITATION_INDEX
from .errors import FixtureSafetyError


def query_invitation_transactions(*, dynamodb_client: object, table_name: str, invitation_id: str) -> list[dict]:
    """Return exact base-table keys for one protected fixture invitation.

    The index projection exposes only the base primary key.  Each caller must
    exact-read and attribute every returned row before journaling it.  This
    helper deliberately exposes no Scan operation or output side effects.
    """
    if not invitation_id:
        raise FixtureSafetyError("INVITATION_LOCATOR_REQUIRED")
    keys: list[dict] = []
    cursor = None
    while True:
        request = {
            "TableName": table_name,
            "IndexName": JOIN_TRANSACTION_INVITATION_INDEX,
            "KeyConditionExpression": "#invitation_id = :invitation_id",
            "ExpressionAttributeNames": {"#invitation_id": "invitation_id"},
            "ExpressionAttributeValues": {":invitation_id": {"S": invitation_id}},
            "ProjectionExpression": "join_resume_hash",
        }
        if cursor is not None:
            request["ExclusiveStartKey"] = cursor
        response = dynamodb_client.query(**request)
        for item in response.get("Items") or []:
            key = {"join_resume_hash": item.get("join_resume_hash")}
            value = key["join_resume_hash"]
            if not isinstance(value, Mapping) or not isinstance(value.get("S"), str) or not value["S"]:
                raise FixtureSafetyError("QUERY_RESULT_KEY_INVALID")
            if key not in keys:
                keys.append(key)
        cursor = response.get("LastEvaluatedKey")
        if not cursor:
            return keys


def exact_read_transactions(*, dynamodb_client: object, table_name: str, keys: list[dict]) -> list[dict]:
    """Consistently read every GSI result; never infer from index projection."""
    records: list[dict] = []
    for key in keys:
        response = dynamodb_client.get_item(TableName=table_name, Key=key, ConsistentRead=True)
        item = response.get("Item")
        if not isinstance(item, dict):
            raise FixtureSafetyError("QUERY_RESULT_DISAPPEARED")
        records.append(item)
    return records
