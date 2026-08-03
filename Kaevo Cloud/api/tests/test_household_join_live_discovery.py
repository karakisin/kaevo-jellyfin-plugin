from __future__ import annotations

from scripts.household_join_live.discovery import exact_read_transactions, query_invitation_transactions


class Dynamo:
    def __init__(self):
        self.query_calls = []
        self.get_calls = []
        self.scan_calls = 0

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        return {"Items": [{"join_resume_hash": {"S": "opaque-a"}}, {"join_resume_hash": {"S": "opaque-b"}}]}

    def get_item(self, **kwargs):
        self.get_calls.append(kwargs)
        return {"Item": {**kwargs["Key"], "invitation_id": {"S": "fixture-owned"}}}

    def scan(self, **_kwargs):
        self.scan_calls += 1
        raise AssertionError("scan is prohibited")


def test_watcher_queries_the_exact_invitation_index_then_consistently_reads_each_result():
    client = Dynamo()
    keys = query_invitation_transactions(dynamodb_client=client, table_name="safe-table", invitation_id="fixture-invitation")
    records = exact_read_transactions(dynamodb_client=client, table_name="safe-table", keys=keys)
    assert len(keys) == 2
    assert len(records) == 2
    assert client.query_calls[0]["IndexName"] == "invitation_id-created_at_epoch-index"
    assert all(call["ConsistentRead"] for call in client.get_calls)
    assert client.scan_calls == 0
