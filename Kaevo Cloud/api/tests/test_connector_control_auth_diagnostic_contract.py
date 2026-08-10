from __future__ import annotations

import importlib.util
import json
import logging
import os
from pathlib import Path


os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

HANDLER_PATH = Path(__file__).resolve().parents[1] / "connector_control" / "connector_control_handler.py"
SPEC = importlib.util.spec_from_file_location("kaevo_connector_control_auth_diagnostic", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


class Table:
    def __init__(self, items=None):
        self.items = dict(items or {})

    def get_item(self, *, Key, **_kwargs):
        key = next(iter(Key.values()))
        item = self.items.get(key)
        return {"Item": dict(item)} if item else {}


def event(path, *, headers=None):
    return {
        "rawPath": path,
        "headers": dict(headers or {}),
        "requestContext": {"http": {"method": "POST"}},
    }


def records(caplog):
    return [record for record in caplog.records if control.CONNECTOR_AUTH_DIAGNOSTIC_EVENT in record.message]


def test_missing_connector_diagnostic_is_route_bounded_and_redacted(monkeypatch, caplog):
    connector_id = "connector-secret-canary"
    request_id = "request-secret-canary"
    signature = "signature-secret-canary"
    monkeypatch.setattr(control, "home_connectors_table", Table())
    monkeypatch.setattr(control, "app_sessions_table", Table())
    caplog.set_level(logging.WARNING, logger=control.__name__)

    assert control.authenticate_connector(
        event(f"/v3/remote-requests/{request_id}/complete", headers={"x-kaevo-plugin-signature": signature}),
        connector_id,
        {"connector_id": connector_id},
    ) is None

    found = records(caplog)
    assert len(found) == 1
    payload = json.loads(found[0].message)
    assert payload["reason_category"] == "CONNECTOR_NOT_FOUND"
    assert payload["route_category"] == "remote_request_complete"
    assert payload["connector_fingerprint"]
    for sensitive in (connector_id, request_id, signature):
        assert sensitive not in found[0].message


def test_diagnostic_failure_preserves_fail_closed_result(monkeypatch):
    class BrokenLogger:
        def warning(self, *_args, **_kwargs):
            raise RuntimeError("diagnostic sink unavailable")

    monkeypatch.setattr(control, "home_connectors_table", Table())
    monkeypatch.setattr(control, "app_sessions_table", Table())
    monkeypatch.setattr(control, "LOGGER", BrokenLogger())

    assert control.authenticate_connector(
        event("/v3/remote-requests/claim"),
        "missing-connector",
        {"connector_id": "missing-connector"},
    ) is None
