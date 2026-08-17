from __future__ import annotations

import importlib.util
import hashlib
import json
import logging
import os
from pathlib import Path


os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

HANDLER_PATH = Path(__file__).resolve().parents[1] / "src" / "handler.py"
SPEC = importlib.util.spec_from_file_location("kaevo_pairing_v3_connector_auth_diagnostic_handler", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


class Table:
    def __init__(self, items=None):
        self.items = dict(items or {})

    def get_item(self, *, Key, **_kwargs):
        key = next(iter(Key.values()))
        item = self.items.get(key)
        return {"Item": dict(item)} if item else {}

    def put_item(self, *, Item, **_kwargs):
        key = Item.get("token_hash") or Item.get("connector_id")
        self.items[key] = dict(Item)


def connector_event(path, *, headers=None):
    return {
        "rawPath": path,
        "headers": dict(headers or {}),
        "requestContext": {"http": {"method": "POST"}},
        "_kaevo_lambda_request_fingerprint": "request-fingerprint-canary",
    }


def diagnostic_records(caplog):
    return [record for record in caplog.records if handler.PAIRING_V3_CONNECTOR_AUTH_DIAGNOSTIC_EVENT in record.message]


def test_missing_connector_diagnostic_is_route_bounded_and_redacted(monkeypatch, caplog):
    connector_id = "connector-secret-canary"
    request_id = "request-secret-canary"
    signature = "signature-secret-canary"
    event = connector_event(
        f"/v3/remote-requests/{request_id}/complete",
        headers={"x-kaevo-plugin-signature": signature},
    )
    monkeypatch.setattr(handler, "home_connectors_table", Table())
    monkeypatch.setattr(handler, "app_sessions_table", Table())
    caplog.set_level(logging.WARNING, logger=handler.__name__)

    assert handler.require_pairing_v3_connector_auth(event, connector_id, {"connector_id": connector_id}) is False

    records = diagnostic_records(caplog)
    assert len(records) == 1
    payload = json.loads(records[0].message)
    assert payload["reason_category"] == "CONNECTOR_NOT_FOUND"
    assert payload["route_category"] == "remote_request_complete"
    assert payload["connector_fingerprint"]
    for sensitive in (connector_id, request_id, signature):
        assert sensitive not in records[0].message


def test_signature_rejection_reports_only_allowlisted_category(monkeypatch, caplog):
    connector_id = "connector-signature-canary"
    public_key = b"k" * 32
    connector = {
        "connector_id": connector_id,
        "protocol_version": handler.PAIRING_V3_PROTOCOL,
        "auth_state": "v3_active",
        "state": "active",
        "plugin_public_key": handler.pairing_v3_b64url_encode(public_key),
        "plugin_public_key_fingerprint": handler.pairing_v3_plugin_fingerprint(public_key),
        "plugin_instance_id": "plugin-instance-canary",
        "plugin_key_id": "1",
    }
    event = connector_event("/v3/remote-requests/claim", headers={
        "x-kaevo-plugin-key-id": "1",
        "x-kaevo-plugin-timestamp": str(handler.epoch_now() * 1000),
        "x-kaevo-plugin-nonce": "nonce01234567890123456",
        "x-kaevo-plugin-signature": "signature-secret-canary",
    })
    monkeypatch.setattr(handler, "home_connectors_table", Table({connector_id: connector}))
    monkeypatch.setattr(handler, "app_sessions_table", Table())
    caplog.set_level(logging.WARNING, logger=handler.__name__)

    assert handler.require_pairing_v3_connector_auth(event, connector_id, {"connector_id": connector_id}) is False

    records = diagnostic_records(caplog)
    assert len(records) == 1
    payload = json.loads(records[0].message)
    assert payload["reason_category"] == "PLUGIN_SIGNATURE_INVALID"
    assert payload["route_category"] == "remote_request_claim"
    for sensitive in (connector_id, "plugin-instance-canary", "signature-secret-canary", "nonce01234567890123456"):
        assert sensitive not in records[0].message


def test_connector_auth_diagnostic_failure_preserves_fail_closed_result(monkeypatch):
    class BrokenLogger:
        def warning(self, *_args, **_kwargs):
            raise RuntimeError("diagnostic sink unavailable")

    monkeypatch.setattr(handler, "home_connectors_table", Table())
    monkeypatch.setattr(handler, "app_sessions_table", Table())
    monkeypatch.setattr(handler, "LOGGER", BrokenLogger())

    assert handler.require_pairing_v3_connector_auth(
        connector_event("/v3/remote-requests/claim"),
        "missing-connector",
        {"connector_id": "missing-connector"},
    ) is False


def test_signature_v2_verifies_the_exact_strict_utf8_body(monkeypatch):
    connector_id = "connector-v2-exact"
    seed = b"E" * 32
    public_key = handler.ed25519_public_key_from_seed(seed)
    fingerprint = handler.pairing_v3_plugin_fingerprint(public_key)
    connector = {
        "connector_id": connector_id,
        "protocol_version": handler.PAIRING_V3_PROTOCOL,
        "auth_state": "v3_active",
        "state": "active",
        "plugin_public_key": handler.pairing_v3_b64url_encode(public_key),
        "plugin_public_key_fingerprint": fingerprint,
        "plugin_instance_id": "plugin-v2-exact",
        "plugin_key_id": "1",
    }
    route = "/v3/remote-requests/request-v2/complete"
    raw_body = '{"connector_id":"connector-v2-exact","value":1.2300,"label":"a\u2060b"}'
    timestamp = str(handler.epoch_now() * 1000)
    nonce = "signaturev2exactnonce0123456789"
    digest = handler.pairing_v3_b64url_encode(hashlib.sha256(raw_body.encode("utf-8")).digest())
    transcript = handler.pairing_v3_canonical_transcript("connector-request", (
        ("httpMethod", "POST"), ("canonicalRoute", route), ("bodyDigest", digest),
        ("timestamp", timestamp), ("nonce", nonce), ("connectorId", connector_id),
        ("pluginInstanceId", "plugin-v2-exact"), ("pluginKeyId", "1"),
        ("pluginPublicKeyFingerprint", fingerprint),
    ))
    event = connector_event(route, headers={
        "x-kaevo-plugin-key-id": "1",
        "x-kaevo-plugin-timestamp": timestamp,
        "x-kaevo-plugin-nonce": nonce,
        "x-kaevo-plugin-signature": handler.pairing_v3_sign_ed25519(seed, transcript),
        "x-kaevo-plugin-signature-version": "2",
    })
    event["body"] = raw_body
    monkeypatch.setattr(handler, "home_connectors_table", Table({connector_id: connector}))
    monkeypatch.setattr(handler, "app_sessions_table", Table())

    assert handler.require_pairing_v3_connector_auth(event, connector_id, json.loads(raw_body)) is True


def test_signature_v2_rejects_duplicate_keys_and_nonstandard_numbers():
    for raw_body in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
        event = {"body": raw_body}
        try:
            handler._pairing_v3_exact_json_body_bytes(event)
        except handler.PairingV3CryptoError:
            pass
        else:
            raise AssertionError(f"strict v2 JSON accepted {raw_body}")
