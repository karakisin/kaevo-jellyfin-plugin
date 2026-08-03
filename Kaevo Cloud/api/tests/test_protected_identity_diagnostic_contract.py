from __future__ import annotations

import importlib.util
import logging
import os
from pathlib import Path


os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

HANDLER_PATH = Path(__file__).resolve().parents[1] / "src" / "handler.py"
SPEC = importlib.util.spec_from_file_location("kaevo_protected_identity_diagnostic_handler", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


class Table:
    def __init__(self, items):
        self.items = dict(items)

    def get_item(self, *, Key, **_kwargs):
        key = next(iter(Key.values()))
        item = self.items.get(key)
        return {"Item": dict(item)} if item else {}


def protected_event(*, token, proof="proof-canary"):
    return {
        "rawPath": "/v3/identity/profile-mappings",
        "headers": {"authorization": f"Bearer {token}", "dpop": proof},
        "requestContext": {"http": {"method": "GET"}},
        "_kaevo_lambda_request_fingerprint": "request-fingerprint-canary",
    }


def test_protected_identity_dpop_rejection_is_safe_and_redacted(monkeypatch, caplog):
    token = "access-token-canary"
    subject = "fixture-subject-canary"
    installation_id = "installation-fixture-canary"
    session = {
        "record_type": "access",
        "state": "active",
        "expires_at": handler.epoch_now() + 120,
        "principal_id": subject,
        "installation_id": installation_id,
        "key_thumbprint": "thumbprint-canary",
    }
    monkeypatch.setattr(handler, "KAEVO_ENV", "dev")
    monkeypatch.setattr(handler, "production_token_hash", lambda _token: "token-hash")
    monkeypatch.setattr(handler, "app_sessions_table", Table({"access#token-hash": session}))
    monkeypatch.setattr(handler, "installations_table", Table({installation_id: {"state": "active", "key_thumbprint": "thumbprint-canary"}}))
    monkeypatch.setattr(
        handler,
        "verify_dpop",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(handler.IdentityError("dpop_url_mismatch", 401)),
    )
    caplog.set_level(logging.WARNING, logger=handler.__name__)

    assert handler.authenticated_app_session(protected_event(token=token)) is None

    records = [record for record in caplog.records if handler.PROTECTED_IDENTITY_DIAGNOSTIC_EVENT in record.message]
    assert len(records) == 1
    assert '"reason_category":"DPOP_HTU_MISMATCH"' in records[0].message
    for sensitive in (token, subject, installation_id, "proof-canary", "thumbprint-canary"):
        assert sensitive not in records[0].message


def test_protected_identity_diagnostic_failure_preserves_fail_closed_result(monkeypatch):
    class BrokenLogger:
        def warning(self, *_args, **_kwargs):
            raise RuntimeError("diagnostic sink unavailable")

    token = "inactive-token-canary"
    monkeypatch.setattr(handler, "KAEVO_ENV", "dev")
    monkeypatch.setattr(handler, "production_token_hash", lambda _token: "inactive-token-hash")
    monkeypatch.setattr(handler, "app_sessions_table", Table({"access#inactive-token-hash": {
        "record_type": "access", "state": "revoked", "expires_at": handler.epoch_now() + 120,
    }}))
    monkeypatch.setattr(handler, "LOGGER", BrokenLogger())

    assert handler.authenticated_app_session(protected_event(token=token)) is None
