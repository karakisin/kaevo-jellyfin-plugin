import json
import logging

import pytest

import account_lifecycle_v2_api as api
from account_lifecycle_v2_status_token import LifecycleV2StatusTokenCodec


NOW = 1_800_000_000
OPERATION_ID = "ald2_0123456789abcdef0123456789abcdef"


class Service:
    def __init__(self):
        self.calls = []

    def preflight(self, **values):
        self.calls.append(("preflight", values))
        return {
            "operation_id": OPERATION_ID,
            "account_id": "acct_0123456789abcdef01234567",
            "can_confirm": True,
        }

    def register_session_resources(self, **values):
        self.calls.append(("register_session_resources", values))
        return "acct_0123456789abcdef01234567"

    def confirm(self, **values):
        self.calls.append(("confirm", values))
        return {
            "operation_id": OPERATION_ID,
            "account_id": "acct_0123456789abcdef01234567",
            "phase": "queued",
        }

    def status(self, **values):
        self.calls.append(("status", values))
        return {"operation_id": OPERATION_ID, "phase": "completed"}

    def status_for_account(self, **values):
        self.calls.append(("status_for_account", values))
        return {"operation_id": OPERATION_ID, "phase": "completed"}


def session():
    return {
        "principal_id": "opaque-subject-123",
        "account_id": "acct_0123456789abcdef01234567",
    }


def codec():
    return LifecycleV2StatusTokenCodec("s" * 64, clock=lambda: NOW)


def event(method, path, body=None, *, status_token=None):
    result = {
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "body": None if body is None else json.dumps(body),
    }
    if status_token:
        result["headers"] = {"X-Kaevo-Lifecycle-Status": status_token}
    return result


def decoded(response):
    return json.loads(response["body"])


def test_preflight_accepts_only_scope_from_native_access_token():
    service = Service()
    response = api.handle(
        event("POST", "/v4/account-lifecycle/deletion-preflights", {"scope": "everything"}),
        service=service,
        session=session(),
        status_codec=codec(),
        now=NOW,
    )

    assert response["statusCode"] == 201
    assert service.calls == [
        ("register_session_resources", {
            "subject": "opaque-subject-123", "session": session(), "now": NOW,
        }),
        ("preflight", {
            "subject": "opaque-subject-123", "requested_scope": "everything",
        }),
    ]


def test_preflight_routes_a_real_named_production_stage_event():
    service = Service()
    request = event(
        "POST",
        "/production/v4/account-lifecycle/deletion-preflights",
        {"scope": "everything"},
    )
    request["requestContext"]["stage"] = "production"

    response = api.handle(
        request,
        service=service,
        session=session(),
        status_codec=codec(),
        now=NOW,
    )

    assert response["statusCode"] == 201
    assert service.calls[-1] == (
        "preflight",
        {"subject": "opaque-subject-123", "requested_scope": "everything"},
    )


def test_confirmation_binds_operation_id_in_path_body_and_frozen_digest():
    service = Service()
    queued = []
    response = api.handle(
        event("POST", f"/v4/account-lifecycle/deletions/{OPERATION_ID}/confirm", {
            "operation_id": OPERATION_ID,
            "plan_digest": "aldp2_digest",
            "confirmation": "DELETE",
            "profile_ids": ["client-must-not-control-this"],
        }),
        service=service,
        session=session(),
        status_codec=codec(),
        enqueue=queued.append,
        now=NOW,
    )

    assert response["statusCode"] == 202
    assert service.calls == [("confirm", {
        "subject": "opaque-subject-123",
        "operation_id": OPERATION_ID,
        "plan_digest": "aldp2_digest",
        "confirmation": "DELETE",
    })]
    assert queued == [{
        "operation_id": OPERATION_ID,
        "account_id": "acct_0123456789abcdef01234567",
        "phase": "queued",
    }]
    assert decoded(response)["status_token"].startswith("alst2.")


def test_mismatched_operation_path_never_reaches_service():
    service = Service()
    with pytest.raises(api.LifecycleV2Error, match="operation_id_mismatch"):
        api.handle(
            event("POST", f"/v4/account-lifecycle/deletions/{OPERATION_ID}/confirm", {
                "operation_id": "ald2_abcdefghijklmnopqrstuvwxyz012345",
                "plan_digest": "aldp2_digest",
                "confirmation": "DELETE",
            }),
            service=service,
            session=session(),
            status_codec=codec(),
            now=NOW,
        )
    assert service.calls == []


def test_status_is_account_scoped_by_subject_not_client_account_id():
    service = Service()
    token = codec().issue(
        operation_id=OPERATION_ID,
        account_id="acct_0123456789abcdef01234567",
    )
    response = api.handle(
        event(
            "GET", f"/v4/account-lifecycle/deletions/{OPERATION_ID}",
            status_token=token,
        ),
        service=service,
        status_codec=codec(),
        now=NOW,
    )

    assert response["statusCode"] == 200
    assert service.calls == [("status_for_account", {
        "account_id": "acct_0123456789abcdef01234567", "operation_id": OPERATION_ID,
    })]


def test_status_rejects_a_missing_operation_status_token():
    with pytest.raises(api.LifecycleV2StatusTokenError):
        api.handle(
            event("GET", f"/v4/account-lifecycle/deletions/{OPERATION_ID}"),
            service=Service(),
            status_codec=codec(),
            now=NOW,
        )


def test_lambda_handler_logs_only_safe_session_rejection_context(monkeypatch, caplog):
    request = event(
        "POST",
        "/v4/account-lifecycle/deletion-preflights",
        {"scope": "kaevo_only"},
    )
    request["requestContext"]["stage"] = "production"
    request["headers"] = {
        "authorization": "Bearer must-not-appear",
        "dpop": "proof-must-not-appear",
    }

    class RejectingAuthenticator:
        def authenticate(self, _event):
            raise api.LifecycleV2SessionError("protected_session_proof_invalid")

    monkeypatch.setattr(api, "_service", Service)
    monkeypatch.setattr(api, "_authenticator", RejectingAuthenticator)
    with caplog.at_level(logging.INFO, logger=api.LOGGER.name):
        response = api.lambda_handler(request, None)

    assert response["statusCode"] == 401
    assert decoded(response) == {"state": "not_authorized"}
    output = caplog.text
    assert "reason=protected_session_proof_invalid" in output
    assert "method=POST" in output
    assert "path=/v4/account-lifecycle/deletion-preflights" in output
    assert "stage=production" in output
    assert "must-not-appear" not in output
    assert "proof-must-not-appear" not in output


def test_lambda_handler_rejects_missing_status_token_without_crashing(
    monkeypatch, caplog,
):
    request = event("GET", f"/v4/account-lifecycle/deletions/{OPERATION_ID}")

    monkeypatch.setattr(api, "_service", Service)
    monkeypatch.setattr(api, "_status_codec", codec)
    monkeypatch.setattr(api, "_provider_sync", lambda _service: None)
    with caplog.at_level(logging.INFO, logger=api.LOGGER.name):
        response = api.lambda_handler(request, None)

    assert response["statusCode"] == 401
    assert decoded(response) == {"state": "not_authorized"}
    assert "reason=status_token_invalid" in caplog.text
