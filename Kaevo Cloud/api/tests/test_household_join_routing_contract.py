import json

import handler


class Table:
    name = "test-table"

    def __init__(self, items=()):
        self.items = {item.get("code_hash") or item.get("join_resume_hash"): dict(item) for item in items}

    def get_item(self, *, Key, **_kwargs):
        item = self.items.get(Key.get("code_hash") or Key.get("join_resume_hash"))
        return {"Item": dict(item)} if item else {}

    def put_item(self, *, Item, **_kwargs):
        self.items[Item.get("code_hash") or Item.get("join_resume_hash")] = dict(Item)

    def update_item(self, *, Key, ExpressionAttributeValues, **_kwargs):
        key = Key["join_resume_hash"]
        if key.startswith("rate_"):
            item = self.items.setdefault(key, {})
            item["attempts"] = item.get("attempts", 0) + 1
            return
        item = self.items[key]
        item.update({
            "state": ExpressionAttributeValues[":state"],
            "auth_state_hash": ExpressionAttributeValues[":state_hash"],
            "email_hash": ExpressionAttributeValues[":email_hash"],
        })


def payload(result):
    return json.loads(result["body"])


def transaction_record(table):
    return next(item for key, item in table.items.items() if not key.startswith("rate_"))


def valid_invitation():
    return {
        "code_hash": handler._join_code_hash("ABCDE-12345"),
        "invitation_id": "invite_test", "state": "pending",
        "code_expires_at": handler.epoch_now() + 120,
    }


def begin_event():
    return {"body": json.dumps({
        "join_code": "ABCDE-12345", "installation_id": "installation-test-1234",
        "correlation_nonce": "a" * 24,
    })}


def test_begin_returns_only_opaque_resume_material_and_does_not_accept(monkeypatch):
    invitation = valid_invitation()
    joins = Table()
    monkeypatch.setattr(handler, "household_invitations_table", Table([invitation]))
    monkeypatch.setattr(handler, "household_join_transactions_table", joins)

    result = handler.begin_household_join(begin_event())
    body = payload(result)

    assert result["statusCode"] == 201
    assert body["state"] == "household_join_ready"
    assert set(body) == {"state", "join_resume_handle", "expires_at", "next"}
    stored = transaction_record(joins)
    assert stored["state"] == "initiated"
    assert "ABCDE" not in json.dumps(stored)
    assert invitation["state"] == "pending"


def test_begin_rejects_a_non_household_qr_payload_without_creating_a_transaction(monkeypatch):
    joins = Table()
    monkeypatch.setattr(handler, "household_invitations_table", Table([valid_invitation()]))
    monkeypatch.setattr(handler, "household_join_transactions_table", joins)

    result = handler.begin_household_join({"body": json.dumps({
        "invitation": "kaevo://connector?code=ABCDE-12345",
        "installation_id": "installation-test-1234", "correlation_nonce": "a" * 24,
    })})

    assert result["statusCode"] == 400
    assert payload(result) == {"state": "household_join_invalid_request", "retryable": False}
    assert not joins.items


def test_rate_limit_returns_a_generic_retry_response(monkeypatch):
    monkeypatch.setattr(handler, "household_invitations_table", Table([valid_invitation()]))
    monkeypatch.setattr(handler, "household_join_transactions_table", Table())
    monkeypatch.setattr(handler, "_consume_household_join_rate_limit", lambda *_args: False)

    result = handler.begin_household_join(begin_event())

    assert result["statusCode"] == 429
    assert payload(result) == {"state": "household_join_retry_later", "retryable": True}


def test_route_auth_never_returns_account_existence_or_email(monkeypatch):
    joins = Table()
    monkeypatch.setattr(handler, "household_invitations_table", Table([valid_invitation()]))
    monkeypatch.setattr(handler, "household_join_transactions_table", joins)
    monkeypatch.setattr(handler, "NATIVE_OIDC_AUTHORIZATION_ENDPOINT", "https://auth.example/oauth2/authorize")
    monkeypatch.setattr(handler, "EXPECTED_NATIVE_CALLBACK_URI", "kaevo://oauth/callback")
    monkeypatch.setenv("EXPECTED_NATIVE_CLIENT_ID", "native-client")
    monkeypatch.setattr(handler, "COGNITO_USER_POOL_ID", "pool")
    monkeypatch.setattr(handler, "_cognito_user_exists", lambda _email: True)
    started = payload(handler.begin_household_join(begin_event()))

    result = handler.route_household_join_auth({"body": json.dumps({
        "join_resume_handle": started["join_resume_handle"], "installation_id": "installation-test-1234",
        "email": "member@example.com", "oauth_state": "b" * 24, "code_challenge": "c" * 43,
    })})
    body = payload(result)

    assert result["statusCode"] == 200
    assert set(body) == {"state", "redirect_url", "oauth_state", "expires_at"}
    assert "account" not in json.dumps(body).lower()
    assert "member@example.com" not in json.dumps(body)
    assert "/signup" not in body["redirect_url"]
    stored = transaction_record(joins)
    assert stored["state"] == "awaiting_callback"
    assert "member@example.com" not in json.dumps(stored)


def test_new_account_route_uses_signup_with_the_same_response_shape(monkeypatch):
    joins = Table()
    monkeypatch.setattr(handler, "household_invitations_table", Table([valid_invitation()]))
    monkeypatch.setattr(handler, "household_join_transactions_table", joins)
    monkeypatch.setattr(handler, "NATIVE_OIDC_AUTHORIZATION_ENDPOINT", "https://auth.example/oauth2/authorize")
    monkeypatch.setattr(handler, "EXPECTED_NATIVE_CALLBACK_URI", "kaevo://oauth/callback")
    monkeypatch.setenv("EXPECTED_NATIVE_CLIENT_ID", "native-client")
    monkeypatch.setattr(handler, "COGNITO_USER_POOL_ID", "pool")
    monkeypatch.setattr(handler, "_cognito_user_exists", lambda _email: False)
    started = payload(handler.begin_household_join(begin_event()))

    body = payload(handler.route_household_join_auth({"body": json.dumps({
        "join_resume_handle": started["join_resume_handle"], "installation_id": "installation-test-1234",
        "email": "new@example.com", "oauth_state": "d" * 24, "code_challenge": "e" * 43,
    })}))

    assert set(body) == {"state", "redirect_url", "oauth_state", "expires_at"}
    assert "/signup?" in body["redirect_url"]
