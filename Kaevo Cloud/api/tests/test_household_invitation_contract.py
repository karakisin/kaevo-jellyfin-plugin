import json

import handler


class Invitations:
    name = "household-invitations"

    def __init__(self, records=None):
        self.item = None
        self.records = list(records or [])

    def put_item(self, *, Item, **_kwargs):
        self.item = Item

    def scan(self, **_kwargs):
        return {"Items": self.records}

    def get_item(self, *, Key, **_kwargs):
        return {"Item": next((item for item in self.records if item.get("code_hash") == Key.get("code_hash")), None)}


class Entitlements:
    name = "entitlements"
    def __init__(self):
        self.item = None

    def put_item(self, *, Item, **_kwargs):
        self.item = Item


class RecordsTable:
    def __init__(self, name, records=None):
        self.name = name
        self.records = {str(item.get("profile_id") or item.get("principal_id")): item for item in (records or [])}

    def get_item(self, *, Key, **_kwargs):
        value = str(Key.get("profile_id") or Key.get("principal_id") or "")
        item = self.records.get(value)
        return {"Item": item} if item else {}


def body(result):
    return json.loads(result["body"])


def test_invitation_code_is_returned_once_but_only_hash_is_stored(monkeypatch):
    invitations = Invitations()
    entitlements = Entitlements()
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "entitlements_table", entitlements)
    monkeypatch.setattr(handler, "KAEVO_ENV", "security-stage")
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: ({
        "profile_id": "profile-owner", "principal_id": "principal-owner",
        "account_id": "account-1", "household_id": "household-1",
    }, None))
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile: ({"family_enabled": False}, None))

    result = handler.create_household_invitation({"body": json.dumps({"display_name": "Margaret", "profile_type": "adult"})})
    payload = body(result)

    assert result["statusCode"] == 201
    assert payload["join_code"] not in json.dumps(invitations.item)
    assert invitations.item["code_hash"] == handler._join_code_hash(payload["join_code"])
    assert invitations.item["code_expires_at"] == payload["expires_at"]
    assert invitations.item["expires_at"] > invitations.item["code_expires_at"]
    assert payload["profile_id"] == invitations.item["profile_id"]
    assert payload["profile_type"] == "adult"
    assert entitlements.item["profile_id"] == "profile-owner"


def test_production_does_not_auto_grant_family_access(monkeypatch):
    monkeypatch.setattr(handler, "household_invitations_table", Invitations())
    monkeypatch.setattr(handler, "KAEVO_ENV", "production")
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: ({"profile_id": "profile-owner"}, None))
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile: ({"family_enabled": False}, None))

    result = handler.create_household_invitation({"body": "{}"})

    assert result["statusCode"] == 409
    assert body(result)["state"] == "family_plan_required"


def test_development_grants_internal_family_tester_access(monkeypatch):
    invitations = Invitations()
    entitlements = Entitlements()
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "entitlements_table", entitlements)
    monkeypatch.setattr(handler, "KAEVO_ENV", "dev")
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: ({
        "profile_id": "profile-owner", "principal_id": "principal-owner",
        "account_id": "account-1", "household_id": "household-1",
    }, None))
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile: ({"family_enabled": False}, None))

    result = handler.create_household_invitation({"body": json.dumps({"display_name": "Margaret", "profile_type": "adult"})})

    assert result["statusCode"] == 201
    assert entitlements.item["entitlements_json"].find("dev_owner_testing") != -1


def test_invitation_rejects_when_device_bound_owner_session_is_missing(monkeypatch):
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: (
        None,
        handler.response(401, {"state": "owner_session_required"}),
    ))

    result = handler.create_household_invitation({"body": json.dumps({
        "display_name": "Margaret",
        "profile_type": "adult",
    })})

    assert result["statusCode"] == 401
    assert body(result) == {"state": "owner_session_required"}


def test_kid_invitation_uses_the_same_valid_bound_owner_session(monkeypatch):
    invitations = Invitations()
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "KAEVO_ENV", "dev")
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: ({
        "profile_id": "profile-owner", "principal_id": "principal-owner",
        "account_id": "account-1", "household_id": "household-1",
    }, None))
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile: ({"family_enabled": True}, None))

    result = handler.create_household_invitation({"body": json.dumps({
        "display_name": "Kid profile",
        "profile_type": "kid",
    })})

    assert result["statusCode"] == 201
    assert invitations.item["profile_type"] == "kid"
    assert invitations.item["role"] == "kid"


def test_parent_managed_kid_profile_creates_no_invitation_or_child_credential(monkeypatch):
    invitations = Invitations()
    recorder = TransactionRecorder()
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "identity_profiles_table", RecordsTable("identity-profiles"))
    monkeypatch.setattr(handler, "principals_table", RecordsTable("principals"))
    monkeypatch.setattr(handler, "entitlements_table", Entitlements())
    monkeypatch.setattr(handler, "dynamodb", FakeDynamoDB(recorder))
    monkeypatch.setattr(handler, "KAEVO_ENV", "dev")
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: ({
        "profile_id": "profile-owner", "principal_id": "principal-owner",
        "account_id": "account-1", "household_id": "household-1",
    }, None))
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile: ({"family_enabled": True}, None))

    result = handler.create_household_invitation({"body": json.dumps({
        "display_name": "Kid profile",
        "profile_type": "kid",
        "access_mode": "parent_managed",
    })})
    payload = body(result)

    assert result["statusCode"] == 201
    assert payload["state"] == "parent_managed_profile_created"
    assert payload["profile_type"] == "kid"
    assert "join_code" not in payload
    assert "join_url" not in payload
    assert invitations.item is None
    transaction = recorder.calls[0]["TransactItems"]
    profile = transaction[0]["Put"]["Item"]
    assert profile["managed_by_owner"] is True
    assert "member_principal_id" not in profile
    assert transaction[2]["Update"]["Key"] == {"principal_id": "principal-owner"}


def test_existing_parent_managed_kid_profile_can_receive_one_device_invitation(monkeypatch):
    profile_id = "profile_1234567890abcdef"
    managed = {
        "profile_id": profile_id,
        "account_id": "account-1",
        "household_id": "household-1",
        "owner_principal_id": "principal-owner",
        "profile_type": "kid",
        "managed_by_owner": True,
    }
    invitations = Invitations()
    recorder = TransactionRecorder()
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "identity_profiles_table", RecordsTable("identity-profiles", [managed]))
    monkeypatch.setattr(handler, "dynamodb", FakeDynamoDB(recorder))
    monkeypatch.setattr(handler, "KAEVO_ENV", "dev")
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: ({
        "profile_id": "profile-owner", "principal_id": "principal-owner",
        "account_id": "account-1", "household_id": "household-1",
    }, None))
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile: ({"family_enabled": True}, None))

    result = handler.create_household_invitation({"body": json.dumps({
        "display_name": "Kid profile",
        "profile_type": "kid",
        "profile_id": profile_id,
    })})
    payload = body(result)

    assert result["statusCode"] == 201
    assert payload["profile_id"] == profile_id
    transaction = recorder.calls[0]["TransactItems"]
    assert transaction[0]["Update"]["Key"] == {"profile_id": profile_id}
    stored = transaction[1]["Put"]["Item"]
    assert stored["managed_profile"] is True
    assert stored["profile_id"] == profile_id
    assert payload["join_code"] not in json.dumps(stored)


def test_parent_managed_profile_rejects_adult_and_cross_household_binding(monkeypatch):
    profile_id = "profile_1234567890abcdef"
    managed = {
        "profile_id": profile_id,
        "account_id": "another-account",
        "household_id": "another-household",
        "owner_principal_id": "another-owner",
        "managed_by_owner": True,
    }
    monkeypatch.setattr(handler, "household_invitations_table", Invitations())
    monkeypatch.setattr(handler, "identity_profiles_table", RecordsTable("identity-profiles", [managed]))
    monkeypatch.setattr(handler, "KAEVO_ENV", "dev")
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: ({
        "profile_id": "profile-owner", "principal_id": "principal-owner",
        "account_id": "account-1", "household_id": "household-1",
    }, None))
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile: ({"family_enabled": True}, None))

    adult = handler.create_household_invitation({"body": json.dumps({
        "display_name": "Adult", "profile_type": "adult", "profile_id": profile_id,
    })})
    mismatch = handler.create_household_invitation({"body": json.dumps({
        "display_name": "Kid", "profile_type": "kid", "profile_id": profile_id,
    })})

    assert adult["statusCode"] == 400
    assert body(adult)["state"] == "invalid_managed_profile"
    assert mismatch["statusCode"] == 403
    assert body(mismatch)["state"] == "managed_profile_mismatch"


def test_managed_profile_invitation_adds_device_identity_without_duplicate_profile(monkeypatch):
    join_code = "ABCDE-FGHIJ"
    profile_id = "profile_1234567890abcdef"
    invitation_id = "invite_12345678"
    invitation = {
        "code_hash": handler._join_code_hash(join_code),
        "invitation_id": invitation_id,
        "profile_id": profile_id,
        "account_id": "account-1",
        "household_id": "household-1",
        "owner_principal_id": "principal-owner",
        "owner_profile_id": "profile-owner",
        "display_name": "Kid",
        "profile_type": "kid",
        "role": "kid",
        "state": "pending",
        "managed_profile": True,
        "code_expires_at": 2_000,
    }
    managed = {
        "profile_id": profile_id,
        "account_id": "account-1",
        "household_id": "household-1",
        "owner_principal_id": "principal-owner",
        "display_name": "Kid",
        "profile_type": "kid",
        "managed_by_owner": True,
        "pending_invitation_id": invitation_id,
        "created_at": "2026-07-22T19:00:00Z",
    }
    recorder = TransactionRecorder()
    monkeypatch.setattr(handler, "household_invitations_table", Invitations([invitation]))
    monkeypatch.setattr(handler, "principals_table", RecordsTable("principals"))
    monkeypatch.setattr(handler, "identity_memberships_table", RecordsTable("memberships"))
    monkeypatch.setattr(handler, "identity_profiles_table", RecordsTable("identity-profiles", [managed]))
    monkeypatch.setattr(handler, "entitlements_table", Entitlements())
    monkeypatch.setattr(handler, "dynamodb", FakeDynamoDB(recorder))
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)
    monkeypatch.setattr(handler, "utc_now_iso", lambda: "2026-07-22T20:00:00Z")
    monkeypatch.setattr(handler, "validate_access_token_claims", lambda *_args, **_kwargs: {"sub": "principal-kid"})
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile: ({"family_enabled": True}, None))

    result = handler.join_household({"body": json.dumps({"join_code": join_code})})

    assert result["statusCode"] == 201
    transaction = recorder.calls[0]["TransactItems"]
    assert len(transaction) == 4
    assert transaction[0]["Put"]["Item"]["principal_id"] == "principal-kid"
    profile_write = transaction[3]["Put"]
    assert profile_write["Item"]["profile_id"] == profile_id
    assert profile_write["Item"]["member_principal_id"] == "principal-kid"
    assert profile_write["Item"]["device_access_enabled"] is True
    assert "pending_invitation_id" not in profile_write["Item"]
    assert "list_append" not in json.dumps(transaction)


class TransactionRecorder:
    def __init__(self):
        self.calls = []

    def transact_write_items(self, **kwargs):
        self.calls.append(kwargs)


class FakeDynamoDB:
    def __init__(self, client):
        self.meta = type("Meta", (), {"client": client})()


def test_owner_refresh_rotates_only_the_code_and_keeps_the_pending_profile(monkeypatch):
    old = {
        "code_hash": "old-code-hash",
        "invitation_id": "invite_12345678",
        "profile_id": "profile-pending",
        "account_id": "account-1",
        "household_id": "household-1",
        "owner_principal_id": "principal-owner",
        "owner_profile_id": "profile-owner",
        "display_name": "Margaret",
        "profile_type": "kid",
        "role": "kid",
        "state": "pending",
        "code_expires_at": 1,
        "expires_at": 2,
    }
    recorder = TransactionRecorder()
    monkeypatch.setattr(handler, "household_invitations_table", Invitations([old]))
    monkeypatch.setattr(handler, "dynamodb", FakeDynamoDB(recorder))
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: ({"household_id": "household-1"}, None))
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)
    monkeypatch.setattr(handler, "utc_now_iso", lambda: "2026-07-22T19:30:00Z")

    result = handler.refresh_household_invitation({"body": json.dumps({"invitation_id": "invite_12345678"})})
    payload = body(result)

    assert result["statusCode"] == 201
    assert payload["state"] == "invitation_refreshed"
    assert payload["invitation_id"] == old["invitation_id"]
    assert payload["profile_id"] == old["profile_id"]
    assert payload["profile_type"] == "kid"
    assert payload["expires_at"] == 1_000 + handler.HOUSEHOLD_INVITATION_CODE_TTL_SECONDS
    transaction = recorder.calls[0]["TransactItems"]
    assert transaction[0]["Delete"]["Key"] == {"code_hash": "old-code-hash"}
    assert transaction[0]["Delete"]["ConditionExpression"] == (
        "#state = :pending AND invitation_id = :invitation_id AND household_id = :household_id"
    )
    refreshed = transaction[1]["Put"]["Item"]
    assert refreshed["profile_id"] == old["profile_id"]
    assert refreshed["code_hash"] != old["code_hash"]
    assert refreshed["expires_at"] == 1_000 + handler.HOUSEHOLD_INVITATION_RETENTION_SECONDS


def test_list_marks_expired_pending_invitation_without_rotating_it(monkeypatch):
    invitation = {
        "invitation_id": "invite_12345678",
        "profile_id": "profile-pending",
        "household_id": "household-1",
        "display_name": "Margaret",
        "profile_type": "adult",
        "state": "pending",
        "code_expires_at": 999,
        "expires_at": 10_000,
    }
    monkeypatch.setattr(handler, "household_invitations_table", Invitations([invitation]))
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: ({"household_id": "household-1"}, None))
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)

    result = handler.list_household_invitations({})
    listed = body(result)["invitations"][0]

    assert result["statusCode"] == 200
    assert listed == {
        "invitation_id": "invite_12345678",
        "profile_id": "profile-pending",
        "display_name": "Margaret",
        "profile_type": "adult",
        "state": "expired",
        "expires_at": 999,
    }
    assert "join_code" not in listed
    assert "code_hash" not in listed


def test_consumed_invitation_cannot_be_refreshed(monkeypatch):
    invitation = {
        "code_hash": "used-code-hash",
        "invitation_id": "invite_12345678",
        "profile_id": "profile-active",
        "household_id": "household-1",
        "display_name": "Margaret",
        "profile_type": "adult",
        "state": "consumed",
    }
    recorder = TransactionRecorder()
    monkeypatch.setattr(handler, "household_invitations_table", Invitations([invitation]))
    monkeypatch.setattr(handler, "dynamodb", FakeDynamoDB(recorder))
    monkeypatch.setattr(handler, "owner_bound_session", lambda _event: ({"household_id": "household-1"}, None))

    result = handler.refresh_household_invitation({"body": json.dumps({"invitation_id": "invite_12345678"})})

    assert result["statusCode"] == 409
    assert body(result)["state"] == "invitation_already_used"
    assert recorder.calls == []
