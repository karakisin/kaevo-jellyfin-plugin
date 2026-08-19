import json

import handler


class Invitations:
    name = "household-invitations"

    def __init__(self, records=None):
        self.item = None
        self.records = []
        self.query_calls = []
        for index, record in enumerate(records or []):
            stored = dict(record)
            stored.setdefault("code_hash", f"fixture-code-hash-{index}")
            self.records.append(stored)

    def put_item(self, *, Item, **_kwargs):
        self.item = Item

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        return {"Items": self.records}

    def scan(self, **_kwargs):
        raise AssertionError("household invitation paths must never Scan")

    def get_item(self, *, Key, **_kwargs):
        return {"Item": next((item for item in self.records if item.get("code_hash") == Key.get("code_hash")), None)}

    def delete_item(self, *, Key, **_kwargs):
        self.records = [
            item for item in self.records
            if item.get("code_hash") != Key.get("code_hash")
        ]


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
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({
        "profile_id": "profile-owner", "principal_id": "principal-owner",
        "account_id": "account-1", "household_id": "household-1",
    }, None))
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile: ({"family_enabled": False}, None))

    result = handler.create_household_invitation({"body": json.dumps({"display_name": "Margaret", "profile_type": "adult"})})
    payload = body(result)

    assert result["statusCode"] == 201
    assert payload["join_code"] not in json.dumps(invitations.item)
    assert invitations.item["code_hash"] == handler._join_code_hash(payload["join_code"])
    assert payload["binding_handle"] == invitations.item["code_hash"]
    assert invitations.item["code_expires_at"] == payload["expires_at"]
    assert invitations.item["expires_at"] > invitations.item["code_expires_at"]
    assert payload["profile_id"] == invitations.item["profile_id"]
    assert payload["profile_type"] == "adult"
    assert entitlements.item["profile_id"] == "profile-owner"


def test_production_does_not_auto_grant_family_access(monkeypatch):
    monkeypatch.setattr(handler, "household_invitations_table", Invitations())
    monkeypatch.setattr(handler, "KAEVO_ENV", "production")
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({"profile_id": "profile-owner"}, None))
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
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({
        "profile_id": "profile-owner", "principal_id": "principal-owner",
        "account_id": "account-1", "household_id": "household-1",
    }, None))
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile: ({"family_enabled": False}, None))

    result = handler.create_household_invitation({"body": json.dumps({"display_name": "Margaret", "profile_type": "adult"})})

    assert result["statusCode"] == 201
    assert entitlements.item["entitlements_json"].find("dev_owner_testing") != -1


def test_invitation_rejects_when_device_bound_owner_session_is_missing(monkeypatch):
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: (
        None,
        handler.response(401, {"state": "household_manager_session_required"}),
    ))

    result = handler.create_household_invitation({"body": json.dumps({
        "display_name": "Margaret",
        "profile_type": "adult",
    })})

    assert result["statusCode"] == 401
    assert body(result) == {"state": "household_manager_session_required"}


def test_kid_invitation_uses_the_same_valid_bound_owner_session(monkeypatch):
    invitations = Invitations()
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "KAEVO_ENV", "dev")
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({
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
    assert invitations.item["role"] == "child"
    assert invitations.item["canonical_role"] == "child"
    assert invitations.item["household_access_role"] == "member"


def test_parent_managed_kid_profile_creates_no_invitation_or_child_credential(monkeypatch):
    invitations = Invitations()
    recorder = TransactionRecorder()
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "identity_profiles_table", RecordsTable("identity-profiles"))
    monkeypatch.setattr(handler, "principals_table", RecordsTable("principals"))
    monkeypatch.setattr(handler, "entitlements_table", Entitlements())
    monkeypatch.setattr(handler, "dynamodb", FakeDynamoDB(recorder))
    monkeypatch.setattr(handler, "KAEVO_ENV", "dev")
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({
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
    assert transaction[3]["Update"]["Key"] == {"profile_id": "profile-owner"}
    owner_update = transaction[3]["Update"]
    assert "switch_profile_ids" in owner_update["UpdateExpression"]
    assert "watching_profile_ids" in owner_update["UpdateExpression"]
    assert owner_update["ExpressionAttributeValues"][":profile"] == [payload["profile_id"]]


def test_owner_can_assign_exact_watching_targets_during_parent_managed_creation(monkeypatch):
    target_id = "profile_1234567890abcdef"
    recorder = TransactionRecorder()
    monkeypatch.setattr(handler, "household_invitations_table", Invitations())
    monkeypatch.setattr(handler, "identity_profiles_table", RecordsTable("identity-profiles", [{
        "profile_id": target_id,
        "account_id": "account-1",
        "household_id": "household-1",
        "state": "active",
    }]))
    monkeypatch.setattr(handler, "principals_table", RecordsTable("principals"))
    monkeypatch.setattr(handler, "entitlements_table", Entitlements())
    monkeypatch.setattr(handler, "dynamodb", FakeDynamoDB(recorder))
    monkeypatch.setattr(handler, "KAEVO_ENV", "dev")
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({
        "profile_id": "profile-owner", "principal_id": "principal-owner",
        "account_id": "account-1", "household_id": "household-1",
        "household_access_role": "owner",
    }, None))
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile: ({"family_enabled": True}, None))

    result = handler.create_household_invitation({"body": json.dumps({
        "display_name": "Kid profile",
        "profile_type": "kid",
        "access_mode": "parent_managed",
        "watching_profile_ids": [target_id],
    })})

    assert result["statusCode"] == 201
    profile = recorder.calls[0]["TransactItems"][0]["Put"]["Item"]
    assert profile["watching_profile_ids"] == [target_id]


def test_owner_can_assign_exact_watching_targets_during_device_invitation(monkeypatch):
    target_id = "profile_1234567890abcdef"
    invitations = Invitations()
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "identity_profiles_table", RecordsTable("identity-profiles", [{
        "profile_id": target_id,
        "account_id": "account-1",
        "household_id": "household-1",
        "state": "active",
    }]))
    monkeypatch.setattr(handler, "KAEVO_ENV", "dev")
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({
        "profile_id": "profile-owner", "principal_id": "principal-owner",
        "account_id": "account-1", "household_id": "household-1",
        "household_access_role": "owner",
    }, None))
    monkeypatch.setattr(handler, "load_entitlements_for_profile", lambda _profile: ({"family_enabled": True}, None))

    result = handler.create_household_invitation({"body": json.dumps({
        "display_name": "New member",
        "profile_type": "adult",
        "watching_profile_ids": [target_id],
    })})

    assert result["statusCode"] == 201
    assert invitations.item["watching_profile_ids"] == [target_id]


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
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({
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
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({
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
        "watching_profile_ids": ["profile_1234567890abcdef"],
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
    assert profile_write["Item"]["watching_profile_ids"] == ["profile_1234567890abcdef"]
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
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({"household_id": "household-1"}, None))
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
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({"household_id": "household-1"}, None))
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)

    result = handler.list_household_invitations({})
    listed = body(result)["invitations"][0]

    assert result["statusCode"] == 200
    assert listed == {
        "invitation_id": "invite_12345678",
        "profile_id": "profile-pending",
        "display_name": "Margaret",
        "profile_type": "adult",
        "canonical_role": "adult",
        "household_access_role": "member",
        "cloud_access_enabled": True,
        "request_access_enabled": False,
        "switch_profile_ids": [],
        "state": "expired",
        "expires_at": 999,
    }
    assert "join_code" not in listed
    assert "code_hash" not in listed


def test_list_uses_household_query_and_never_returns_revoked_or_deleting_records(monkeypatch):
    invitations = Invitations([
        {
            "invitation_id": "invite_pending1",
            "profile_id": "profile-pending",
            "household_id": "household-1",
            "display_name": "Pending",
            "profile_type": "adult",
            "state": "pending",
            "code_expires_at": 2_000,
        },
        {
            "invitation_id": "invite_revoked1",
            "profile_id": "profile-revoked",
            "household_id": "household-1",
            "display_name": "Revoked",
            "profile_type": "adult",
            "state": "revoked",
            "code_expires_at": 2_000,
        },
        {
            "invitation_id": "invite_deleting1",
            "profile_id": "profile-deleting",
            "household_id": "household-1",
            "display_name": "Deleting",
            "profile_type": "adult",
            "state": "deletion_pending",
            "code_expires_at": 2_000,
        },
    ])
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: (
        {"household_id": "household-1"}, None,
    ))
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)

    result = handler.list_household_invitations({})
    listed = body(result)["invitations"]

    assert [item["profile_id"] for item in listed] == ["profile-pending"]
    assert invitations.query_calls
    assert invitations.query_calls[0]["IndexName"] == "household_id-index"
    assert invitations.query_calls[0]["ConsistentRead"] is False


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
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({"household_id": "household-1"}, None))

    result = handler.refresh_household_invitation({"body": json.dumps({"invitation_id": "invite_12345678"})})

    assert result["statusCode"] == 409
    assert body(result)["state"] == "invitation_already_used"
    assert recorder.calls == []


def test_permanent_invitation_deletion_uses_exact_query_and_confirms_absence(monkeypatch):
    invitations = Invitations([{
        "code_hash": "pending-code-hash",
        "invitation_id": "invite_12345678",
        "profile_id": "profile-pending",
        "household_id": "household-1",
        "state": "pending",
    }])
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: (
        {"household_id": "household-1"}, None,
    ))

    result = handler.delete_household_invitation(
        {}, "/v2/household/invitations/invite_12345678",
    )

    assert result["statusCode"] == 200
    assert body(result)["state"] == "invitation_deleted"
    assert invitations.records == []
    assert len(invitations.query_calls) == 2
    assert all(call["IndexName"] == "household_id-index" for call in invitations.query_calls)


def test_permanent_invitation_deletion_never_deletes_consumed_identity(monkeypatch):
    invitation = {
        "code_hash": "consumed-code-hash",
        "invitation_id": "invite_12345678",
        "profile_id": "profile-active",
        "household_id": "household-1",
        "state": "consumed",
    }
    invitations = Invitations([invitation])
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: (
        {"household_id": "household-1"}, None,
    ))

    result = handler.delete_household_invitation(
        {}, "/v2/household/invitations/invite_12345678",
    )

    assert result["statusCode"] == 409
    assert body(result)["state"] == "invitation_not_deletable"
    assert invitations.records[0]["state"] == "consumed"
