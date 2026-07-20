import json

import handler


class Invitations:
    def __init__(self):
        self.item = None

    def put_item(self, *, Item, **_kwargs):
        self.item = Item


class Entitlements:
    def __init__(self):
        self.item = None

    def put_item(self, *, Item, **_kwargs):
        self.item = Item


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
    assert invitations.item["expires_at"] > 0
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
