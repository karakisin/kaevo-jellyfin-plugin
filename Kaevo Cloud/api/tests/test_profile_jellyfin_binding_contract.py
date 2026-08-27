import json

import handler


class ExactProfileTable:
    def __init__(self, records=None):
        self.records = {
            item["profile_id"]: dict(item) for item in (records or [])
        }

    def get_item(self, Key, ConsistentRead=False):
        item = self.records.get(Key["profile_id"])
        return {"Item": dict(item)} if item is not None else {}

    def update_item(self, Key, ExpressionAttributeValues, **_kwargs):
        item = self.records[Key["profile_id"]]
        if ":seerr_user_id" in ExpressionAttributeValues:
            item.update({
                "seerr_connector_id": ExpressionAttributeValues[":connector_id"],
                "seerr_jellyfin_user_id": ExpressionAttributeValues[":jellyfin_user_id"],
                "seerr_user_id": ExpressionAttributeValues[":seerr_user_id"],
                "seerr_binding_state": ExpressionAttributeValues[":binding_state"],
                "seerr_binding_updated_at": ExpressionAttributeValues[":updated_at"],
                "request_access_enabled": ExpressionAttributeValues[":request_access_enabled"],
            })
        else:
            item.update({
                "jellyfin_connector_id": ExpressionAttributeValues[":connector_id"],
                "jellyfin_user_id": ExpressionAttributeValues[":user_id"],
                "jellyfin_binding_state": ExpressionAttributeValues[":binding_state"],
                "jellyfin_binding_updated_at": ExpressionAttributeValues[":updated_at"],
            })


class ExactInvitationTable:
    def __init__(self, invitation=None):
        self.invitation = invitation

    def get_item(self, Key, ConsistentRead=False):
        assert ConsistentRead is True
        if (
            self.invitation is not None
            and self.invitation["code_hash"] == Key["code_hash"]
        ):
            return {"Item": dict(self.invitation)}
        return {}

    def update_item(self, Key, ExpressionAttributeValues, **_kwargs):
        assert self.invitation["code_hash"] == Key["code_hash"]
        if ":cleanup_state" in ExpressionAttributeValues:
            self.invitation.update({
                "provider_cleanup_state": ExpressionAttributeValues[":cleanup_state"],
                "provider_cleanup_updated_at": ExpressionAttributeValues[":updated_at"],
            })
            if ":seerr_binding_state" in ExpressionAttributeValues:
                self.invitation["seerr_binding_state"] = ExpressionAttributeValues[":seerr_binding_state"]
            if ":jellyfin_binding_state" in ExpressionAttributeValues:
                self.invitation["jellyfin_binding_state"] = ExpressionAttributeValues[":jellyfin_binding_state"]
        elif ":seerr_user_id" in ExpressionAttributeValues:
            self.invitation.update({
                "seerr_connector_id": ExpressionAttributeValues[":connector_id"],
                "seerr_jellyfin_user_id": ExpressionAttributeValues[":jellyfin_user_id"],
                "seerr_user_id": ExpressionAttributeValues[":seerr_user_id"],
                "seerr_binding_state": ExpressionAttributeValues[":binding_state"],
                "seerr_binding_updated_at": ExpressionAttributeValues[":updated_at"],
                "request_access_enabled": ExpressionAttributeValues[":request_access_enabled"],
            })
        else:
            self.invitation.update({
                "jellyfin_connector_id": ExpressionAttributeValues[":connector_id"],
                "jellyfin_user_id": ExpressionAttributeValues[":user_id"],
                "jellyfin_binding_state": ExpressionAttributeValues[":binding_state"],
                "jellyfin_binding_updated_at": ExpressionAttributeValues[":updated_at"],
            })


class BindingOperationTable:
    def __init__(self):
        self.records = {}

    def put_item(self, Item, ConditionExpression=None, **_kwargs):
        if Item["operation_id"] in self.records:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem")
        self.records[Item["operation_id"]] = dict(Item)

    def get_item(self, Key, ConsistentRead=False):
        item = self.records.get(Key["operation_id"])
        return {"Item": dict(item)} if item else {}

    def update_item(self, Key, ExpressionAttributeValues, **_kwargs):
        item = self.records[Key["operation_id"]]
        item["phase"] = ExpressionAttributeValues[":phase"]
        item["updated_at"] = ExpressionAttributeValues[":updated_at"]
        item["revision"] = ExpressionAttributeValues.get(":next_revision", item.get("revision", 0))
        for key in (
            "source_state", "inspection_result", "plugin_cas_result",
            "cloud_persistence_result", "snapshot_result", "terminal_result",
            "reconciliation_required", "connector_request_id",
        ):
            placeholder = ":value_" + key
            if placeholder in ExpressionAttributeValues:
                item[key] = ExpressionAttributeValues[placeholder]
        return {"Attributes": dict(item)}


class ExactTombstoneTable:
    def __init__(self, records=None):
        self.records = {
            item["profile_id"]: dict(item) for item in (records or [])
        }

    def get_item(self, Key, ConsistentRead=False):
        item = self.records.get(Key["profile_id"])
        return {"Item": dict(item)} if item is not None else {}


def body(result):
    return json.loads(result["body"])


def install_manager(monkeypatch):
    monkeypatch.setattr(handler, "household_manager_bound_session", lambda _event: ({
        "profile_id": "profile_owner_1234567890",
        "household_id": "household-1",
    }, None))
    monkeypatch.setattr(handler, "_home_connectors_for_profile_access", lambda _profile_id: [{
        "connector_id": "connector-1",
    }])
    monkeypatch.setattr(handler, "household_memberships_table", object())
    monkeypatch.setattr(handler, "home_connectors_table", object())
    monkeypatch.setattr(handler, "_household_membership_records", lambda _household_id: [])
    monkeypatch.setattr(handler, "_repair_legacy_active_membership_profile_pointer", lambda value: value)


def test_deleted_profile_recovery_binding_requires_exact_plugin_and_tombstone_owner(monkeypatch):
    profile_id = "profile_RdirdBJ1OIm3ezAyDcFvJCZexEwFa-5H"
    jellyfin_user_id = "dbb85e8dd0844ee097a4c9fd8d358215"
    invitation = {
        "code_hash": "a" * 64,
        "state": "pending",
        "household_id": "household-1",
        "profile_id": profile_id,
        "code_expires_at": handler.epoch_now() + 900,
        "deleted_profile_recovery": True,
    }
    install_manager(monkeypatch)
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable())
    invitations = ExactInvitationTable(invitation)
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "profile_binding_tombstones_table", ExactTombstoneTable([{
        "profile_id": profile_id,
        "household_id": "household-1",
        "state": "deleted",
        "expires_at": handler.epoch_now() + 3600,
        "connector_id": "connector-1",
        "provider_user_fingerprint": handler._binding_operation_fingerprint(jellyfin_user_id),
    }]))
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [invitation])
    monkeypatch.setattr(handler, "_household_identity_profile_records", lambda _household_id: [])
    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", lambda *_args, **_kwargs: {
        "state": "completed",
        "connector_id": "connector-1",
        "result": {
            "owner_state": "found",
            "source_profile_id": profile_id,
        },
    })

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "jellyfin_user_id": jellyfin_user_id,
        "explicit_confirmation": True,
        "invitation_binding_handle": invitation["code_hash"],
    })}, f"/v3/identity/profiles/{profile_id}/jellyfin-binding")

    assert result["statusCode"] == 200, result
    assert body(result) == {"state": "profile_jellyfin_binding_saved"}
    assert invitations.invitation["jellyfin_user_id"] == jellyfin_user_id


def test_deleted_profile_recovery_binding_rejects_different_plugin_owner(monkeypatch):
    profile_id = "profile_RdirdBJ1OIm3ezAyDcFvJCZexEwFa-5H"
    jellyfin_user_id = "dbb85e8dd0844ee097a4c9fd8d358215"
    invitation = {
        "code_hash": "a" * 64,
        "state": "pending",
        "household_id": "household-1",
        "profile_id": profile_id,
        "code_expires_at": handler.epoch_now() + 900,
        "deleted_profile_recovery": True,
    }
    install_manager(monkeypatch)
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable())
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable(invitation))
    monkeypatch.setattr(handler, "profile_binding_tombstones_table", ExactTombstoneTable([{
        "profile_id": profile_id,
        "household_id": "household-1",
        "state": "deleted",
        "expires_at": handler.epoch_now() + 3600,
        "connector_id": "connector-1",
        "provider_user_fingerprint": handler._binding_operation_fingerprint(jellyfin_user_id),
    }]))
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [invitation])
    monkeypatch.setattr(handler, "_household_identity_profile_records", lambda _household_id: [])
    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", lambda *_args, **_kwargs: {
        "state": "completed",
        "connector_id": "connector-1",
        "result": {
            "owner_state": "found",
            "source_profile_id": "profile_other_1234567890",
        },
    })

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "jellyfin_user_id": jellyfin_user_id,
        "explicit_confirmation": True,
        "invitation_binding_handle": invitation["code_hash"],
    })}, f"/v3/identity/profiles/{profile_id}/jellyfin-binding")

    assert result["statusCode"] == 409
    assert body(result)["state"] == "profile_jellyfin_binding_recovery_owner_mismatch"


def install_seerr_owner(monkeypatch):
    session = {
        "record_type": "access",
        "profile_id": "profile_owner_1234567890",
        "principal_id": "principal-owner",
        "account_id": "account-owner",
        "household_id": "household-1",
    }
    monkeypatch.setattr(handler, "authenticated_app_session", lambda _event: session)
    monkeypatch.setattr(handler, "_normalized_profile_context", lambda _event, _session: ({
        "household": {
            "household_id": "household-1",
            "role": "owner",
        },
    }, None))
    monkeypatch.setattr(handler, "security_audit_table", object())
    monkeypatch.setattr(handler, "commit_security_audit", lambda _item: None)


def pending_provider_invitation(*, household_id="household-1"):
    jellyfin_user_id = "0123456789abcdef0123456789abcdef"
    return {
        "code_hash": "a" * 64,
        "state": "pending",
        "household_id": household_id,
        "profile_id": "profile_member_1234567890",
        "code_expires_at": handler.epoch_now() + 900,
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": jellyfin_user_id,
        "jellyfin_binding_state": "active",
        "seerr_connector_id": "connector-1",
        "seerr_jellyfin_user_id": jellyfin_user_id,
        "seerr_user_id": 16,
        "seerr_binding_state": "active",
    }


def install_pending_provider_cleanup(monkeypatch, invitation):
    install_seerr_owner(monkeypatch)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable(invitation))
    monkeypatch.setattr(handler, "identity_profiles_table", object())
    monkeypatch.setattr(handler, "remote_requests_table", object())
    monkeypatch.setattr(handler, "_home_connectors_for_profile_access", lambda _profile_id: [{
        "connector_id": "connector-1",
    }])


def pending_cleanup_event(invitation):
    return {"body": json.dumps({
        "jellyfin_user_id": invitation["jellyfin_user_id"],
        "seerr_user_id": invitation["seerr_user_id"],
        "created_by_this_attempt": True,
        "explicit_confirmation": True,
        "invitation_binding_handle": invitation["code_hash"],
    })}


def test_pending_provider_cleanup_is_transactionally_seerr_then_jellyfin(monkeypatch):
    invitation = pending_provider_invitation()
    install_pending_provider_cleanup(monkeypatch, invitation)
    operations = []

    def execute(profile_id, _connectors, operation, parameters, **_kwargs):
        operations.append((profile_id, operation, dict(parameters)))
        if operation == "seerr.delete_exact_bound_user":
            return {"state": "completed", "result": {
                "state": "deleted",
                "jellyfin_user_id": invitation["jellyfin_user_id"],
                "seerr_user_id": invitation["seerr_user_id"],
                "absence_confirmed": True,
            }}
        assert operation == "jellyfin.delete_pending_exact_user"
        return {"state": "completed", "result": {
            "state": "deleted",
            "jellyfin_user_id": invitation["jellyfin_user_id"],
            "absence_confirmed": True,
        }}

    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", execute)
    path = "/v3/identity/profiles/profile_member_1234567890/pending-provider-cleanup"
    result = handler.cleanup_pending_profile_providers_v3(pending_cleanup_event(invitation), path)

    assert result["statusCode"] == 200, result
    assert body(result)["state"] == "pending_provider_cleanup_complete"
    assert [item[1] for item in operations] == [
        "seerr.delete_exact_bound_user",
        "jellyfin.delete_pending_exact_user",
    ]
    assert invitation["provider_cleanup_state"] == "complete"
    assert invitation["seerr_binding_state"] == "absent"
    assert invitation["jellyfin_binding_state"] == "absent"


def test_pending_provider_cleanup_retains_retry_state_and_never_deletes_jellyfin_first(monkeypatch):
    invitation = pending_provider_invitation()
    install_pending_provider_cleanup(monkeypatch, invitation)
    operations = []

    def execute(_profile_id, _connectors, operation, _parameters, **_kwargs):
        operations.append(operation)
        return {"state": "failed", "result": None}

    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", execute)
    path = "/v3/identity/profiles/profile_member_1234567890/pending-provider-cleanup"
    result = handler.cleanup_pending_profile_providers_v3(pending_cleanup_event(invitation), path)

    assert result["statusCode"] == 202, result
    assert body(result)["state"] == "pending_provider_cleanup_retryable"
    assert operations == ["seerr.delete_exact_bound_user"]
    assert invitation["provider_cleanup_state"] == "seerr_retryable"
    assert invitation["jellyfin_binding_state"] == "active"


def test_pending_provider_cleanup_denies_exact_receipt_mismatch(monkeypatch):
    invitation = pending_provider_invitation()
    install_pending_provider_cleanup(monkeypatch, invitation)
    commands = []
    monkeypatch.setattr(
        handler,
        "_execute_profile_binding_connector_command",
        lambda *_args, **_kwargs: commands.append(True),
    )
    event = pending_cleanup_event(invitation)
    event["body"] = json.dumps({**json.loads(event["body"]), "seerr_user_id": 99})
    path = "/v3/identity/profiles/profile_member_1234567890/pending-provider-cleanup"
    result = handler.cleanup_pending_profile_providers_v3(event, path)

    assert result["statusCode"] in {403, 409}
    assert commands == []


def test_pending_provider_cleanup_denies_cross_household_handle(monkeypatch):
    invitation = pending_provider_invitation(household_id="household-other")
    install_pending_provider_cleanup(monkeypatch, invitation)
    commands = []
    monkeypatch.setattr(
        handler,
        "_execute_profile_binding_connector_command",
        lambda *_args, **_kwargs: commands.append(True),
    )
    path = "/v3/identity/profiles/profile_member_1234567890/pending-provider-cleanup"
    result = handler.cleanup_pending_profile_providers_v3(
        pending_cleanup_event(invitation), path,
    )

    assert result["statusCode"] in {403, 409}
    assert commands == []


def test_pending_provider_cleanup_never_deletes_an_identity_not_created_by_attempt(monkeypatch):
    invitation = pending_provider_invitation()
    install_pending_provider_cleanup(monkeypatch, invitation)
    commands = []
    monkeypatch.setattr(
        handler,
        "_execute_profile_binding_connector_command",
        lambda *_args, **_kwargs: commands.append(True),
    )
    event = pending_cleanup_event(invitation)
    event["body"] = json.dumps({
        **json.loads(event["body"]),
        "created_by_this_attempt": False,
    })
    path = "/v3/identity/profiles/profile_member_1234567890/pending-provider-cleanup"
    result = handler.cleanup_pending_profile_providers_v3(event, path)

    assert result["statusCode"] == 409
    assert commands == []


def test_owner_exact_seerr_orphan_repair_requires_authoritative_jellyfin_absence(monkeypatch):
    install_seerr_owner(monkeypatch)
    monkeypatch.setattr(handler, "remote_requests_table", object())
    monkeypatch.setattr(handler, "_home_connectors_for_profile_access", lambda _profile_id: [{
        "connector_id": "connector-1",
    }])
    operations = []

    def execute(_profile_id, _connectors, operation, parameters, **_kwargs):
        operations.append((operation, dict(parameters)))
        return {"state": "completed", "result": {
            "state": "deleted",
            "jellyfin_user_id": parameters["jellyfin_user_id"],
            "seerr_user_id": parameters["seerr_user_id"],
            "jellyfin_absence_confirmed": True,
            "absence_confirmed": True,
        }}

    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", execute)
    event = {"body": json.dumps({
        "jellyfin_user_id": "0123456789abcdef0123456789abcdef",
        "seerr_user_id": 16,
        "explicit_confirmation": True,
    })}
    result = handler.repair_exact_seerr_orphan_v3(event)

    assert result["statusCode"] == 200
    assert operations == [("seerr.delete_orphaned_jellyfin_user", {
        "jellyfin_user_id": "0123456789abcdef0123456789abcdef",
        "seerr_user_id": 16,
    })]


class CompletedRecoveryTable:
    def __init__(self, provider_id):
        self.provider_id = provider_id
        self.item = None
        self.deleted = False

    def put_item(self, Item, **_kwargs):
        self.item = dict(Item)

    def get_item(self, Key, ConsistentRead=False):
        assert ConsistentRead is True
        assert self.item["request_id"] == Key["request_id"]
        completed = dict(self.item)
        completed.update({
            "status": "completed",
            "http_status": 200,
            "response_json": json.dumps({
                "requestId": self.item["request_id"],
                "state": "complete",
                "operation": "jellyfin.recover_profile_binding",
                "result": {
                    "provider": "jellyfin",
                    "provider_user_id": self.provider_id,
                },
            }),
        })
        return {"Item": completed}

    def delete_item(self, Key, **_kwargs):
        assert self.item["request_id"] == Key["request_id"]
        self.deleted = True


def test_connector_recovery_accepts_only_exact_completed_response(monkeypatch):
    provider_id = "0123456789abcdef0123456789abcdef"
    table = CompletedRecoveryTable(provider_id)
    monkeypatch.setattr(handler, "remote_requests_table", table)
    monkeypatch.setattr(handler, "connector_online_from_item", lambda _item: True)

    recovered = handler._recover_profile_jellyfin_binding_from_connector(
        "profile_member_1234567890",
        [{"connector_id": "connector-1"}],
        timeout_seconds=0.2,
    )

    assert recovered == {
        "state": "recovered",
        "connector_id": "connector-1",
        "jellyfin_user_id": provider_id,
    }
    assert table.deleted is True


def test_connector_recovery_refuses_ambiguous_online_connectors(monkeypatch):
    monkeypatch.setattr(handler, "remote_requests_table", object())
    monkeypatch.setattr(handler, "connector_online_from_item", lambda _item: True)

    recovered = handler._recover_profile_jellyfin_binding_from_connector(
        "profile_member_1234567890",
        [{"connector_id": "connector-1"}, {"connector_id": "connector-2"}],
        timeout_seconds=0.1,
    )

    assert recovered == {"state": "profile_jellyfin_connector_ambiguous"}


def test_repair_falls_back_to_exact_plugin_binding_when_invitation_has_none(monkeypatch):
    install_manager(monkeypatch)
    profile_id = "profile_member_1234567890"
    provider_id = "0123456789abcdef0123456789abcdef"
    profiles = ExactProfileTable([{
        "profile_id": profile_id,
        "household_id": "household-1",
        "member_principal_id": "principal-member",
        "state": "active",
    }])
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable())
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])
    monkeypatch.setattr(handler, "_household_identity_profile_records", lambda _household_id: list(profiles.records.values()))
    monkeypatch.setattr(
        handler,
        "_recover_profile_jellyfin_binding_from_connector",
        lambda _profile_id, _connectors: {
            "state": "recovered",
            "connector_id": "connector-1",
            "jellyfin_user_id": provider_id,
        },
    )

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "repair_from_consumed_invitation": True,
        "explicit_confirmation": True,
    })}, f"/v3/identity/profiles/{profile_id}/jellyfin-binding")

    assert result["statusCode"] == 200
    assert body(result) == {"state": "profile_jellyfin_binding_repaired"}
    assert profiles.records[profile_id]["jellyfin_user_id"] == provider_id


def test_parent_managed_repair_accepts_retained_exact_active_binding(monkeypatch):
    install_manager(monkeypatch)
    profile_id = "profile_kid_12345678901234"
    provider_id = "0123456789abcdef0123456789abcdef"
    profiles = ExactProfileTable([{
        "profile_id": profile_id,
        "household_id": "household-1",
        "state": "active",
        "managed_by_owner": True,
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": provider_id,
    }])
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable())
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])
    monkeypatch.setattr(
        handler,
        "_recover_profile_jellyfin_binding_from_connector",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("retained canonical binding must not invoke plugin recovery")
        ),
    )

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "repair_from_consumed_invitation": True,
        "explicit_confirmation": True,
    })}, f"/v3/identity/profiles/{profile_id}/jellyfin-binding")

    assert result["statusCode"] == 200
    assert body(result) == {"state": "profile_jellyfin_binding_repaired"}


def test_manager_saves_exact_pending_invitation_binding(monkeypatch):
    install_manager(monkeypatch)
    profile_id = "profile_member_1234567890"
    binding_handle = "a" * 64
    invitation = {
        "code_hash": binding_handle,
        "household_id": "household-1",
        "profile_id": profile_id,
        "state": "pending",
        "code_expires_at": 2_000,
    }
    invitations = ExactInvitationTable(invitation)
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable())
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)
    # Reproduce a newly-created invitation that is not visible through the
    # eventually-consistent household GSI yet.
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "jellyfin_user_id": "01234567-89ab-cdef-0123-456789abcdef",
        "explicit_confirmation": True,
        "invitation_binding_handle": binding_handle,
    })}, f"/v3/identity/profiles/{profile_id}/jellyfin-binding")

    assert result["statusCode"] == 200
    assert body(result) == {"state": "profile_jellyfin_binding_saved"}
    assert invitation["jellyfin_binding_state"] == "active"
    assert invitation["jellyfin_connector_id"] == "connector-1"
    assert invitation["jellyfin_user_id"] == "0123456789abcdef0123456789abcdef"


def test_manager_rejects_invalid_exact_pending_invitation_handle(monkeypatch):
    install_manager(monkeypatch)
    profile_id = "profile_member_1234567890"
    binding_handle = "b" * 64
    invitation = {
        "code_hash": binding_handle,
        "household_id": "household-other",
        "profile_id": profile_id,
        "state": "pending",
        "code_expires_at": 2_000,
    }
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable())
    monkeypatch.setattr(
        handler, "household_invitations_table", ExactInvitationTable(invitation),
    )
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "jellyfin_user_id": "01234567-89ab-cdef-0123-456789abcdef",
        "explicit_confirmation": True,
        "invitation_binding_handle": binding_handle,
    })}, f"/v3/identity/profiles/{profile_id}/jellyfin-binding")

    assert result["statusCode"] == 409
    assert body(result) == {
        "state": "profile_jellyfin_binding_invitation_invalid",
    }
    assert "jellyfin_binding_state" not in invitation
    assert "jellyfin_user_id" not in invitation


def test_manager_rejects_stale_or_mismatched_invitation_handles(monkeypatch):
    install_manager(monkeypatch)
    profile_id = "profile_member_1234567890"
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable())
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])

    cases = [
        {"state": "consumed", "profile_id": profile_id, "household_id": "household-1", "code_expires_at": 2_000},
        {"state": "revoked", "profile_id": profile_id, "household_id": "household-1", "code_expires_at": 2_000},
        {"state": "pending", "profile_id": profile_id, "household_id": "household-1", "code_expires_at": 999},
        {"state": "pending", "profile_id": "profile_other_12345678901", "household_id": "household-1", "code_expires_at": 2_000},
    ]
    for index, candidate in enumerate(cases):
        binding_handle = format(index + 1, "064x")
        invitation = {"code_hash": binding_handle, **candidate}
        monkeypatch.setattr(
            handler,
            "household_invitations_table",
            ExactInvitationTable(invitation),
        )
        result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
            "jellyfin_user_id": "01234567-89ab-cdef-0123-456789abcdef",
            "explicit_confirmation": True,
            "invitation_binding_handle": binding_handle,
        })}, f"/v3/identity/profiles/{profile_id}/jellyfin-binding")
        assert result["statusCode"] == 409
        assert body(result) == {
            "state": "profile_jellyfin_binding_invitation_invalid",
        }
        assert "jellyfin_binding_state" not in invitation
        assert "jellyfin_user_id" not in invitation


def test_owner_saves_exact_seerr_binding_on_pending_invitation(monkeypatch):
    install_seerr_owner(monkeypatch)
    profile_id = "profile_member_1234567890"
    binding_handle = "d" * 64
    jellyfin_user_id = "0123456789abcdef0123456789abcdef"
    invitation = {
        "code_hash": binding_handle,
        "household_id": "household-1",
        "profile_id": profile_id,
        "state": "pending",
        "code_expires_at": 2_000,
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": jellyfin_user_id,
    }
    invitations = ExactInvitationTable(invitation)
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable())
    monkeypatch.setattr(handler, "household_invitations_table", invitations)
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)

    result = handler.save_profile_seerr_binding_v3({"body": json.dumps({
        "jellyfin_user_id": jellyfin_user_id,
        "seerr_user_id": 42,
        "explicit_confirmation": True,
        "invitation_binding_handle": binding_handle,
    })}, f"/v3/identity/profiles/{profile_id}/seerr-binding")

    assert result["statusCode"] == 200
    assert body(result) == {"state": "profile_seerr_binding_saved"}
    assert invitation["seerr_binding_state"] == "active"
    assert invitation["seerr_connector_id"] == "connector-1"
    assert invitation["seerr_jellyfin_user_id"] == jellyfin_user_id
    assert invitation["seerr_user_id"] == "42"
    assert invitation["request_access_enabled"] is True


def test_owner_rejects_invalid_or_wrong_pending_seerr_binding_handle(monkeypatch):
    install_seerr_owner(monkeypatch)
    profile_id = "profile_member_1234567890"
    jellyfin_user_id = "0123456789abcdef0123456789abcdef"
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable())
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)

    cases = [
        {"state": "consumed", "profile_id": profile_id, "household_id": "household-1", "code_expires_at": 2_000},
        {"state": "revoked", "profile_id": profile_id, "household_id": "household-1", "code_expires_at": 2_000},
        {"state": "pending", "profile_id": profile_id, "household_id": "household-1", "code_expires_at": 999},
        {"state": "pending", "profile_id": profile_id, "household_id": "household-other", "code_expires_at": 2_000},
        {"state": "pending", "profile_id": "profile_other_12345678901", "household_id": "household-1", "code_expires_at": 2_000},
    ]
    for index, candidate in enumerate(cases):
        binding_handle = format(index + 20, "064x")
        invitation = {
            "code_hash": binding_handle,
            "jellyfin_binding_state": "active",
            "jellyfin_connector_id": "connector-1",
            "jellyfin_user_id": jellyfin_user_id,
            **candidate,
        }
        monkeypatch.setattr(
            handler,
            "household_invitations_table",
            ExactInvitationTable(invitation),
        )
        result = handler.save_profile_seerr_binding_v3({"body": json.dumps({
            "jellyfin_user_id": jellyfin_user_id,
            "seerr_user_id": 42,
            "explicit_confirmation": True,
            "invitation_binding_handle": binding_handle,
        })}, f"/v3/identity/profiles/{profile_id}/seerr-binding")
        assert result["statusCode"] == 409
        assert body(result) == {
            "state": "profile_seerr_binding_invitation_invalid",
        }
        assert "seerr_binding_state" not in invitation


def test_owner_rejects_pending_seerr_binding_with_wrong_jellyfin_tuple(monkeypatch):
    install_seerr_owner(monkeypatch)
    profile_id = "profile_member_1234567890"
    binding_handle = "e" * 64
    invitation = {
        "code_hash": binding_handle,
        "household_id": "household-1",
        "profile_id": profile_id,
        "state": "pending",
        "code_expires_at": 2_000,
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": "0123456789abcdef0123456789abcdef",
    }
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable())
    monkeypatch.setattr(
        handler, "household_invitations_table", ExactInvitationTable(invitation),
    )
    monkeypatch.setattr(handler, "epoch_now", lambda: 1_000)

    result = handler.save_profile_seerr_binding_v3({"body": json.dumps({
        "jellyfin_user_id": "fedcba9876543210fedcba9876543210",
        "seerr_user_id": 42,
        "explicit_confirmation": True,
        "invitation_binding_handle": binding_handle,
    })}, f"/v3/identity/profiles/{profile_id}/seerr-binding")

    assert result["statusCode"] == 409
    assert body(result) == {
        "state": "profile_seerr_binding_jellyfin_mismatch",
    }
    assert "seerr_binding_state" not in invitation


def test_owner_retains_active_profile_seerr_binding_path(monkeypatch):
    install_seerr_owner(monkeypatch)
    profile_id = "profile_member_1234567890"
    jellyfin_user_id = "0123456789abcdef0123456789abcdef"
    profiles = ExactProfileTable([{
        "profile_id": profile_id,
        "household_id": "household-1",
        "state": "active",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": jellyfin_user_id,
    }])
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable())

    result = handler.save_profile_seerr_binding_v3({"body": json.dumps({
        "jellyfin_user_id": jellyfin_user_id,
        "seerr_user_id": 42,
        "explicit_confirmation": True,
    })}, f"/v3/identity/profiles/{profile_id}/seerr-binding")

    assert result["statusCode"] == 200
    assert profiles.records[profile_id]["seerr_user_id"] == "42"
    assert profiles.records[profile_id]["request_access_enabled"] is True


def test_invitation_claim_promotes_only_consistent_exact_seerr_tuple():
    jellyfin_user_id = "0123456789abcdef0123456789abcdef"
    invitation = {
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": jellyfin_user_id,
        "jellyfin_binding_updated_at": "2026-08-19T06:00:00Z",
        "seerr_binding_state": "active",
        "seerr_connector_id": "connector-1",
        "seerr_jellyfin_user_id": jellyfin_user_id,
        "seerr_user_id": "42",
        "seerr_binding_updated_at": "2026-08-19T06:01:00Z",
    }

    promoted = handler._promote_invitation_provider_bindings(
        {}, invitation, "2026-08-19T06:02:00Z",
    )

    assert promoted["jellyfin_user_id"] == jellyfin_user_id
    assert promoted["seerr_connector_id"] == "connector-1"
    assert promoted["seerr_jellyfin_user_id"] == jellyfin_user_id
    assert promoted["seerr_user_id"] == "42"
    assert promoted["seerr_binding_state"] == "active"
    assert promoted["request_access_enabled"] is True

    mismatched = dict(invitation)
    mismatched["seerr_jellyfin_user_id"] = "fedcba9876543210fedcba9876543210"
    refused = handler._promote_invitation_provider_bindings(
        {}, mismatched, "2026-08-19T06:02:00Z",
    )
    assert "seerr_user_id" not in refused
    assert "seerr_binding_state" not in refused


def test_manager_rejects_provider_identity_already_owned_by_other_profile(monkeypatch):
    install_manager(monkeypatch)
    target_id = "profile_member_1234567890"
    existing_id = "profile_other_12345678901"
    provider_id = "0123456789abcdef0123456789abcdef"
    profiles = ExactProfileTable([
        {
            "profile_id": target_id,
            "household_id": "household-1",
            "state": "active",
        },
        {
            "profile_id": existing_id,
            "household_id": "household-1",
            "state": "active",
            "jellyfin_binding_state": "active",
            "jellyfin_connector_id": "connector-1",
            "jellyfin_user_id": provider_id,
        },
    ])
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable())
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])
    monkeypatch.setattr(handler, "_household_identity_profile_records", lambda _household_id: list(profiles.records.values()))

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "jellyfin_user_id": provider_id,
        "explicit_confirmation": True,
    })}, f"/v3/identity/profiles/{target_id}/jellyfin-binding")

    assert result["statusCode"] == 409
    assert body(result)["state"] == "jellyfin_identity_already_bound"
    assert "jellyfin_user_id" not in profiles.records[target_id]


def test_claim_projection_delivers_exact_binding_only_to_matching_connector(monkeypatch):
    profile_id = "profile_member_1234567890"
    provider_id = "0123456789abcdef0123456789abcdef"
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable([{
        "profile_id": profile_id,
        "household_id": "household-1",
        "state": "active",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": provider_id,
    }]))
    item = {
        "request_id": "request-1",
        "profile_id": profile_id,
        "connector_id": "connector-1",
        "status": "in_progress",
        "request_json": json.dumps({
            "provider": "jellyfin", "method": "GET",
            "path": "/kaevo/internal/main-snapshot", "query": {},
        }),
    }

    projected = handler.connector_remote_request_item(item)
    assert projected["profile_provider_binding"] == {
        "provider": "jellyfin",
        "connector_id": "connector-1",
        "provider_user_id": provider_id,
    }
    item["connector_id"] = "connector-2"
    assert "profile_provider_binding" not in handler.connector_remote_request_item(item)


def test_binding_route_requires_explicit_confirmation(monkeypatch):
    install_manager(monkeypatch)
    monkeypatch.setattr(handler, "identity_profiles_table", ExactProfileTable())
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable())
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])
    profile_id = "profile_member_1234567890"
    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "jellyfin_user_id": "0123456789abcdef0123456789abcdef",
    })}, f"/v3/identity/profiles/{profile_id}/jellyfin-binding")
    assert result["statusCode"] == 400
    assert body(result)["state"] == "profile_jellyfin_binding_invalid"


def test_manager_repairs_exact_consumed_invitation_binding(monkeypatch):
    install_manager(monkeypatch)
    profile_id = "profile_member_1234567890"
    member_principal_id = "principal-member"
    provider_id = "0123456789abcdef0123456789abcdef"
    profiles = ExactProfileTable([{
        "profile_id": profile_id,
        "household_id": "household-1",
        "member_principal_id": member_principal_id,
        "state": "active",
    }])
    invitation = {
        "code_hash": "opaque-hash",
        "household_id": "household-1",
        "profile_id": profile_id,
        "member_principal_id": member_principal_id,
        "state": "consumed",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": provider_id,
    }
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable(invitation))
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [invitation])
    monkeypatch.setattr(handler, "_household_identity_profile_records", lambda _household_id: list(profiles.records.values()))
    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "repair_from_consumed_invitation": True,
        "explicit_confirmation": True,
    })}, f"/v3/identity/profiles/{profile_id}/jellyfin-binding")

    assert result["statusCode"] == 200
    assert body(result) == {"state": "profile_jellyfin_binding_repaired"}
    assert profiles.records[profile_id]["jellyfin_user_id"] == provider_id
    assert profiles.records[profile_id]["jellyfin_connector_id"] == "connector-1"


def test_consumed_invitation_repair_rejects_subject_mismatch(monkeypatch):
    install_manager(monkeypatch)
    profile_id = "profile_member_1234567890"
    profiles = ExactProfileTable([{
        "profile_id": profile_id,
        "household_id": "household-1",
        "member_principal_id": "principal-member",
        "state": "active",
    }])
    invitation = {
        "household_id": "household-1",
        "profile_id": profile_id,
        "member_principal_id": "different-principal",
        "state": "consumed",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": "0123456789abcdef0123456789abcdef",
    }
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable(invitation))
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [invitation])
    monkeypatch.setattr(handler, "_household_identity_profile_records", lambda _household_id: list(profiles.records.values()))
    monkeypatch.setattr(
        handler,
        "_recover_profile_jellyfin_binding_from_connector",
        lambda _profile_id, _connectors: {
            "state": "profile_jellyfin_binding_source_missing",
        },
    )

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "repair_from_consumed_invitation": True,
        "explicit_confirmation": True,
    })}, f"/v3/identity/profiles/{profile_id}/jellyfin-binding")

    assert result["statusCode"] == 409
    assert body(result)["state"] == "profile_jellyfin_binding_source_missing"
    assert "jellyfin_user_id" not in profiles.records[profile_id]


def test_consumed_invitation_repair_rejects_ambiguous_sources(monkeypatch):
    install_manager(monkeypatch)
    profile_id = "profile_member_1234567890"
    profiles = ExactProfileTable([{
        "profile_id": profile_id,
        "household_id": "household-1",
        "member_principal_id": "principal-member",
        "state": "active",
    }])
    invitation = {
        "household_id": "household-1",
        "profile_id": profile_id,
        "member_principal_id": "principal-member",
        "state": "consumed",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": "0123456789abcdef0123456789abcdef",
    }
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable(invitation))
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [dict(invitation), dict(invitation)])
    monkeypatch.setattr(handler, "_household_identity_profile_records", lambda _household_id: list(profiles.records.values()))

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "repair_from_consumed_invitation": True,
        "explicit_confirmation": True,
    })}, f"/v3/identity/profiles/{profile_id}/jellyfin-binding")

    assert result["statusCode"] == 409
    assert body(result)["state"] == "profile_jellyfin_binding_source_ambiguous"
    assert "jellyfin_user_id" not in profiles.records[profile_id]


def test_repair_never_overwrites_a_different_active_binding(monkeypatch):
    install_manager(monkeypatch)
    profile_id = "profile_member_1234567890"
    profiles = ExactProfileTable([{
        "profile_id": profile_id,
        "household_id": "household-1",
        "member_principal_id": "principal-member",
        "state": "active",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }])
    invitation = {
        "household_id": "household-1",
        "profile_id": profile_id,
        "member_principal_id": "principal-member",
        "state": "consumed",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    }
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable(invitation))
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [invitation])
    monkeypatch.setattr(handler, "_household_identity_profile_records", lambda _household_id: list(profiles.records.values()))

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "repair_from_consumed_invitation": True,
        "explicit_confirmation": True,
    })}, f"/v3/identity/profiles/{profile_id}/jellyfin-binding")

    assert result["statusCode"] == 409
    assert body(result)["state"] == "profile_jellyfin_binding_conflict"
    assert profiles.records[profile_id]["jellyfin_user_id"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def test_explicit_reassignment_moves_exact_inactive_owner(monkeypatch):
    install_manager(monkeypatch)
    target_id = "profile_member_1234567890"
    stale_id = "profile_stale_12345678901"
    provider_id = "0123456789abcdef0123456789abcdef"
    profiles = ExactProfileTable([
        {
            "profile_id": target_id,
            "household_id": "household-1",
            "state": "active",
        },
        {
            "profile_id": stale_id,
            "household_id": "household-1",
            "state": "deleted",
        },
    ])
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable())
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])
    monkeypatch.setattr(
        handler,
        "_household_identity_profile_records",
        lambda _household_id: list(profiles.records.values()),
    )
    commands = []

    def execute(profile_id, connectors, operation, parameters):
        commands.append((profile_id, connectors, operation, parameters))
        if operation == "jellyfin.inspect_profile_binding_owner":
            return {
                "state": "completed",
                "connector_id": "connector-1",
                "result": {
                    "provider": "jellyfin",
                    "owner_state": "found",
                    "source_profile_id": stale_id,
                },
            }
        assert operation == "jellyfin.reassign_stale_profile_binding"
        assert parameters == {
            "jellyfin_user_id": provider_id,
            "expected_source_profile_id": stale_id,
            "target_profile_id": target_id,
        }
        return {
            "state": "completed",
            "connector_id": "connector-1",
            "result": {"provider": "jellyfin", "state": "reassigned"},
        }

    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", execute)

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "jellyfin_user_id": provider_id,
        "explicit_confirmation": True,
        "allow_inactive_reassignment": True,
    })}, f"/v3/identity/profiles/{target_id}/jellyfin-binding")

    assert result["statusCode"] == 200
    assert body(result) == {"state": "profile_jellyfin_binding_reassigned"}
    assert [command[2] for command in commands] == [
        "jellyfin.inspect_profile_binding_owner",
        "jellyfin.reassign_stale_profile_binding",
    ]
    assert profiles.records[target_id]["jellyfin_user_id"] == provider_id
    assert profiles.records[target_id]["jellyfin_connector_id"] == "connector-1"


def test_explicit_reassignment_refuses_active_source_profile(monkeypatch):
    install_manager(monkeypatch)
    target_id = "profile_member_1234567890"
    source_id = "profile_active_1234567890"
    provider_id = "0123456789abcdef0123456789abcdef"
    profiles = ExactProfileTable([
        {
            "profile_id": target_id,
            "household_id": "household-1",
            "state": "active",
        },
        {
            "profile_id": source_id,
            "household_id": "household-1",
            "state": "active",
        },
    ])
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable())
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])
    monkeypatch.setattr(
        handler,
        "_household_identity_profile_records",
        lambda _household_id: list(profiles.records.values()),
    )

    def execute(_profile_id, _connectors, operation, _parameters):
        assert operation == "jellyfin.inspect_profile_binding_owner"
        return {
            "state": "completed",
            "connector_id": "connector-1",
            "result": {
                "provider": "jellyfin",
                "owner_state": "found",
                "source_profile_id": source_id,
            },
        }

    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", execute)

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "jellyfin_user_id": provider_id,
        "explicit_confirmation": True,
        "allow_inactive_reassignment": True,
    })}, f"/v3/identity/profiles/{target_id}/jellyfin-binding")

    assert result["statusCode"] == 409
    assert body(result) == {"state": "jellyfin_identity_already_bound"}
    assert "jellyfin_user_id" not in profiles.records[target_id]


def test_explicit_reassignment_refuses_unrelated_inactive_source(monkeypatch):
    install_manager(monkeypatch)
    target_id = "profile_member_1234567890"
    source_id = "profile_unrelated_12345678"
    provider_id = "0123456789abcdef0123456789abcdef"
    profiles = ExactProfileTable([
        {
            "profile_id": target_id,
            "household_id": "household-1",
            "state": "active",
        },
        {
            "profile_id": source_id,
            "household_id": "household-2",
            "state": "deleted",
        },
    ])
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable())
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])
    monkeypatch.setattr(
        handler,
        "_household_identity_profile_records",
        lambda _household_id: [profiles.records[target_id]],
    )
    monkeypatch.setattr(
        handler,
        "_execute_profile_binding_connector_command",
        lambda _profile_id, _connectors, _operation, _parameters: {
            "state": "completed",
            "connector_id": "connector-1",
            "result": {
                "provider": "jellyfin",
                "owner_state": "found",
                "source_profile_id": source_id,
            },
        },
    )

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "jellyfin_user_id": provider_id,
        "explicit_confirmation": True,
        "allow_inactive_reassignment": True,
    })}, f"/v3/identity/profiles/{target_id}/jellyfin-binding")

    assert result["statusCode"] == 409
    assert body(result) == {"state": "profile_jellyfin_binding_owner_unrelated"}
    assert "jellyfin_user_id" not in profiles.records[target_id]


def test_explicit_reassignment_refuses_missing_source_record(monkeypatch):
    install_manager(monkeypatch)
    target_id = "profile_member_1234567890"
    missing_source_id = "profile_missing_123456789"
    provider_id = "0123456789abcdef0123456789abcdef"
    profiles = ExactProfileTable([{
        "profile_id": target_id,
        "household_id": "household-1",
        "state": "active",
    }])
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable())
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])
    monkeypatch.setattr(
        handler,
        "_household_identity_profile_records",
        lambda _household_id: list(profiles.records.values()),
    )
    monkeypatch.setattr(
        handler,
        "_execute_profile_binding_connector_command",
        lambda _profile_id, _connectors, _operation, _parameters: {
            "state": "completed",
            "connector_id": "connector-1",
            "result": {
                "provider": "jellyfin",
                "owner_state": "found",
                "source_profile_id": missing_source_id,
            },
        },
    )

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "jellyfin_user_id": provider_id,
        "explicit_confirmation": True,
        "allow_inactive_reassignment": True,
    })}, f"/v3/identity/profiles/{target_id}/jellyfin-binding")

    assert result["statusCode"] == 409
    assert body(result) == {"state": "profile_jellyfin_binding_owner_unverifiable"}
    assert "jellyfin_user_id" not in profiles.records[target_id]


def test_failed_connector_compare_and_swap_never_updates_cloud(monkeypatch):
    install_manager(monkeypatch)
    target_id = "profile_member_1234567890"
    stale_id = "profile_stale_12345678901"
    provider_id = "0123456789abcdef0123456789abcdef"
    profiles = ExactProfileTable([
        {
            "profile_id": target_id,
            "household_id": "household-1",
            "state": "active",
        },
        {
            "profile_id": stale_id,
            "household_id": "household-1",
            "state": "deleted",
        },
    ])
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable())
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])
    monkeypatch.setattr(
        handler,
        "_household_identity_profile_records",
        lambda _household_id: list(profiles.records.values()),
    )

    def execute(_profile_id, _connectors, operation, _parameters):
        if operation == "jellyfin.inspect_profile_binding_owner":
            return {
                "state": "completed",
                "connector_id": "connector-1",
                "result": {
                    "provider": "jellyfin",
                    "owner_state": "found",
                    "source_profile_id": stale_id,
                },
            }
        return {"state": "profile_jellyfin_binding_command_failed"}

    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", execute)

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "jellyfin_user_id": provider_id,
        "explicit_confirmation": True,
        "allow_inactive_reassignment": True,
    })}, f"/v3/identity/profiles/{target_id}/jellyfin-binding")

    assert result["statusCode"] == 409
    assert body(result) == {"state": "profile_jellyfin_binding_command_failed"}
    assert "jellyfin_user_id" not in profiles.records[target_id]


def test_binding_preflight_authorizes_an_explicitly_selected_unbound_target(monkeypatch):
    install_manager(monkeypatch)
    target_id = "profile_member_1234567890"
    provider_id = "0123456789abcdef0123456789abcdef"
    operations = BindingOperationTable()
    profiles = ExactProfileTable([{
        "profile_id": target_id,
        "household_id": "household-1",
        "state": "active",
    }])
    monkeypatch.setattr(handler, "binding_operations_table", operations)
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "remote_requests_table", object())
    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", lambda *_args, **_kwargs: {
        "state": "completed",
        "connector_id": "connector-1",
        "result": {"provider": "jellyfin", "owner_state": "missing"},
    })

    result = handler.preflight_profile_jellyfin_binding_v3({"body": json.dumps({
        "operation_id": "operation_abcdefghijklmnopqrstuv",
        "jellyfin_user_id": provider_id,
        "explicit_confirmation": True,
    })}, f"/v3/identity/profiles/{target_id}/jellyfin-binding-operations")

    assert result["statusCode"] == 200
    operation = body(result)["operation"]
    assert operation["phase"] == "mutation_authorized"
    assert operation["source_state"] == "unbound_target_explicit"
    assert operation["terminal_result"] == "preflight_eligible"
    persisted = next(iter(operations.records.values()))
    assert persisted["provider_user_fingerprint"] == handler._binding_operation_fingerprint(provider_id)
    assert "jellyfin_user_id" not in persisted
    assert "operation_id" not in operation


def test_binding_preflight_reuses_exact_operation_without_second_dispatch(monkeypatch):
    install_manager(monkeypatch)
    target_id = "profile_member_1234567890"
    provider_id = "0123456789abcdef0123456789abcdef"
    operations = BindingOperationTable()
    profiles = ExactProfileTable([{
        "profile_id": target_id,
        "household_id": "household-1",
        "state": "active",
    }])
    calls = []
    monkeypatch.setattr(handler, "binding_operations_table", operations)
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "remote_requests_table", object())
    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", lambda *_args, **_kwargs: calls.append(1) or {
        "state": "completed",
        "connector_id": "connector-1",
        "result": {"provider": "jellyfin", "owner_state": "missing"},
    })
    event = {"body": json.dumps({
        "operation_id": "operation_abcdefghijklmnopqrstuv",
        "jellyfin_user_id": provider_id,
        "explicit_confirmation": True,
    })}
    path = f"/v3/identity/profiles/{target_id}/jellyfin-binding-operations"

    assert handler.preflight_profile_jellyfin_binding_v3(event, path)["statusCode"] == 200
    repeated = handler.preflight_profile_jellyfin_binding_v3(event, path)

    assert repeated["statusCode"] == 200
    assert body(repeated)["operation"]["source_state"] == "unbound_target_explicit"
    assert calls == [1]


def test_binding_preflight_refuses_a_partially_populated_target_when_owner_is_missing(monkeypatch):
    install_manager(monkeypatch)
    target_id = "profile_member_1234567890"
    provider_id = "0123456789abcdef0123456789abcdef"
    operations = BindingOperationTable()
    profiles = ExactProfileTable([{
        "profile_id": target_id,
        "household_id": "household-1",
        "state": "active",
        "jellyfin_connector_id": "connector-stale",
    }])
    monkeypatch.setattr(handler, "binding_operations_table", operations)
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "remote_requests_table", object())
    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", lambda *_args, **_kwargs: {
        "state": "completed",
        "connector_id": "connector-1",
        "result": {"provider": "jellyfin", "owner_state": "missing"},
    })

    result = handler.preflight_profile_jellyfin_binding_v3({"body": json.dumps({
        "operation_id": "operation_abcdefghijklmnopqrstuv",
        "jellyfin_user_id": provider_id,
        "explicit_confirmation": True,
    })}, f"/v3/identity/profiles/{target_id}/jellyfin-binding-operations")

    assert result["statusCode"] == 200
    operation = body(result)["operation"]
    assert operation["phase"] == "safely_refused"
    assert operation["source_state"] == "absent_without_proof"
    assert operation["terminal_result"] == "safely_refused"


def test_binding_preflight_authorizes_only_a_same_household_deleted_source_tombstone(monkeypatch):
    install_manager(monkeypatch)
    target_id = "profile_member_1234567890"
    source_id = "profile_deleted_123456789"
    provider_id = "0123456789abcdef0123456789abcdef"
    operations = BindingOperationTable()
    profiles = ExactProfileTable([{
        "profile_id": target_id,
        "household_id": "household-1",
        "state": "active",
    }])
    monkeypatch.setattr(handler, "binding_operations_table", operations)
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "profile_binding_tombstones_table", ExactTombstoneTable([{
        "profile_id": source_id,
        "household_id": "household-1",
        "state": "deleted",
    }]))
    monkeypatch.setattr(handler, "remote_requests_table", object())
    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", lambda *_args, **_kwargs: {
        "state": "completed",
        "connector_id": "connector-1",
        "result": {
            "provider": "jellyfin",
            "owner_state": "found",
            "source_profile_id": source_id,
        },
    })

    result = handler.preflight_profile_jellyfin_binding_v3({"body": json.dumps({
        "operation_id": "operation_abcdefghijklmnopqrstuv",
        "jellyfin_user_id": provider_id,
        "explicit_confirmation": True,
    })}, f"/v3/identity/profiles/{target_id}/jellyfin-binding-operations")

    assert result["statusCode"] == 200
    operation = body(result)["operation"]
    assert operation["phase"] == "mutation_authorized"
    assert operation["source_state"] == "absent_with_valid_tombstone"
    assert operation["terminal_result"] == "preflight_eligible"


def test_guarded_reassignment_publishes_member_snapshot_only_after_cloud_persistence(monkeypatch):
    install_manager(monkeypatch)
    target_id = "profile_member_1234567890"
    source_id = "profile_deleted_123456789"
    provider_id = "0123456789abcdef0123456789abcdef"
    operation_id = "operation_abcdefghijklmnopqrstuv"
    operations = BindingOperationTable()
    profiles = ExactProfileTable([
        {
            "profile_id": target_id,
            "household_id": "household-1",
            "state": "active",
        },
        {
            "profile_id": source_id,
            "household_id": "household-1",
            "state": "deleted",
        },
    ])
    monkeypatch.setattr(handler, "binding_operations_table", operations)
    monkeypatch.setattr(handler, "identity_profiles_table", profiles)
    monkeypatch.setattr(handler, "remote_requests_table", object())
    monkeypatch.setattr(handler, "household_invitations_table", ExactInvitationTable())
    monkeypatch.setattr(handler, "_household_invitation_records", lambda _household_id: [])
    monkeypatch.setattr(
        handler,
        "_household_identity_profile_records",
        lambda _household_id: list(profiles.records.values()),
    )

    def execute(_profile_id, _connectors, operation, _parameters, **_kwargs):
        if operation == "jellyfin.inspect_profile_binding_owner":
            return {
                "state": "completed", "connector_id": "connector-1",
                "result": {
                    "provider": "jellyfin", "owner_state": "found",
                    "source_profile_id": source_id,
                },
            }
        return {
            "state": "completed", "connector_id": "connector-1",
            "result": {"provider": "jellyfin", "state": "reassigned"},
        }

    monkeypatch.setattr(handler, "_execute_profile_binding_connector_command", execute)
    monkeypatch.setattr(
        handler,
        "_publish_profile_jellyfin_snapshot",
        lambda *_args, **_kwargs: {"state": "snapshot_published"},
    )
    preflight = handler.preflight_profile_jellyfin_binding_v3({"body": json.dumps({
        "operation_id": operation_id,
        "jellyfin_user_id": provider_id,
        "explicit_confirmation": True,
    })}, f"/v3/identity/profiles/{target_id}/jellyfin-binding-operations")
    assert preflight["statusCode"] == 200

    result = handler.save_profile_jellyfin_binding_v3({"body": json.dumps({
        "operation_id": operation_id,
        "jellyfin_user_id": provider_id,
        "explicit_confirmation": True,
        "allow_inactive_reassignment": True,
    })}, f"/v3/identity/profiles/{target_id}/jellyfin-binding")

    assert result["statusCode"] == 200
    assert body(result) == {"state": "profile_jellyfin_binding_reassigned"}
    persisted = operations.records[operation_id]
    assert persisted["cloud_persistence_result"] == "persisted"
    assert persisted["snapshot_result"] == "published"
    assert persisted["phase"] == "completed"
    assert persisted["terminal_result"] == "completed"
