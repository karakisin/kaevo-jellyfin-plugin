from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HANDLER = (ROOT / "api/src/handler.py").read_text()
TEMPLATE = (ROOT / "infra/template.yaml").read_text()


def test_guest_pass_routes_are_dispatchable_and_not_profiles():
    assert 'path == "/v1/guest-passes"' in HANDLER
    assert 'path == "/v1/guest-passes/claim"' in HANDLER
    assert 'return create_guest_pass(event)' in HANDLER
    assert '"record_type": "guest_access"' in HANDLER
    assert '"profile_type": "guest"' not in HANDLER
    assert 'path == "/v1/guest-pass/session"' in HANDLER
    assert 'path == "/v1/guest-pass/content"' in HANDLER
    assert 'path == "/v1/guest-pass/activity"' in HANDLER
    assert 'return get_guest_remote_request(event, path)' in HANDLER


def test_guest_pass_table_is_encrypted_retained_and_ttl_bounded():
    guest_table = TEMPLATE.split("  KaevoGuestPassesTable:", 1)[1].split(
        "\n  KaevoHouseholdJoinTransactionsTable:", 1
    )[0]
    assert "DeletionPolicy: Retain" in guest_table
    assert "UpdateReplacePolicy: Retain" in guest_table
    assert "SSEEnabled: true" in guest_table
    assert "PointInTimeRecoveryEnabled: true" in guest_table
    assert "AttributeName: expires_at" in guest_table
    assert "household_id-created_at_epoch-index" in guest_table


def test_guest_claim_is_one_device_and_dpop_bound():
    claim = HANDLER.split("def claim_guest_pass(event):", 1)[1].split(
        "\ndef household_invitation_response", 1
    )[0]
    assert "validate_public_jwk(public_jwk)" in claim
    assert "verify_dpop(" in claim
    assert '"key_thumbprint": thumbprint' in claim
    assert '"device_id": device_id' in claim
    assert '"state": "guest_pass_device_bound"' in claim
    assert "claim_secret_hash" in claim
    assert "guest_pass_pin_matches" in claim


def test_three_pass_limit_is_an_atomic_slot_transaction():
    create = HANDLER.split("def create_guest_pass(event):", 1)[1].split(
        "\ndef list_guest_passes", 1
    )[0]
    assert "for slot_index in range(MAX_ACTIVE_PASSES)" in create
    assert "transact_write_items" in create
    assert '"record_type": "guest_pass_slot"' in create
    assert '"state": "guest_pass_limit_reached"' in create


def test_requests_permission_is_data_only_and_does_not_modify_locked_routes():
    assert '"request_content"' in (ROOT / "api/src/guest_pass.py").read_text()
    claim_and_owner_routes = HANDLER.split("GUEST_PASS_RECORD_RETENTION_SECONDS", 1)[1].split(
        "def household_invitation_response", 1
    )[0]
    assert "/commands/seerr.request" not in claim_and_owner_routes


def test_guest_content_is_separately_dpop_authorized_and_server_filtered():
    access = HANDLER.split("def _guest_access_context(event, *, allow_expired_finish_current=False):", 1)[1].split(
        "\ndef guest_pass_session", 1
    )[0]
    assert 'f"guest#{production_token_hash(token)}"' in access
    assert "verify_dpop(" in access
    assert "guest_pass_effective_state" in access
    assert "guest_pass_scope_authorizes(" in HANDLER
    assert '"guest_pass_id": str(guest_pass.get("pass_id")' in HANDLER
    assert "_guest_filter_main_snapshot(" in HANDLER


def test_guest_playback_starts_only_after_trusted_scope_and_route_validation():
    completion = HANDLER.split(
        "def _completion_with_embedded_playback_grant", 1
    )[1].split("\ndef get_remote_request", 1)[0]
    assert "guest_pass_scope_authorizes(" in completion
    assert "_activate_guest_pass_for_playback(candidate, item_id)" in completion
    assert completion.index("SAFE_PLAYBACK_IDENTIFIER.fullmatch(media_source_id)") < completion.index(
        "_activate_guest_pass_for_playback(candidate, item_id)"
    )
    assert "expires_at_cap=guest_expires_at_cap" in completion
    assert "active_until=guest_active_until" in completion
    assert "runtime_seconds + 600" in completion
    assert 'path == "/v1/guest-pass/playback"' in HANDLER
    assert 'active_playback = :active_playback' in completion
    assert '"active_until"' in HANDLER


def test_guest_activity_is_isolated_and_one_view_completion_is_fail_closed():
    activity = HANDLER.split("def record_guest_playback_activity", 1)[1].split(
        "\ndef _activate_guest_pass_for_playback", 1
    )[0]
    assert 'allow_expired_finish_current=True' in activity
    assert 'active_playback.playback_session_id = :session_id' in activity
    assert 'completed_item_ids = list_append' in activity
    assert 'household-progress' not in activity
    assert 'jellyfin.playback_' not in activity


def test_guest_scope_projection_and_search_are_server_owned():
    content = HANDLER.split("def create_guest_content_request", 1)[1].split(
        "\ndef create_guest_playback_request", 1
    )[0]
    assert 'path = "/kaevo/internal/guest-scope"' in content
    assert 'resource == "search"' in content
    assert '_authorized_jellyfin_metadata_request(' in content
    assert '_guest_annotate_item_page' in HANDLER


def test_plugin_returns_server_trusted_playback_ancestry():
    plugin = (
        ROOT.parent
        / "Kaevo Jellyfin Plugin/src/Kaevo.Plugin.KaevoForJellyfin/Services/KaevoCloudConnectorService.cs"
    ).read_text()
    assert "item_kind = itemKind" in plugin
    assert "series_id = seriesId" in plugin
    assert "season_id = seasonId" in plugin
    assert "runtime_ticks = runTimeTicks" in plugin
