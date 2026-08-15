import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(ROOT))

from guest_pass import (  # noqa: E402
    GuestPassValidationError,
    effective_state,
    normalize_create_request,
    pin_matches,
    pin_record,
    scope_authorizes,
)


ITEM = "a" * 32
SHOW = "b" * 32


def valid_body(now):
    return {
        "guest_name": "Alex",
        "source_profile_id": "profile_abcdefghijklmnop",
        "start_by": now + 86_400,
        "expiration": {"kind": "duration_after_first_play", "seconds": 172_800},
        "scope": {"kind": "episodes", "entries": [{"kind": "episode", "item_id": ITEM}]},
        "permissions": {"casting": True, "search_granted_content": True},
        "replay_policy": "one_completed_view",
        "expiration_behavior": "finish_current_video",
        "pin": "0427",
    }


def test_normalizes_explicit_owner_policy_without_request_defaults():
    now = int(time.time())
    result = normalize_create_request(valid_body(now), now=now)
    assert result["guest_name"] == "Alex"
    assert result["permissions"]["casting"] is True
    assert result["permissions"]["request_content"] is False
    assert result["scope"]["entries"] == [{"kind": "episode", "item_id": ITEM}]


def test_rejects_more_than_30_days_and_unknown_permissions():
    now = int(time.time())
    body = valid_body(now)
    body["start_by"] = now + 31 * 86_400
    try:
        normalize_create_request(body, now=now)
        assert False, "expected validation failure"
    except GuestPassValidationError as error:
        assert error.state == "invalid_start_by"

    body = valid_body(now)
    body["permissions"]["delete_media"] = True
    try:
        normalize_create_request(body, now=now)
        assert False, "expected validation failure"
    except GuestPassValidationError as error:
        assert error.state == "invalid_permissions"


def test_pin_is_salted_and_constant_time_verifiable():
    salt, digest = pin_record("0427")
    assert salt and digest and "0427" not in digest
    assert pin_matches("0427", salt, digest)
    assert not pin_matches("0428", salt, digest)


def test_show_scope_requires_server_resolved_ancestry():
    scope = {"kind": "shows", "entries": [{"kind": "show", "item_id": SHOW}]}
    assert not scope_authorizes(scope, item_id=ITEM, item_kind="episode")
    assert scope_authorizes(
        scope,
        item_id=ITEM,
        item_kind="episode",
        ancestor_ids={"show": SHOW},
    )


def test_unstarted_pass_expires_at_start_by_even_offline():
    assert effective_state(
        {"state": "claimed", "start_by": 100, "started_at": None}, now=101
    ) == "expired"


def test_fixed_pass_expires_from_owner_selected_time_without_start():
    assert effective_state(
        {
            "state": "claimed",
            "start_by": 200,
            "started_at": "2026-08-15T00:00:00Z",
            "expiration": {"kind": "fixed", "at": 100},
        },
        now=101,
    ) == "expired"
