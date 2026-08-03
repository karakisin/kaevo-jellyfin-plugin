from __future__ import annotations

import datetime as dt
import hashlib
import json
import os

import pytest

from scripts.household_join_live.control_plane import RECORD_NAME, assert_control_plane_exception
from scripts.household_join_live.errors import FixtureSafetyError


NOW = dt.datetime(2026, 7, 27, 12, tzinfo=dt.timezone.utc)


def write_record(root, **changes):
    record = {"schema": 2, "state": "CONTROL_PLANE_UNVERIFIABLE_BRANDING_ONLY", "reason": "CLOUDFORMATION_BRANDING_INTERNAL_FAILURE", "account": "295055514343", "profile": "kaevo-dev", "region": "us-west-2", "stack_status": "UPDATE_COMPLETE", "allowed_next_operation": "FIXTURE_RUNNER_PREFLIGHT", "expires_utc": (NOW + dt.timedelta(minutes=30)).isoformat().replace("+00:00", "Z"), "terminal_drift": {"detection_status": "DETECTION_FAILED", "stack_drift_status": "UNKNOWN"}, "branding_direct_fingerprint": "a" * 64, "api_role_drift": "IN_SYNC", "removed_iam_policy_absent": True, "resource_results_complete": True}
    record.update(changes)
    record["integrity_sha256"] = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    path = root / RECORD_NAME
    path.write_text(json.dumps(record)); os.chmod(path, 0o600)


def test_valid_exception_record_is_accepted(tmp_path):
    write_record(tmp_path)
    assert_control_plane_exception(tmp_path, now=NOW)


@pytest.mark.parametrize("changes", [{"terminal_drift": {}}, {"branding_direct_fingerprint": "short"}, {"resource_results_complete": False}])
def test_incomplete_exception_evidence_fails_closed(tmp_path, changes):
    write_record(tmp_path, **changes)
    with pytest.raises(FixtureSafetyError):
        assert_control_plane_exception(tmp_path, now=NOW)
