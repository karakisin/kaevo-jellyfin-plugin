"""Fail-closed approval record for a bounded CloudFormation drift exception."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .constants import AWS_ACCOUNT_ID, AWS_PROFILE, AWS_REGION, STACK_NAME
from .errors import FixtureSafetyError


RECORD_NAME = "cloudformation-control-plane-exception.json"
MAX_AGE = timedelta(hours=24)


def assert_control_plane_exception(root: str | Path, *, now: datetime) -> None:
    """Require current, structured evidence before live fixture work proceeds."""
    path = Path(root) / RECORD_NAME
    try:
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise FixtureSafetyError("CFN_EXCEPTION_RECORD_MODE_INVALID")
        record = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError) as error:
        raise FixtureSafetyError("CFN_EXCEPTION_RECORD_MISSING_OR_INVALID") from error
    if not isinstance(record, dict):
        raise FixtureSafetyError("CFN_EXCEPTION_RECORD_MISSING_OR_INVALID")
    expected = {"schema": 2, "state": "CONTROL_PLANE_UNVERIFIABLE_BRANDING_ONLY", "account": AWS_ACCOUNT_ID, "profile": AWS_PROFILE, "region": AWS_REGION, "stack_status": "UPDATE_COMPLETE", "allowed_next_operation": "FIXTURE_RUNNER_PREFLIGHT"}
    if any(record.get(key) != value for key, value in expected.items()):
        raise FixtureSafetyError("CFN_EXCEPTION_RECORD_SCOPE_MISMATCH")
    try:
        verified = datetime.fromisoformat(str(record["expires_utc"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as error:
        raise FixtureSafetyError("CFN_EXCEPTION_RECORD_TIME_INVALID") from error
    if verified.tzinfo is None or verified.astimezone(UTC) <= now or verified > now + MAX_AGE:
        raise FixtureSafetyError("CFN_EXCEPTION_RECORD_STALE")
    integrity = record.pop("integrity_sha256", None)
    actual = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    record["integrity_sha256"] = integrity
    if not isinstance(integrity, str) or integrity != actual:
        raise FixtureSafetyError("CFN_EXCEPTION_INTEGRITY_INVALID")
    full = record.get("terminal_drift")
    branding = record.get("branding_direct_fingerprint")
    if not isinstance(full, dict) or full.get("detection_status") != "DETECTION_FAILED" or full.get("stack_drift_status") != "UNKNOWN":
        raise FixtureSafetyError("CFN_EXCEPTION_FULL_STACK_NOT_CONFIRMED")
    if not isinstance(branding, str) or len(branding) != 64:
        raise FixtureSafetyError("CFN_EXCEPTION_BRANDING_NOT_CONFIRMED")
    if record.get("reason") != "CLOUDFORMATION_BRANDING_INTERNAL_FAILURE" or record.get("api_role_drift") != "IN_SYNC" or record.get("removed_iam_policy_absent") is not True or record.get("resource_results_complete") is not True:
        raise FixtureSafetyError("CFN_EXCEPTION_BRANDING_EQUIVALENCE_MISSING")
