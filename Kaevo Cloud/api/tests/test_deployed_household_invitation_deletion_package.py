from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "build-deployed-household-invitation-deletion-package.py"
SPEC = importlib.util.spec_from_file_location("invitation_delete_package", SCRIPT)
assert SPEC and SPEC.loader
PACKAGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PACKAGE
SPEC.loader.exec_module(PACKAGE)


DEPLOYED = '''
import re

def revoke_household_invitation(event, path):
    return None

def join_household(event):
    return None

def handler(event, context):
    method = event["method"]
    path = event["path"]
    if method == "POST" and path.startswith("/v2/household/invitations/") and path.endswith("/revoke"):
        return revoke_household_invitation(event, path)

    if method == "POST" and path == "/v2/identity/join-household":
        return join_household(event)
'''

LOCAL = '''
def household_manager_bound_session(event):
    return {"household_id": "household-1"}, None

def _household_invitation_records(household_id):
    return table.query(KeyConditionExpression=key).get("Items", [])

def _household_invitation_by_id(household_id, invitation_id):
    return next((item for item in _household_invitation_records(household_id)), None)

def delete_household_invitation(event, path):
    invitation = _household_invitation_by_id("household-1", "invitation-1")
    table.delete_item(Key={"code_hash": invitation["code_hash"]})
    return response(200, {"state": "invitation_deleted"})
'''


def test_package_inserts_only_exact_delete_function_and_dispatch():
    patched = PACKAGE.patched_handler(DEPLOYED, LOCAL)
    assert "def delete_household_invitation" in patched
    assert 'method == "DELETE"' in patched
    assert patched.count(".scan(") == DEPLOYED.count(".scan(")


def test_package_rejects_scan_and_updates_preexisting_function():
    try:
        PACKAGE.patched_handler(DEPLOYED, LOCAL.replace("table.query(", "table.scan("))
    except ValueError as error:
        assert "must not use DynamoDB Scan" in str(error)
    else:
        raise AssertionError("scan was accepted")

    updated = PACKAGE.patched_handler(DEPLOYED + LOCAL, LOCAL)
    assert updated.count("def delete_household_invitation") == 1
