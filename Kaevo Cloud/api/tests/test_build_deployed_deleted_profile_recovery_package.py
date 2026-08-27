import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[2] / "scripts" / "build-deployed-deleted-profile-recovery-package.py"
SPEC = importlib.util.spec_from_file_location("deleted_profile_recovery_package", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def function(name: str, body: str = "return None") -> str:
    indented = "\n".join(f"    {line}" for line in body.splitlines())
    return f"def {name}():\n{indented}\n"


def deployed_source() -> str:
    names = [
        "_retain_deleted_profile_binding_tombstone",
        "create_household_invitation",
        "save_profile_jellyfin_binding_v3",
        "save_profile_seerr_binding_v3",
        "preflight_profile_jellyfin_binding_v3",
    ]
    return "\n".join(function(name) for name in names)


def local_source() -> str:
    names = [
        "_deleted_profile_recovery_tombstone",
        "_retain_deleted_profile_binding_tombstone",
        "create_household_invitation",
        "save_profile_jellyfin_binding_v3",
        "save_profile_seerr_binding_v3",
        "preflight_profile_jellyfin_binding_v3",
    ]
    return "\n".join(function(name, f"return {index}") for index, name in enumerate(names))


def test_patches_only_exact_recovery_functions():
    deployed = deployed_source()
    local = local_source()
    patched = MODULE.patched_handler(deployed, local)
    deployed_spans = MODULE.function_spans(deployed)
    local_spans = MODULE.function_spans(local)
    patched_spans = MODULE.function_spans(patched)

    for name in MODULE.INSERT_FUNCTIONS + MODULE.REPLACE_FUNCTIONS:
        assert patched_spans[name][2].strip() == local_spans[name][2].strip()
    assert (
        patched_spans[MODULE.INSERT_BEFORE][2].strip()
        == deployed_spans[MODULE.INSERT_BEFORE][2].strip()
    )


def test_refuses_package_that_already_contains_recovery_helper():
    deployed = deployed_source() + "\n" + function("_deleted_profile_recovery_tombstone")
    with pytest.raises(ValueError, match="already contains"):
        MODULE.patched_handler(deployed, local_source())


def test_refuses_scan_delta():
    local = local_source().replace(
        "def create_household_invitation():\n    return 2",
        "def create_household_invitation():\n    table.scan()\n    return 2",
    )
    with pytest.raises(ValueError, match="DynamoDB Scan"):
        MODULE.patched_handler(deployed_source(), local)
