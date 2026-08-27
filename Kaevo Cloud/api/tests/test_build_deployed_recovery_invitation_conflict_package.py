import importlib.util
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).parents[2]
    / "scripts"
    / "build-deployed-recovery-invitation-conflict-package.py"
)
SPEC = importlib.util.spec_from_file_location("recovery_invitation_conflict_package", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def source(predicate: str) -> str:
    return f'''def create_household_invitation():
    return not any(
        isinstance(candidate, dict)
{predicate}    )
'''


def test_patches_only_exact_recovery_invitation_predicate():
    deployed = source(MODULE.OLD_PREDICATE)
    patched = MODULE.patched_handler(deployed)

    assert MODULE.OLD_PREDICATE not in patched
    assert patched.count(MODULE.NEW_PREDICATE) == 1


def test_refuses_an_already_corrected_package():
    with pytest.raises(ValueError, match="already contains"):
        MODULE.patched_handler(source(MODULE.NEW_PREDICATE))


def test_refuses_an_ambiguous_predicate_anchor():
    deployed = source(MODULE.OLD_PREDICATE) + source(MODULE.OLD_PREDICATE)
    with pytest.raises(ValueError, match="exactly one"):
        MODULE.patched_handler(deployed)
