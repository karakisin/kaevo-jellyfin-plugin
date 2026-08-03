"""Private fixture-root checks used before an AWS session is opened."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import FixtureSafetyError


def validate_fixture_root(root: str | Path) -> Path:
    """Require the already-provisioned private root without creating it."""
    path = Path(root)
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError as error:
            raise FixtureSafetyError("FIXTURE_ROOT_MISSING") from error
        if stat.S_ISLNK(info.st_mode):
            raise FixtureSafetyError("FIXTURE_ROOT_SYMLINK")
    info = os.stat(path)
    if not stat.S_ISDIR(info.st_mode):
        raise FixtureSafetyError("FIXTURE_ROOT_NOT_DIRECTORY")
    if info.st_uid != os.getuid():
        raise FixtureSafetyError("FIXTURE_ROOT_OWNER_MISMATCH")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise FixtureSafetyError("FIXTURE_ROOT_MODE_MISMATCH")
    if not os.access(path, os.W_OK | os.X_OK):
        raise FixtureSafetyError("FIXTURE_ROOT_NOT_WRITABLE")
    return path
