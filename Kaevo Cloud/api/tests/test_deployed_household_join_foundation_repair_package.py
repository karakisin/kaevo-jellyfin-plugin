from __future__ import annotations

import subprocess
import sys
from pathlib import Path
import zipfile


ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "build-deployed-household-join-foundation-repair.py"


def test_repair_changes_only_account_foundation(tmp_path):
    deployed = tmp_path / "deployed.zip"
    output = tmp_path / "candidate.zip"
    local = tmp_path / "account_foundation.py"
    local.write_text("def household_access_role():\n    return 'member'\n")
    with zipfile.ZipFile(deployed, "w") as archive:
        archive.writestr("account_foundation.py", "# old\n")
        archive.writestr("household_join_handler.py", "# unchanged\n")

    subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--deployed-zip",
            str(deployed),
            "--local-account-foundation",
            str(local),
            "--output",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    with zipfile.ZipFile(output) as archive:
        assert archive.read("account_foundation.py") == local.read_bytes()
        assert archive.read("household_join_handler.py") == b"# unchanged\n"
