from __future__ import annotations

import subprocess
import sys
from pathlib import Path
import zipfile


ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "build-deployed-lambda-source-package.py"


def test_package_changes_only_the_named_top_level_source(tmp_path):
    deployed = tmp_path / "deployed.zip"
    output = tmp_path / "candidate.zip"
    local = tmp_path / "claim_issuer.py"
    local.write_text("def lambda_handler():\n    return 'updated'\n")
    with zipfile.ZipFile(deployed, "w") as archive:
        archive.writestr("claim_issuer.py", "# old\n")
        archive.writestr("dependency.py", "# unchanged\n")

    subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--deployed-zip",
            str(deployed),
            "--source-name",
            "claim_issuer.py",
            "--local-source",
            str(local),
            "--output",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    with zipfile.ZipFile(output) as archive:
        assert archive.read("claim_issuer.py") == local.read_bytes()
        assert archive.read("dependency.py") == b"# unchanged\n"


def test_package_rejects_nested_source_name(tmp_path):
    deployed = tmp_path / "deployed.zip"
    output = tmp_path / "candidate.zip"
    local = tmp_path / "claim_issuer.py"
    local.write_text("# replacement\n")
    with zipfile.ZipFile(deployed, "w") as archive:
        archive.writestr("claim_issuer.py", "# old\n")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--deployed-zip",
            str(deployed),
            "--source-name",
            "nested/claim_issuer.py",
            "--local-source",
            str(local),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "top-level ZIP entry" in result.stderr
