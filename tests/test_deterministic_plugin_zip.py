from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "create-deterministic-plugin-zip.py"
SPEC = importlib.util.spec_from_file_location("deterministic_plugin_zip", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class DeterministicPluginZipTests(unittest.TestCase):
    def test_creation_order_and_permissions_do_not_change_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / "first", root / "second"
            first.mkdir()
            second.mkdir()
            metadata = b'{"timestamp":"2026-07-18T21:51:05Z"}\n'
            assembly = b"deterministic-assembly"
            (first / "meta.json").write_bytes(metadata)
            (first / "Kaevo.Plugin.KaevoForJellyfin.dll").write_bytes(assembly)
            (second / "Kaevo.Plugin.KaevoForJellyfin.dll").write_bytes(assembly)
            (second / "meta.json").write_bytes(metadata)
            os.chmod(first / "meta.json", 0o600)
            os.chmod(first / "Kaevo.Plugin.KaevoForJellyfin.dll", 0o700)
            os.chmod(second / "meta.json", 0o644)
            os.chmod(second / "Kaevo.Plugin.KaevoForJellyfin.dll", 0o644)
            first_zip, second_zip = root / "first.zip", root / "second.zip"
            MODULE.create_archive(first, first_zip)
            MODULE.create_archive(second, second_zip)
            self.assertEqual(first_zip.read_bytes(), second_zip.read_bytes())


if __name__ == "__main__":
    unittest.main()
