#!/usr/bin/env python3
"""Create the Kaevo Plugin ZIP without filesystem-dependent metadata."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import stat
import zipfile
from pathlib import Path


ARCHIVE_FILES = ("Kaevo.Plugin.KaevoForJellyfin.dll", "meta.json")


def create_archive(plugin_dir: Path, output: Path) -> None:
    metadata = json.loads((plugin_dir / "meta.json").read_text(encoding="utf-8"))
    timestamp = dt.datetime.fromisoformat(metadata["timestamp"].replace("Z", "+00:00"))
    zip_timestamp = (
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second - (timestamp.second % 2),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in ARCHIVE_FILES:
            source = plugin_dir / name
            if not source.is_file():
                raise FileNotFoundError(f"required Plugin package file is missing: {name}")
            info = zipfile.ZipInfo(name, date_time=zip_timestamp)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, source.read_bytes())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("plugin_dir", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    create_archive(arguments.plugin_dir, arguments.output)


if __name__ == "__main__":
    main()
