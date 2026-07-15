from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path


os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

HANDLER_PATH = Path(__file__).resolve().parents[1] / "src" / "handler.py"
SPEC = importlib.util.spec_from_file_location("kaevo_cloud_response_handler", HANDLER_PATH)
assert SPEC is not None and SPEC.loader is not None
handler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handler)


def test_large_remote_response_round_trips_through_compressed_storage():
    payload = {
        "Items": [
            {
                "Id": f"{index:032x}",
                "Name": f"Movie {index}",
                "Overview": "A bounded metadata description. " * 100,
            }
            for index in range(150)
        ]
    }
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    assert len(encoded) > handler.REMOTE_RESPONSE_COMPRESS_THRESHOLD_BYTES

    import base64
    import gzip

    item = {
        "response_gzip_base64": base64.b64encode(gzip.compress(encoded, compresslevel=6)).decode("ascii")
    }
    assert handler.decode_remote_response_payload(item, {}) == payload


def test_plain_remote_response_remains_compatible():
    payload = {"state": "ok", "Items": []}
    item = {"response_json": json.dumps(payload, separators=(",", ":"))}
    assert handler.decode_remote_response_payload(item, {}) == payload
