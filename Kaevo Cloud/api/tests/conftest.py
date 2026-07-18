from __future__ import annotations

import pathlib
import sys

import pytest


SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))


@pytest.fixture(autouse=True)
def audit_reference_test_environment(monkeypatch):
    import security_audit

    monkeypatch.setenv("KAEVO_ENV", "test")
    monkeypatch.setenv("EXPECTED_COGNITO_ISSUER", "https://issuer.example/pool")
    monkeypatch.setenv("AUDIT_REFERENCE_SECRET_ARN", "test-audit-secret")
    security_audit.clear_audit_key_cache()
    security_audit._secret_cache["test-audit-secret"] = b"K" * 64
    yield
    security_audit.clear_audit_key_cache()
