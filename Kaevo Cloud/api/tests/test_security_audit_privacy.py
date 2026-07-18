from __future__ import annotations

import json
import os
import pathlib
import sys
from types import SimpleNamespace

import pytest
from boto3.dynamodb.types import TypeSerializer

os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

import security_audit
from security_audit import (
    AuditReferenceError,
    fallback_audit_item,
    load_audit_key,
    prepare_audit_item,
    principal_ref,
    scoped_ref,
)


KEY_A = b"A" * 64
KEY_B = b"B" * 64
RAW = {
    "subject": "00000000-cognito-subject-canary",
    "household": "hh_private_household_canary",
    "profile": "profile_private_canary",
    "installation": "install_private_canary",
    "request": "request_private_canary",
}


@pytest.fixture(autouse=True)
def environment(monkeypatch):
    monkeypatch.setenv("KAEVO_ENV", "staging")
    monkeypatch.setenv("EXPECTED_COGNITO_ISSUER", "https://issuer.example/staging")
    monkeypatch.setenv("AUDIT_REFERENCE_SECRET_ARN", "arn:aws:secretsmanager:test:audit")
    security_audit.clear_audit_key_cache()


def item(**changes):
    values = {
        "scope_id": RAW["household"],
        "event_type": "installation_registered",
        "actor_subject": RAW["subject"],
        "target_id": RAW["installation"],
        "target_type": "installation",
        "request_id": RAW["request"],
        "now": 1_000,
        "key": KEY_A,
    }
    values.update(changes)
    return prepare_audit_item(**values)


def test_principal_reference_is_deterministic_and_versioned():
    first = principal_ref(RAW["subject"], key=KEY_A)
    assert first == principal_ref(RAW["subject"], key=KEY_A)
    assert first.startswith("apr1_") and len(first.removeprefix("apr1_")) >= 43


def test_different_subjects_do_not_collide():
    assert principal_ref("subject-a", key=KEY_A) != principal_ref("subject-b", key=KEY_A)


def test_environment_specific_keys_prevent_cross_environment_correlation():
    assert principal_ref(RAW["subject"], key=KEY_A) != principal_ref(RAW["subject"], key=KEY_B)


def test_issuer_is_part_of_canonical_actor_input():
    assert principal_ref(RAW["subject"], key=KEY_A, issuer="issuer-a") != principal_ref(
        RAW["subject"], key=KEY_A, issuer="issuer-b"
    )


def test_scope_and_target_references_use_domain_separation():
    household = scoped_ref("household", "same", key=KEY_A)
    profile = scoped_ref("profile", "same", key=KEY_A)
    assert household.startswith("asr1_") and household != profile


def test_record_has_only_versioned_minimized_schema():
    audit = item()
    assert audit["audit_schema_version"] == 1
    assert audit["household_id"] == audit["scope_ref"]
    assert set(audit) == {
        "household_id", "scope_ref", "audit_schema_version", "event_id", "event_type",
        "actor_ref", "actor_type", "result", "request_correlation_ref", "occurred_at",
        "created_at", "expires_at", "target_ref", "target_type",
    }


def test_raw_identifiers_are_absent_from_serialized_record():
    serialized = json.dumps(item(), sort_keys=True)
    assert all(value not in serialized for value in RAW.values())
    assert "subject_hash" not in serialized and "details_json" not in serialized


def test_dynamodb_wire_serialization_contains_no_raw_identifiers():
    serializer = TypeSerializer()
    wire = {key: serializer.serialize(value) for key, value in item().items()}
    encoded = json.dumps(wire, sort_keys=True)
    assert all(value not in encoded for value in RAW.values())


def test_client_cannot_override_derived_references():
    attacker = "apr1_attacker_controlled"
    with pytest.raises(TypeError):
        item(actor_ref=attacker)
    assert item()["actor_ref"] != attacker


def test_audit_reference_is_not_the_raw_principal_lookup_key():
    ref = principal_ref(RAW["subject"], key=KEY_A)
    assert ref != RAW["subject"] and not ref.startswith("00000000-")


def test_missing_secret_configuration_fails_closed(monkeypatch):
    monkeypatch.delenv("AUDIT_REFERENCE_SECRET_ARN")
    with pytest.raises(AuditReferenceError, match="audit_configuration_unavailable"):
        load_audit_key()


def test_short_secret_is_rejected():
    class Client:
        def get_secret_value(self, **_kwargs):
            return {"SecretString": "too-short"}
    with pytest.raises(AuditReferenceError, match="audit_key_unavailable"):
        load_audit_key(client=Client())


def test_secret_manager_value_is_cached_without_logging_secret():
    class Client:
        calls = 0
        def get_secret_value(self, **_kwargs):
            self.calls += 1
            return {"SecretString": "C" * 64}
    client = Client()
    assert load_audit_key(client=client) == b"C" * 64
    assert load_audit_key(client=client) == b"C" * 64
    assert client.calls == 1


def test_json_secret_format_is_supported_without_storing_metadata():
    class Client:
        def get_secret_value(self, **_kwargs):
            return {"SecretString": json.dumps({"audit_reference_key": "D" * 64, "note": RAW["subject"]})}
    assert load_audit_key(client=Client()) == b"D" * 64


def test_fallback_record_is_non_correlatable_and_contains_no_raw_identifier():
    audit = fallback_audit_item(
        event_type="refresh_reuse_detected", result="denied",
        reason_code="audit_key_unavailable", now=1_000,
    )
    serialized = json.dumps(audit, sort_keys=True)
    assert audit["actor_ref"] == "apr0_unavailable"
    assert audit["scope_ref"] == "asr0_unavailable"
    assert all(value not in serialized for value in RAW.values())


def test_reason_codes_reject_identifier_shaped_or_untrusted_detail():
    audit = item(result="denied", reason_code="raw identifier with spaces")
    assert audit["reason_code"] == "security_policy_denied"


def test_request_correlation_is_pseudonymous_and_deterministic_per_key():
    first = item()["request_correlation_ref"]
    second = item()["request_correlation_ref"]
    assert first == second and RAW["request"] not in first


def test_role_change_event_uses_same_privacy_schema():
    audit = item(event_type="role_changed", target_id=RAW["profile"], target_type="profile")
    assert audit["event_type"] == "role_changed" and RAW["profile"] not in json.dumps(audit)


def test_cross_household_denial_uses_same_privacy_schema():
    audit = item(event_type="cross_household_denied", result="denied", reason_code="target_not_found")
    assert audit["result"] == "denied" and audit["reason_code"] == "target_not_found"


def test_dpop_replay_and_refresh_reuse_events_do_not_retain_session_material():
    for event_type, reason in (("dpop_proof_denied", "dpop_replay"), ("refresh_reuse_detected", "refresh_token_reuse")):
        audit = item(event_type=event_type, result="denied", reason_code=reason)
        encoded = json.dumps(audit)
        assert "raw-refresh-token-canary" not in encoded
        assert "raw-session-family-canary" not in encoded
        assert RAW["installation"] not in encoded


def test_expiry_remains_exactly_400_days():
    assert item()["expires_at"] == 1_000 + (400 * 24 * 60 * 60)


def test_privileged_installation_mutation_fails_closed_before_write(monkeypatch):
    import handler

    class Installations:
        writes = []
        def put_item(self, **kwargs):
            self.writes.append(kwargs)

    table = Installations()
    identity = SimpleNamespace(
        subject=RAW["subject"], account_id="account-private",
        household_id=RAW["household"], profile_id=RAW["profile"],
    )
    monkeypatch.setattr(handler, "installations_table", table)
    monkeypatch.setattr(handler, "authoritative_identity", lambda *_args: (identity, {}))
    monkeypatch.setattr(handler, "validate_public_jwk", lambda _value: {"kty": "EC"})
    monkeypatch.setattr(handler, "jwk_thumbprint", lambda _value: "thumbprint")
    monkeypatch.setattr(handler, "verify_dpop", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        handler, "prepare_security_audit",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AuditReferenceError("audit_key_unavailable")),
    )
    event = {
        "body": json.dumps({
            "installation_id": "install-1", "device_id": "device-1", "public_jwk": {},
        }),
        "headers": {"dpop": "proof"},
        "requestContext": {"requestId": "request-1", "http": {"method": "POST"}},
        "rawPath": "/v2/installations",
    }
    response = handler.register_installation_v2(event)
    assert response["statusCode"] == 503
    assert json.loads(response["body"]) == {"state": "temporarily_unavailable"}
    assert table.writes == []


def test_iac_grants_exact_secret_read_to_only_two_audit_writers():
    template = (pathlib.Path(__file__).resolve().parents[2] / "infra" / "template.yaml").read_text()
    assert template.count("secretsmanager:GetSecretValue") == 2
    assert template.count("AUDIT_REFERENCE_SECRET_ARN: !Ref KaevoAuditReferenceSecret") == 2
    assert "DynamoDBCrudPolicy:\n            TableName: !Ref KaevoSecurityAuditTable" not in template
    assert "secretsmanager:PutSecretValue" not in template
    assert "secretsmanager:DeleteSecret" not in template
    outputs = template.split("Outputs:", 1)[1]
    assert "KaevoAuditReferenceSecret" not in outputs
