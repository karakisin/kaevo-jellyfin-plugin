from copy import deepcopy

from account_lifecycle_v2 import OperationPhase, require_phase_transition
from account_lifecycle_v2_executor import AccountLifecycleV2Executor


ACCOUNT_ID = "acct_0123456789abcdef01234567"
OPERATION_ID = "ald2_0123456789abcdef0123456789abcdef"


def resource(kind, identifier, attributes=None):
    return {
        "resource_key": f"resource#{kind}#{identifier}",
        "resource_type": kind,
        "resource_id": identifier,
        "state": "active",
        "attributes": dict(attributes or {}),
    }


def operation(scope="everything", phase="queued", providers=True):
    resources = [
        resource("account", ACCOUNT_ID),
        resource("auth_identity", "cognito#opaque-subject-123"),
        resource("cognito_subject", "opaque-subject-123"),
        resource("cloud_profile", "profile_0123456789abcdef"),
    ]
    if providers:
        resources.append(resource("provider_binding", "provider-binding-1", {
            "profile_id": "profile_0123456789abcdef",
            "connector_id": "connector-1",
            "jellyfin_user_id": "jellyfin-user-1",
            "seerr_user_id": "42",
            "two_way_profile_deletion": "enabled",
        }))
    return {
        "account_id": ACCOUNT_ID,
        "record_key": f"operation#{OPERATION_ID}",
        "record_type": "account_lifecycle_operation",
        "operation_id": OPERATION_ID,
        "scope": scope,
        "phase": phase,
        "resource_snapshots": resources,
    }


class Journal:
    def __init__(self, trace):
        self.trace = trace

    def transition(self, current, *, expected, proposed):
        assert current["phase"] == expected.value
        require_phase_transition(expected.value, proposed.value)
        self.trace.append(f"phase:{proposed.value}")
        result = {**current, "phase": proposed.value}
        result.pop("resume_phase", None)
        result.pop("failure_reason", None)
        return result

    def record_retry(self, current, *, reason):
        self.trace.append(f"retry:{reason}")
        return {
            **current,
            "phase": "retry_required",
            "resume_phase": current.get("resume_phase") or current["phase"],
            "retryable": True,
            "reason": reason,
        }

    def complete(self, current, *, proof):
        assert current["phase"] == OperationPhase.VERIFYING_KAEVO_ABSENCE.value
        self.trace.append("phase:completed")
        return {**current, "phase": "completed", "retryable": False, "proof": dict(proof)}


class Providers:
    def __init__(self, trace, *, seerr_absent=True, jellyfin_absent=True):
        self.trace = trace
        self.is_seerr_absent = seerr_absent
        self.is_jellyfin_absent = jellyfin_absent

    def delete_seerr(self, **_kwargs):
        self.trace.append("provider:delete-seerr")

    def seerr_absent(self, **_kwargs):
        self.trace.append("provider:verify-seerr")
        return self.is_seerr_absent

    def delete_jellyfin(self, **_kwargs):
        self.trace.append("provider:delete-jellyfin")

    def jellyfin_absent(self, **_kwargs):
        self.trace.append("provider:verify-jellyfin")
        return self.is_jellyfin_absent


class Cognito:
    def __init__(self, trace, *, absent=True):
        self.trace = trace
        self.absent = absent

    def delete_identity(self, *, account_id, subject, auth_identity_key):
        assert account_id == ACCOUNT_ID
        assert subject == "opaque-subject-123"
        assert auth_identity_key == "cognito#opaque-subject-123"
        self.trace.append("cognito:delete")

    def identity_and_email_absent(self, *, account_id, subject, auth_identity_key):
        assert account_id == ACCOUNT_ID
        assert subject == "opaque-subject-123"
        assert auth_identity_key == "cognito#opaque-subject-123"
        self.trace.append("cognito:verify")
        return self.absent


class KaevoGraph:
    def __init__(self, trace, *, absent=True):
        self.trace = trace
        self.absent = absent

    def delete_resources(self, *, account_id, operation_id, resources):
        assert account_id == ACCOUNT_ID and operation_id == OPERATION_ID and resources
        self.trace.append("kaevo:delete")

    def resources_absent(self, *, account_id, operation_id, resources):
        assert account_id == ACCOUNT_ID and operation_id == OPERATION_ID and resources
        self.trace.append("kaevo:verify")
        return self.absent


def executor(trace, *, providers=None, cognito=None, graph=None):
    return AccountLifecycleV2Executor(
        journal=Journal(trace),
        providers=providers or Providers(trace),
        cognito=cognito or Cognito(trace),
        kaevo_graph=graph or KaevoGraph(trace),
    )


def test_everything_deletes_seerr_then_jellyfin_then_cognito_then_kaevo():
    trace = []
    result = executor(trace).execute(operation())

    assert result["phase"] == "completed"
    assert result["proof"] == {
        "cognito_identity_absent": True,
        "cognito_email_absent": True,
        "kaevo_graph_absent": True,
        "jellyfin_identity_absent": True,
        "seerr_identity_absent": True,
    }
    assert trace.index("provider:verify-seerr") < trace.index("provider:delete-jellyfin")
    assert trace.index("provider:verify-jellyfin") < trace.index("cognito:delete")
    assert trace.index("cognito:verify") < trace.index("kaevo:delete")
    assert trace[-1] == "phase:completed"


def test_kaevo_only_never_calls_provider_deletion():
    trace = []
    result = executor(trace).execute(operation(scope="kaevo_only"))

    assert result["phase"] == "completed"
    assert not any(item.startswith("provider:") for item in trace)
    assert result["proof"]["jellyfin_identity_absent"] is None
    assert result["proof"]["seerr_identity_absent"] is None


def test_everything_without_provider_accounts_skips_provider_and_still_completes():
    trace = []
    result = executor(trace).execute(operation(providers=False))

    assert result["phase"] == "completed"
    assert not any(item.startswith("provider:") for item in trace)
    assert result["proof"]["jellyfin_identity_absent"] is True
    assert result["proof"]["seerr_identity_absent"] is True


def test_unconfirmed_seerr_absence_stops_before_jellyfin_cognito_and_kaevo():
    trace = []
    result = executor(
        trace, providers=Providers(trace, seerr_absent=False),
    ).execute(operation())

    assert result["phase"] == "retry_required"
    assert result["reason"] == "seerr_absence_unconfirmed"
    assert "provider:delete-jellyfin" not in trace
    assert "cognito:delete" not in trace
    assert "kaevo:delete" not in trace


def test_unconfirmed_cognito_absence_preserves_kaevo_graph_for_retry():
    trace = []
    result = executor(
        trace, cognito=Cognito(trace, absent=False),
    ).execute(operation(scope="kaevo_only"))

    assert result["phase"] == "retry_required"
    assert result["reason"] == "cognito_absence_unconfirmed"
    assert "kaevo:delete" not in trace


def test_retry_required_resumes_same_operation_without_rebuilding_plan():
    trace = []
    retry = operation(scope="kaevo_only", phase="retry_required")
    original_resources = deepcopy(retry["resource_snapshots"])
    result = executor(trace).execute(retry)

    assert result["phase"] == "completed"
    assert result["operation_id"] == OPERATION_ID
    assert result["resource_snapshots"] == original_resources
    assert trace[0] == "phase:queued"


def test_retry_required_resumes_saved_graph_phase_without_repeating_cognito():
    trace = []
    retry = {
        **operation(scope="kaevo_only", phase="retry_required"),
        "resume_phase": "deleting_kaevo_graph",
    }

    result = executor(trace).execute(retry)

    assert result["phase"] == "completed"
    assert trace[0] == "phase:deleting_kaevo_graph"
    assert "cognito:delete" not in trace
    assert "cognito:verify" not in trace
    assert "kaevo:delete" in trace
    assert "kaevo:verify" in trace


def test_abrupt_worker_restart_resumes_durable_graph_phase_without_cognito_evidence():
    trace = []

    result = executor(trace).execute(
        operation(scope="kaevo_only", phase="deleting_kaevo_graph"),
    )

    assert result["phase"] == "completed"
    assert "cognito:delete" not in trace
    assert "cognito:verify" not in trace
    assert trace[0] == "kaevo:delete"
