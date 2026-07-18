from __future__ import annotations

import json
import os

import pytest

from kaevo_home_server.connector_lifecycle import ConnectorLifecycleStore
from kaevo_home_server.connector_identity import ConnectorIdentity


def test_server_id_and_recovery_key_are_stable_and_private(tmp_path):
    store = ConnectorLifecycleStore(tmp_path / "state", environment="security-stage")
    first = store.load_or_initialize()
    second = store.load_or_initialize()
    assert first.server_id == second.server_id
    assert first.server_id.startswith("srv_")
    assert (os.stat(store.state_path).st_mode & 0o777) == 0o600
    recovery = store.directory / first.recovery_key_file
    assert recovery.exists() and (os.stat(recovery).st_mode & 0o777) == 0o600


def test_failed_rotation_retains_current_key(tmp_path):
    store = ConnectorLifecycleStore(tmp_path / "state", environment="security-stage")
    store.load_or_initialize()
    pending, _ = store.begin_key_transition("pair")
    active = store.commit_transition(connector_id="connector-1", credential_version=1)
    current = (store.directory / active.current_key_file).read_bytes()
    store.begin_key_transition("rotate")
    restored = store.abort_transition()
    assert restored.credential_version == 1
    assert (store.directory / restored.current_key_file).read_bytes() == current
    assert not restored.pending_key_file


def test_successful_rotation_activates_new_version_and_removes_old_key(tmp_path):
    store = ConnectorLifecycleStore(tmp_path / "state", environment="security-stage")
    store.load_or_initialize()
    store.begin_key_transition("pair")
    first = store.commit_transition(connector_id="connector-1", credential_version=1)
    old_path = store.directory / first.current_key_file
    store.begin_key_transition("rotate")
    second = store.commit_transition(connector_id="connector-1", credential_version=2)
    assert second.credential_version == 2
    assert not old_path.exists()
    assert (store.directory / second.current_key_file).exists()


def test_restart_preserves_pending_transition_for_explicit_recovery(tmp_path):
    directory = tmp_path / "state"
    store = ConnectorLifecycleStore(directory, environment="security-stage")
    store.load_or_initialize()
    pending, identity = store.begin_key_transition("pair")
    restarted = ConnectorLifecycleStore(directory, environment="security-stage")
    loaded = restarted.load_or_initialize()
    assert loaded.pending_key_file == pending.pending_key_file
    assert restarted.directory.joinpath(loaded.pending_key_file).exists()
    assert identity.thumbprint == ConnectorIdentity.load_or_create(
        restarted.directory / loaded.pending_key_file
    ).thumbprint


def test_environment_cannot_be_changed_after_initialization(tmp_path):
    directory = tmp_path / "state"
    ConnectorLifecycleStore(directory, environment="security-stage").load_or_initialize()
    with pytest.raises(ValueError, match="connectorLifecycleEnvironmentMismatch"):
        ConnectorLifecycleStore(directory, environment="production").load_or_initialize()


def test_state_file_contains_no_private_key_material(tmp_path):
    store = ConnectorLifecycleStore(tmp_path / "state", environment="security-stage")
    store.load_or_initialize()
    store.begin_key_transition("pair")
    text = store.state_path.read_text()
    assert "PRIVATE KEY" not in text
    assert set(json.loads(text)) == {
        "environment", "server_id", "connector_id", "credential_version", "current_key_file",
        "recovery_key_file", "pending_key_file", "pending_operation",
    }
