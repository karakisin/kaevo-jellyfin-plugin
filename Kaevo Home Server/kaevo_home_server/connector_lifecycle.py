from __future__ import annotations

import json
import os
import secrets
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from .connector_identity import ConnectorIdentity


@dataclass(frozen=True)
class ConnectorLifecycleState:
    environment: str
    server_id: str
    connector_id: str = ""
    credential_version: int = 0
    current_key_file: str = ""
    recovery_key_file: str = "recovery-key.pem"
    pending_key_file: str = ""
    pending_operation: str = ""


class ConnectorLifecycleStore:
    """Crash-safe local connector identity metadata and versioned P-256 keys."""

    def __init__(self, directory: str | Path, *, environment: str):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.environment = environment
        self.state_path = self.directory / "connector-state.json"

    def _write_state(self, state: ConnectorLifecycleState) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=".connector-state-", dir=self.directory)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                json.dump(asdict(state), stream, separators=(",", ":"), sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.state_path)
            os.chmod(self.state_path, 0o600)
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    def load_or_initialize(self) -> ConnectorLifecycleState:
        if self.state_path.exists():
            data = json.loads(self.state_path.read_text())
            state = ConnectorLifecycleState(**data)
            if state.environment != self.environment or not state.server_id.startswith("srv_"):
                raise ValueError("connectorLifecycleEnvironmentMismatch")
            os.chmod(self.state_path, 0o600)
            return state
        state = ConnectorLifecycleState(
            environment=self.environment,
            server_id="srv_" + secrets.token_urlsafe(32),
        )
        self._write_state(state)
        ConnectorIdentity.load_or_create(self.directory / state.recovery_key_file)
        return state

    def recovery_identity(self) -> ConnectorIdentity:
        state = self.load_or_initialize()
        return ConnectorIdentity.load_or_create(self.directory / state.recovery_key_file)

    def begin_key_transition(self, operation: str) -> tuple[ConnectorLifecycleState, ConnectorIdentity]:
        if operation not in {"pair", "rotate", "recover"}:
            raise ValueError("connectorLifecycleOperationInvalid")
        state = self.load_or_initialize()
        if state.pending_key_file:
            raise RuntimeError("connectorLifecycleTransitionPending")
        target_version = state.credential_version + 1
        pending_name = f"connector-key-v{target_version}.pending.pem"
        identity = ConnectorIdentity.load_or_create(self.directory / pending_name)
        pending = ConnectorLifecycleState(
            **{**asdict(state), "pending_key_file": pending_name, "pending_operation": operation}
        )
        self._write_state(pending)
        return pending, identity

    def commit_transition(self, *, connector_id: str, credential_version: int) -> ConnectorLifecycleState:
        state = self.load_or_initialize()
        if not state.pending_key_file or credential_version != state.credential_version + 1:
            raise RuntimeError("connectorLifecycleVersionInvalid")
        pending_path = self.directory / state.pending_key_file
        final_name = f"connector-key-v{credential_version}.pem"
        final_path = self.directory / final_name
        os.replace(pending_path, final_path)
        os.chmod(final_path, 0o600)
        committed = ConnectorLifecycleState(
            environment=state.environment, server_id=state.server_id,
            connector_id=connector_id, credential_version=credential_version,
            current_key_file=final_name, recovery_key_file=state.recovery_key_file,
        )
        self._write_state(committed)
        if state.current_key_file and state.current_key_file != final_name:
            old_path = self.directory / state.current_key_file
            if old_path.exists():
                old_path.write_bytes(b"\0" * old_path.stat().st_size)
                old_path.unlink()
        return committed

    def abort_transition(self) -> ConnectorLifecycleState:
        state = self.load_or_initialize()
        if state.pending_key_file:
            pending = self.directory / state.pending_key_file
            if pending.exists():
                pending.write_bytes(b"\0" * pending.stat().st_size)
                pending.unlink()
        restored = ConnectorLifecycleState(
            **{**asdict(state), "pending_key_file": "", "pending_operation": ""}
        )
        self._write_state(restored)
        return restored

    def current_identity(self) -> ConnectorIdentity:
        state = self.load_or_initialize()
        if not state.current_key_file:
            raise RuntimeError("connectorLifecycleNotPaired")
        return ConnectorIdentity.load_or_create(self.directory / state.current_key_file)
