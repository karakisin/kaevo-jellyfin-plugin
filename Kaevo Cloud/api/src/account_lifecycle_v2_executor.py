"""Idempotent phase executor for frozen Account Lifecycle V2 operations."""

from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence

from account_lifecycle_v2 import DeletionScope, LifecycleV2Error, OperationPhase


class LifecycleV2ExecutionError(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


EXECUTABLE_PHASES = frozenset({
    OperationPhase.QUEUED,
    OperationPhase.DELETING_SEERR,
    OperationPhase.VERIFYING_SEERR_ABSENCE,
    OperationPhase.DELETING_JELLYFIN,
    OperationPhase.VERIFYING_JELLYFIN_ABSENCE,
    OperationPhase.DELETING_COGNITO,
    OperationPhase.VERIFYING_COGNITO_ABSENCE,
    OperationPhase.DELETING_KAEVO_GRAPH,
    OperationPhase.VERIFYING_KAEVO_ABSENCE,
})


class OperationJournal(Protocol):
    def transition(
        self,
        operation: Mapping[str, Any],
        *,
        expected: OperationPhase,
        proposed: OperationPhase,
    ) -> dict[str, Any]: ...

    def record_retry(self, operation: Mapping[str, Any], *, reason: str) -> dict[str, Any]: ...
    def complete(self, operation: Mapping[str, Any], *, proof: Mapping[str, Any]) -> dict[str, Any]: ...


class ExactProviderDeletionV2(Protocol):
    def delete_seerr(self, *, operation_id: str, binding: Mapping[str, Any]) -> None: ...
    def seerr_absent(self, *, operation_id: str, binding: Mapping[str, Any]) -> bool: ...
    def delete_jellyfin(self, *, operation_id: str, binding: Mapping[str, Any]) -> None: ...
    def jellyfin_absent(self, *, operation_id: str, binding: Mapping[str, Any]) -> bool: ...


class CognitoDeletionV2(Protocol):
    def delete_identity(
        self,
        *,
        account_id: str,
        subject: str,
        auth_identity_key: str,
    ) -> None: ...

    def identity_and_email_absent(
        self,
        *,
        account_id: str,
        subject: str,
        auth_identity_key: str,
    ) -> bool: ...


class KaevoGraphDeletionV2(Protocol):
    def delete_resources(
        self,
        *,
        account_id: str,
        operation_id: str,
        resources: Sequence[Mapping[str, Any]],
    ) -> None: ...

    def resources_absent(
        self,
        *,
        account_id: str,
        operation_id: str,
        resources: Sequence[Mapping[str, Any]],
    ) -> bool: ...


def _resources(operation: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    values = operation.get("resource_snapshots")
    if not isinstance(values, list) or not values:
        raise LifecycleV2ExecutionError("frozen_resources_missing")
    result = []
    seen = set()
    for value in values:
        if not isinstance(value, Mapping):
            raise LifecycleV2ExecutionError("frozen_resource_invalid")
        key = str(value.get("resource_key") or "")
        if not key or key in seen:
            raise LifecycleV2ExecutionError("frozen_resource_invalid")
        seen.add(key)
        result.append(dict(value))
    return tuple(sorted(result, key=lambda item: item["resource_key"]))


def _provider_bindings(resources: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    result = []
    for resource in resources:
        if resource.get("resource_type") != "provider_binding":
            continue
        attributes = resource.get("attributes")
        if not isinstance(attributes, Mapping):
            raise LifecycleV2ExecutionError("provider_binding_snapshot_invalid")
        required = (
            "profile_id", "connector_id", "jellyfin_user_id",
            "two_way_profile_deletion",
        )
        if any(not str(attributes.get(key) or "") for key in required):
            raise LifecycleV2ExecutionError("provider_binding_snapshot_invalid")
        if str(attributes.get("two_way_profile_deletion") or "") != "enabled":
            raise LifecycleV2ExecutionError("provider_deletion_not_enabled")
        result.append(dict(resource))
    return tuple(result)


def _cognito_subject(resources: Sequence[Mapping[str, Any]]) -> str:
    subjects = {
        str(resource.get("resource_id") or "")
        for resource in resources
        if resource.get("resource_type") == "cognito_subject"
    }
    if len(subjects) != 1 or not next(iter(subjects)):
        raise LifecycleV2ExecutionError("cognito_subject_ambiguous")
    return next(iter(subjects))


def _auth_identity_key(resources: Sequence[Mapping[str, Any]]) -> str:
    keys = {
        str(resource.get("resource_id") or "")
        for resource in resources
        if resource.get("resource_type") == "auth_identity"
    }
    if len(keys) != 1 or not next(iter(keys)):
        raise LifecycleV2ExecutionError("auth_identity_ambiguous")
    return next(iter(keys))


class AccountLifecycleV2Executor:
    def __init__(
        self,
        *,
        journal: OperationJournal,
        providers: ExactProviderDeletionV2,
        cognito: CognitoDeletionV2,
        kaevo_graph: KaevoGraphDeletionV2,
    ):
        self.journal = journal
        self.providers = providers
        self.cognito = cognito
        self.kaevo_graph = kaevo_graph

    def execute(self, operation: Mapping[str, Any]) -> dict[str, Any]:
        current = dict(operation)
        try:
            resources = _resources(current)
            subject = _cognito_subject(resources)
            auth_identity_key = _auth_identity_key(resources)
            scope = DeletionScope(str(current.get("scope") or ""))
            bindings = _provider_bindings(resources) if scope is DeletionScope.EVERYTHING else ()
            operation_id = str(current.get("operation_id") or "")
            account_id = str(current.get("account_id") or "")
            if not operation_id or not account_id:
                raise LifecycleV2ExecutionError("operation_identity_invalid")

            try:
                phase = OperationPhase(str(current.get("phase") or ""))
            except ValueError as error:
                raise LifecycleV2ExecutionError("operation_not_executable") from error
            if phase is OperationPhase.RETRY_REQUIRED:
                try:
                    resume = OperationPhase(
                        str(current.get("resume_phase") or OperationPhase.QUEUED.value),
                    )
                except ValueError as error:
                    raise LifecycleV2ExecutionError("operation_resume_phase_invalid") from error
                if resume not in EXECUTABLE_PHASES:
                    raise LifecycleV2ExecutionError("operation_resume_phase_invalid")
                current = self.journal.transition(
                    current, expected=OperationPhase.RETRY_REQUIRED, proposed=resume,
                )
                phase = resume
            if phase not in EXECUTABLE_PHASES:
                raise LifecycleV2ExecutionError("operation_not_executable")

            while True:
                phase = OperationPhase(str(current.get("phase") or ""))
                if phase is OperationPhase.QUEUED:
                    current = self.journal.transition(
                        current,
                        expected=OperationPhase.QUEUED,
                        proposed=(
                            OperationPhase.DELETING_SEERR
                            if bindings else OperationPhase.DELETING_COGNITO
                        ),
                    )
                    continue

                if phase is OperationPhase.DELETING_SEERR:
                    if not bindings:
                        raise LifecycleV2ExecutionError("provider_phase_without_bindings")
                    for binding in bindings:
                        if str((binding.get("attributes") or {}).get("seerr_user_id") or ""):
                            self.providers.delete_seerr(
                                operation_id=operation_id, binding=binding,
                            )
                    current = self.journal.transition(
                        current, expected=OperationPhase.DELETING_SEERR,
                        proposed=OperationPhase.VERIFYING_SEERR_ABSENCE,
                    )
                    continue

                if phase is OperationPhase.VERIFYING_SEERR_ABSENCE:
                    if not bindings:
                        raise LifecycleV2ExecutionError("provider_phase_without_bindings")
                    if any(
                        str((binding.get("attributes") or {}).get("seerr_user_id") or "")
                        and not self.providers.seerr_absent(
                            operation_id=operation_id, binding=binding,
                        )
                        for binding in bindings
                    ):
                        raise LifecycleV2ExecutionError("seerr_absence_unconfirmed")
                    current = self.journal.transition(
                        current, expected=OperationPhase.VERIFYING_SEERR_ABSENCE,
                        proposed=OperationPhase.DELETING_JELLYFIN,
                    )
                    continue

                if phase is OperationPhase.DELETING_JELLYFIN:
                    if not bindings:
                        raise LifecycleV2ExecutionError("provider_phase_without_bindings")
                    for binding in bindings:
                        self.providers.delete_jellyfin(
                            operation_id=operation_id, binding=binding,
                        )
                    current = self.journal.transition(
                        current, expected=OperationPhase.DELETING_JELLYFIN,
                        proposed=OperationPhase.VERIFYING_JELLYFIN_ABSENCE,
                    )
                    continue

                if phase is OperationPhase.VERIFYING_JELLYFIN_ABSENCE:
                    if not bindings:
                        raise LifecycleV2ExecutionError("provider_phase_without_bindings")
                    if any(
                        not self.providers.jellyfin_absent(
                            operation_id=operation_id, binding=binding,
                        )
                        for binding in bindings
                    ):
                        raise LifecycleV2ExecutionError("jellyfin_absence_unconfirmed")
                    current = self.journal.transition(
                        current, expected=OperationPhase.VERIFYING_JELLYFIN_ABSENCE,
                        proposed=OperationPhase.DELETING_COGNITO,
                    )
                    continue

                if phase is OperationPhase.DELETING_COGNITO:
                    self.cognito.delete_identity(
                        account_id=account_id,
                        subject=subject,
                        auth_identity_key=auth_identity_key,
                    )
                    current = self.journal.transition(
                        current, expected=OperationPhase.DELETING_COGNITO,
                        proposed=OperationPhase.VERIFYING_COGNITO_ABSENCE,
                    )
                    continue

                if phase is OperationPhase.VERIFYING_COGNITO_ABSENCE:
                    if not self.cognito.identity_and_email_absent(
                        account_id=account_id,
                        subject=subject,
                        auth_identity_key=auth_identity_key,
                    ):
                        raise LifecycleV2ExecutionError("cognito_absence_unconfirmed")
                    current = self.journal.transition(
                        current, expected=OperationPhase.VERIFYING_COGNITO_ABSENCE,
                        proposed=OperationPhase.DELETING_KAEVO_GRAPH,
                    )
                    continue

                if phase is OperationPhase.DELETING_KAEVO_GRAPH:
                    self.kaevo_graph.delete_resources(
                        account_id=account_id,
                        operation_id=operation_id,
                        resources=resources,
                    )
                    current = self.journal.transition(
                        current, expected=OperationPhase.DELETING_KAEVO_GRAPH,
                        proposed=OperationPhase.VERIFYING_KAEVO_ABSENCE,
                    )
                    continue

                if phase is OperationPhase.VERIFYING_KAEVO_ABSENCE:
                    if not self.kaevo_graph.resources_absent(
                        account_id=account_id,
                        operation_id=operation_id,
                        resources=resources,
                    ):
                        raise LifecycleV2ExecutionError("kaevo_absence_unconfirmed")
                    proof = {
                        "cognito_identity_absent": True,
                        "cognito_email_absent": True,
                        "kaevo_graph_absent": True,
                        "jellyfin_identity_absent": (
                            True if scope is DeletionScope.EVERYTHING else None
                        ),
                        "seerr_identity_absent": (
                            True if scope is DeletionScope.EVERYTHING else None
                        ),
                    }
                    return self.journal.complete(current, proof=proof)

                raise LifecycleV2ExecutionError("operation_not_executable")
        except (LifecycleV2ExecutionError, LifecycleV2Error, ValueError) as error:
            reason = getattr(error, "reason", "operation_invalid")
            return self.journal.record_retry(current, reason=str(reason))
        except Exception:
            return self.journal.record_retry(current, reason="dependency_failure")
