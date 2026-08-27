"""AWS adapters for Account Lifecycle V2 execution."""

from __future__ import annotations

import hmac
import time
from typing import Any, Mapping, Sequence

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

from account_foundation import normalized_email, provider_subject_key
from account_lifecycle_v2 import OperationPhase, require_phase_transition
from account_lifecycle_v2_executor import LifecycleV2ExecutionError


class DynamoOperationJournal:
    def __init__(self, table: Any, *, clock):
        self.table = table
        self.clock = clock

    @staticmethod
    def _key(operation: Mapping[str, Any]) -> dict[str, str]:
        return {
            "account_id": str(operation.get("account_id") or ""),
            "record_key": str(operation.get("record_key") or ""),
        }

    def transition(self, operation, *, expected, proposed):
        require_phase_transition(expected.value, proposed.value)
        try:
            result = self.table.update_item(
                Key=self._key(operation),
                UpdateExpression=(
                    "SET #phase = :proposed, updated_at_epoch = :now "
                    "REMOVE failure_reason, resume_phase"
                ),
                ConditionExpression=(
                    "record_type = :record_type AND operation_id = :operation_id "
                    "AND #phase = :expected"
                ),
                ExpressionAttributeNames={"#phase": "phase"},
                ExpressionAttributeValues={
                    ":proposed": proposed.value,
                    ":now": int(self.clock()),
                    ":record_type": "account_lifecycle_operation",
                    ":operation_id": str(operation.get("operation_id") or ""),
                    ":expected": expected.value,
                },
                ReturnValues="ALL_NEW",
            )
        except ClientError as error:
            raise LifecycleV2ExecutionError("operation_phase_conflict") from error
        return dict(result.get("Attributes") or {})

    def record_retry(self, operation, *, reason):
        safe_reason = str(reason or "dependency_failure")[:128]
        resume_phase = str(
            operation.get("resume_phase") or operation.get("phase") or "",
        )
        if not resume_phase:
            raise LifecycleV2ExecutionError("operation_resume_phase_invalid")
        try:
            result = self.table.update_item(
                Key=self._key(operation),
                UpdateExpression=(
                    "SET resume_phase = :resume, "
                    "#phase = :retry, retryable = :yes, failure_reason = :reason, "
                    "updated_at_epoch = :now"
                ),
                ConditionExpression=(
                    "record_type = :record_type AND operation_id = :operation_id "
                    "AND #phase <> :completed"
                ),
                ExpressionAttributeNames={"#phase": "phase"},
                ExpressionAttributeValues={
                    ":retry": OperationPhase.RETRY_REQUIRED.value,
                    ":resume": resume_phase,
                    ":yes": True,
                    ":reason": safe_reason,
                    ":now": int(self.clock()),
                    ":record_type": "account_lifecycle_operation",
                    ":operation_id": str(operation.get("operation_id") or ""),
                    ":completed": OperationPhase.COMPLETED.value,
                },
                ReturnValues="ALL_NEW",
            )
        except ClientError as error:
            raise LifecycleV2ExecutionError("operation_retry_record_failed") from error
        return dict(result.get("Attributes") or {})

    def complete(self, operation, *, proof):
        if not (
            proof.get("cognito_identity_absent") is True
            and proof.get("cognito_email_absent") is True
            and proof.get("kaevo_graph_absent") is True
        ):
            raise LifecycleV2ExecutionError("terminal_proof_incomplete")
        try:
            result = self.table.update_item(
                Key=self._key(operation),
                UpdateExpression=(
                    "SET #phase = :completed, retryable = :no, proof = :proof, "
                    "updated_at_epoch = :now, completed_at_epoch = :now REMOVE failure_reason"
                ),
                ConditionExpression=(
                    "record_type = :record_type AND operation_id = :operation_id "
                    "AND #phase = :expected"
                ),
                ExpressionAttributeNames={"#phase": "phase"},
                ExpressionAttributeValues={
                    ":completed": OperationPhase.COMPLETED.value,
                    ":no": False,
                    ":proof": dict(proof),
                    ":now": int(self.clock()),
                    ":record_type": "account_lifecycle_operation",
                    ":operation_id": str(operation.get("operation_id") or ""),
                    ":expected": OperationPhase.VERIFYING_KAEVO_ABSENCE.value,
                },
                ReturnValues="ALL_NEW",
            )
        except ClientError as error:
            raise LifecycleV2ExecutionError("operation_completion_conflict") from error
        return dict(result.get("Attributes") or {})


class CognitoSubjectDeletion:
    """Delete and prove absence of one exact Cognito identity and its email.

    The normalized email comes only from the frozen account's exact
    AuthIdentity edge (or is backfilled from that exact Cognito subject before
    deletion). It is verification evidence, never an ownership selector.
    Keeping the evidence in AuthIdentity until graph deletion also makes a
    retry safe if Cognito deletion succeeded but the worker stopped before the
    absence check.
    """

    def __init__(
        self,
        client: Any,
        *,
        user_pool_id: str,
        auth_identities_table: Any,
    ):
        self.client = client
        self.user_pool_id = user_pool_id
        self.auth_identities_table = auth_identities_table

    @staticmethod
    def _attributes(user: Mapping[str, Any]) -> dict[str, str]:
        return {
            str(item.get("Name") or ""): str(item.get("Value") or "")
            for item in user.get("Attributes") or user.get("UserAttributes") or []
            if isinstance(item, Mapping)
        }

    @staticmethod
    def _escaped_filter_value(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def _filtered_users(self, field: str, value: str, *, ambiguity: str) -> list[dict[str, Any]]:
        response = self.client.list_users(
            UserPoolId=self.user_pool_id,
            Filter=f'{field} = "{self._escaped_filter_value(value)}"',
            Limit=2,
        )
        users = list(response.get("Users") or [])
        if response.get("PaginationToken") or len(users) > 1:
            raise LifecycleV2ExecutionError(ambiguity)
        return users

    def _users(self, subject: str) -> list[dict[str, Any]]:
        if not subject or len(subject) > 256 or any(ord(char) < 32 for char in subject):
            raise LifecycleV2ExecutionError("cognito_subject_invalid")
        return self._filtered_users(
            "sub", subject, ambiguity="cognito_subject_ambiguous",
        )

    def _auth_identity(
        self,
        *,
        account_id: str,
        subject: str,
        auth_identity_key: str,
    ) -> dict[str, Any]:
        expected_key = provider_subject_key("cognito", subject)
        if not hmac.compare_digest(auth_identity_key, expected_key):
            raise LifecycleV2ExecutionError("auth_identity_subject_conflict")
        item = self.auth_identities_table.get_item(
            Key={"auth_identity_key": auth_identity_key},
            ConsistentRead=True,
        ).get("Item")
        if not isinstance(item, Mapping) or any((
            item.get("entity_type") != "AuthIdentity",
            item.get("provider") != "cognito",
            item.get("status") != "active",
            not hmac.compare_digest(str(item.get("account_id") or ""), account_id),
        )):
            raise LifecycleV2ExecutionError("auth_identity_conflict")
        return dict(item)

    def _verified_email(
        self,
        *,
        account_id: str,
        subject: str,
        auth_identity_key: str,
    ) -> str:
        identity = self._auth_identity(
            account_id=account_id,
            subject=subject,
            auth_identity_key=auth_identity_key,
        )
        stored = ""
        if identity.get("email_verified") is True:
            try:
                stored = normalized_email(identity.get("normalized_email")) or ""
            except Exception:
                stored = ""

        users = self._users(subject)
        cognito_email = ""
        if users:
            attributes = self._attributes(users[0])
            if attributes.get("email_verified", "").lower() == "true":
                try:
                    cognito_email = normalized_email(attributes.get("email")) or ""
                except Exception:
                    cognito_email = ""
        if stored and cognito_email and not hmac.compare_digest(stored, cognito_email):
            raise LifecycleV2ExecutionError("cognito_email_conflict")
        email = stored or cognito_email
        if not email:
            raise LifecycleV2ExecutionError("cognito_verified_email_missing")
        if not stored:
            try:
                self.auth_identities_table.update_item(
                    Key={"auth_identity_key": auth_identity_key},
                    UpdateExpression=(
                        "SET normalized_email = :email, email_verified = :verified, "
                        "updated_at_epoch = :now"
                    ),
                    ConditionExpression=(
                        "entity_type = :entity_type AND provider = :provider "
                        "AND account_id = :account_id "
                        "AND #status = :active"
                    ),
                    ExpressionAttributeNames={"#status": "status"},
                    ExpressionAttributeValues={
                        ":email": email,
                        ":verified": True,
                        ":now": int(time.time()),
                        ":entity_type": "AuthIdentity",
                        ":provider": "cognito",
                        ":account_id": account_id,
                        ":active": "active",
                    },
                )
            except ClientError as error:
                raise LifecycleV2ExecutionError("cognito_email_evidence_persist_failed") from error
        return email

    def delete_identity(
        self,
        *,
        account_id: str,
        subject: str,
        auth_identity_key: str,
    ) -> None:
        email = self._verified_email(
            account_id=account_id,
            subject=subject,
            auth_identity_key=auth_identity_key,
        )
        users = self._users(subject)
        if not users:
            return
        username = str(users[0].get("Username") or "")
        if not username:
            raise LifecycleV2ExecutionError("cognito_subject_ambiguous")
        email_users = self._filtered_users(
            "email", email, ambiguity="cognito_email_ambiguous",
        )
        if (
            len(email_users) != 1
            or not hmac.compare_digest(
                str(email_users[0].get("Username") or ""), username,
            )
        ):
            raise LifecycleV2ExecutionError("cognito_email_binding_conflict")
        try:
            self.client.admin_delete_user(
                UserPoolId=self.user_pool_id, Username=username,
            )
        except ClientError as error:
            code = str((error.response or {}).get("Error", {}).get("Code") or "")
            if code not in {"UserNotFoundException", "ResourceNotFoundException"}:
                raise

    def identity_and_email_absent(
        self,
        *,
        account_id: str,
        subject: str,
        auth_identity_key: str,
    ) -> bool:
        email = self._verified_email(
            account_id=account_id,
            subject=subject,
            auth_identity_key=auth_identity_key,
        )
        return not self._users(subject) and not self._filtered_users(
            "email", email, ambiguity="cognito_email_ambiguous",
        )


class DynamoKaevoGraphDeletion:
    """Delete only the exact business keys frozen in the lifecycle operation."""

    _PRIORITY = {
        "profile_binding": 10,
        "cloud_profile": 20,
        "identity_profile": 30,
        "household_membership": 40,
        "household_membership_guard": 40,
        "identity_membership": 50,
        "principal": 60,
        "household": 70,
        "auth_identity": 80,
        "account": 90,
        "app_session_access": 5,
        "app_session_refresh": 5,
        "app_session_family": 6,
        "installation": 7,
        "profile_mapping": 8,
        "provider_binding": 100,
        "cognito_subject": 100,
        "owner_lifecycle_guard": 100,
    }

    def __init__(
        self, *, lifecycle_table: Any, tables: Mapping[str, Any],
        app_sessions_table: Any | None = None,
        household_invitations_table: Any | None = None,
    ):
        self.lifecycle_table = lifecycle_table
        self.tables = dict(tables)
        self.app_sessions_table = app_sessions_table
        self.household_invitations_table = household_invitations_table

    @staticmethod
    def _business_key(account_id: str, resource: Mapping[str, Any]):
        kind = str(resource.get("resource_type") or "")
        identifier = str(resource.get("resource_id") or "")
        attributes = resource.get("attributes") or {}
        if kind == "account":
            return "accounts", {"account_id": identifier}
        if kind == "auth_identity":
            return "auth_identities", {"auth_identity_key": identifier}
        if kind == "principal":
            return "principals", {"principal_id": identifier}
        if kind == "identity_membership":
            return "identity_memberships", {"principal_id": identifier}
        if kind == "household":
            return "identity_households", {"household_id": identifier}
        if kind in {"household_membership", "household_membership_guard"}:
            household_id = str(attributes.get("household_id") or "")
            if not household_id:
                raise LifecycleV2ExecutionError("household_membership_key_invalid")
            return "household_memberships", {
                "household_id": household_id, "membership_id": identifier,
            }
        if kind == "identity_profile":
            return "identity_profiles", {"profile_id": identifier}
        if kind == "cloud_profile":
            return "profiles", {"profile_id": identifier}
        if kind == "profile_binding":
            profile_id = str(attributes.get("profile_id") or "") or identifier
            return "profile_bindings", {"account_id": account_id, "profile_id": profile_id}
        if kind == "installation":
            return "installations", {"installation_id": identifier}
        if kind == "profile_mapping":
            installation_id = str(attributes.get("installation_id") or "")
            local_source_id = str(attributes.get("local_profile_source_id") or "")
            if not installation_id or not local_source_id:
                raise LifecycleV2ExecutionError("profile_mapping_key_invalid")
            return "profile_mappings", {
                "installation_id": installation_id,
                "local_profile_source_id": local_source_id,
            }
        if kind in {"app_session_access", "app_session_refresh"}:
            return "app_sessions", {"token_hash": identifier}
        if kind in {
            "app_session_family", "provider_binding", "cognito_subject",
            "owner_lifecycle_guard",
        }:
            return None
        raise LifecycleV2ExecutionError("resource_type_not_executable")

    def _family_session_items(self, family_id: str):
        if self.app_sessions_table is None or not family_id:
            raise LifecycleV2ExecutionError("app_session_table_missing")
        response = self.app_sessions_table.query(
            IndexName="family_id-created_at_epoch-index",
            KeyConditionExpression=Key("family_id").eq(family_id),
        )
        items = list(response.get("Items") or [])
        while response.get("LastEvaluatedKey"):
            response = self.app_sessions_table.query(
                IndexName="family_id-created_at_epoch-index",
                KeyConditionExpression=Key("family_id").eq(family_id),
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items") or [])
        return items

    def _family_sessions_present(self, family_id: str) -> bool:
        for item in self._family_session_items(family_id):
            token_hash = str(item.get("token_hash") or "")
            if token_hash and self.app_sessions_table.get_item(
                Key={"token_hash": token_hash}, ConsistentRead=True,
            ).get("Item") is not None:
                return True
        return False

    @staticmethod
    def _operation_key(operation_id: str) -> str:
        if (
            not operation_id.startswith("ald2_")
            or len(operation_id) > 128
            or any(ord(character) < 32 for character in operation_id)
        ):
            raise LifecycleV2ExecutionError("operation_identity_invalid")
        return f"operation#{operation_id}"

    def _lifecycle_partition(self, account_id: str) -> list[dict[str, Any]]:
        response = self.lifecycle_table.query(
            KeyConditionExpression=Key("account_id").eq(account_id),
            ConsistentRead=True,
        )
        items = [dict(item) for item in response.get("Items") or []]
        while response.get("LastEvaluatedKey"):
            response = self.lifecycle_table.query(
                KeyConditionExpression=Key("account_id").eq(account_id),
                ConsistentRead=True,
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(dict(item) for item in response.get("Items") or [])
        return items

    def _ordered(self, resources: Sequence[Mapping[str, Any]]):
        return sorted(
            resources,
            key=lambda item: (
                self._PRIORITY.get(str(item.get("resource_type") or ""), -1),
                str(item.get("resource_key") or ""),
            ),
        )

    @staticmethod
    def _cloud_seat_keys(
        resources: Sequence[Mapping[str, Any]],
    ) -> set[tuple[str, str]]:
        """Return only exact household/profile pairs frozen in memberships."""
        deleted_household_ids = {
            str(resource.get("resource_id") or "")
            for resource in resources
            if str(resource.get("resource_type") or "") == "household"
        }
        keys: set[tuple[str, str]] = set()
        for resource in resources:
            if str(resource.get("resource_type") or "") != "household_membership":
                continue
            attributes = resource.get("attributes") or {}
            household_id = str(attributes.get("household_id") or "")
            profile_id = str(attributes.get("profile_id") or "")
            if not household_id or not profile_id:
                raise LifecycleV2ExecutionError("household_cloud_seat_key_invalid")
            if household_id in deleted_household_ids:
                # A sole Owner deletion removes the exact household record;
                # there is no surviving shared seat ledger to reconcile.
                continue
            keys.add((household_id, profile_id))
        return keys

    def _release_cloud_seats(
        self, resources: Sequence[Mapping[str, Any]],
    ) -> None:
        seat_keys = self._cloud_seat_keys(resources)
        if not seat_keys:
            return
        households = self.tables.get("identity_households")
        if households is None:
            raise LifecycleV2ExecutionError("kaevo_table_missing")
        for household_id, profile_id in seat_keys:
            households.update_item(
                Key={"household_id": household_id},
                UpdateExpression=(
                    "DELETE cloud_seat_profile_ids :profile_ids "
                    "SET updated_at_epoch = :updated_at_epoch"
                ),
                ExpressionAttributeValues={
                    ":profile_ids": {profile_id},
                    ":updated_at_epoch": int(time.time()),
                },
            )

    def _cloud_seats_absent(
        self, resources: Sequence[Mapping[str, Any]],
    ) -> bool:
        seat_keys = self._cloud_seat_keys(resources)
        if not seat_keys:
            return True
        households = self.tables.get("identity_households")
        if households is None:
            raise LifecycleV2ExecutionError("kaevo_table_missing")
        for household_id, profile_id in seat_keys:
            household = households.get_item(
                Key={"household_id": household_id}, ConsistentRead=True,
            ).get("Item")
            if isinstance(household, Mapping) and profile_id in set(
                household.get("cloud_seat_profile_ids") or []
            ):
                return False
        return True

    @staticmethod
    def _invitation_scope(
        resources: Sequence[Mapping[str, Any]],
    ) -> tuple[set[str], dict[str, set[str]]]:
        """Return exact whole-household and member-profile deletion scopes."""
        whole_household_ids = {
            str(resource.get("resource_id") or "")
            for resource in resources
            if str(resource.get("resource_type") or "") == "household"
            and str(resource.get("resource_id") or "")
        }
        profile_ids_by_household: dict[str, set[str]] = {}
        for resource in resources:
            attributes = resource.get("attributes") or {}
            household_id = str(attributes.get("household_id") or "")
            profile_id = str(attributes.get("profile_id") or "")
            if (
                str(resource.get("resource_type") or "")
                in {"household_membership", "identity_profile", "cloud_profile"}
                and household_id
            ):
                if not profile_id:
                    profile_id = str(resource.get("resource_id") or "")
                if profile_id:
                    profile_ids_by_household.setdefault(household_id, set()).add(
                        profile_id
                    )
        return whole_household_ids, profile_ids_by_household

    def _scoped_invitation_items(
        self, resources: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        whole_household_ids, profile_ids_by_household = self._invitation_scope(
            resources
        )
        household_ids = whole_household_ids.union(profile_ids_by_household)
        if not household_ids or self.household_invitations_table is None:
            return []

        exact_items: list[dict[str, Any]] = []
        for household_id in sorted(household_ids):
            query = {
                "IndexName": "household_id-index",
                "KeyConditionExpression": Key("household_id").eq(household_id),
                "ConsistentRead": False,
            }
            while True:
                response = self.household_invitations_table.query(**query)
                for candidate in response.get("Items", []):
                    code_hash = str(candidate.get("code_hash") or "")
                    if not code_hash:
                        continue
                    exact = self.household_invitations_table.get_item(
                        Key={"code_hash": code_hash}, ConsistentRead=True,
                    ).get("Item")
                    if (
                        not isinstance(exact, Mapping)
                        or str(exact.get("household_id") or "") != household_id
                    ):
                        continue
                    if (
                        household_id in whole_household_ids
                        or str(exact.get("profile_id") or "")
                        in profile_ids_by_household.get(household_id, set())
                    ):
                        exact_items.append(dict(exact))
                last_key = response.get("LastEvaluatedKey")
                if not last_key:
                    break
                query["ExclusiveStartKey"] = last_key
        return exact_items

    def _delete_scoped_invitations(
        self, resources: Sequence[Mapping[str, Any]],
    ) -> None:
        if self.household_invitations_table is None:
            return
        for invitation in self._scoped_invitation_items(resources):
            code_hash = str(invitation.get("code_hash") or "")
            if code_hash:
                self.household_invitations_table.delete_item(
                    Key={"code_hash": code_hash}
                )

    def _scoped_invitations_absent(
        self, resources: Sequence[Mapping[str, Any]],
    ) -> bool:
        return not self._scoped_invitation_items(resources)

    def _reconcile_owner_guard(self, resource: Mapping[str, Any]) -> None:
        owner_account_id = str(resource.get("resource_id") or "")
        attributes = resource.get("attributes") or {}
        household_id = str(attributes.get("household_id") or "")
        if (
            not owner_account_id
            or str(attributes.get("owner_account_id") or "") != owner_account_id
            or not household_id
        ):
            raise LifecycleV2ExecutionError("owner_lifecycle_guard_invalid")
        memberships = self.tables.get("household_memberships")
        if memberships is None:
            raise LifecycleV2ExecutionError("kaevo_table_missing")
        response = memberships.query(
            KeyConditionExpression=Key("household_id").eq(household_id),
            ConsistentRead=True,
        )
        items = list(response.get("Items") or [])
        while response.get("LastEvaluatedKey"):
            response = memberships.query(
                KeyConditionExpression=Key("household_id").eq(household_id),
                ConsistentRead=True,
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items") or [])
        active = [
            item for item in items
            if item.get("entity_type") == "HouseholdMembership"
            and item.get("status") == "active"
        ]
        owners = [
            item for item in active
            if str(item.get("account_id") or "") == owner_account_id
            and str(item.get("canonical_role") or item.get("role") or "") == "owner"
        ]
        if len(owners) != 1:
            raise LifecycleV2ExecutionError("owner_membership_ambiguous")
        next_state = (
            "sole_member" if len(active) == 1
            else "ownership_transfer_required"
        )
        try:
            self.lifecycle_table.update_item(
                Key={"account_id": owner_account_id, "record_key": "root"},
                UpdateExpression=(
                    "SET owner_deletion_state = :next, updated_at_epoch = :now "
                    "ADD revision :one"
                ),
                ConditionExpression=(
                    "record_type = :root_type AND #state = :active "
                    "AND account_role = :owner"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":next": next_state,
                    ":now": int(time.time()),
                    ":one": 1,
                    ":root_type": "account_lifecycle_root",
                    ":active": "active",
                    ":owner": "owner",
                },
            )
        except ClientError as error:
            raise LifecycleV2ExecutionError("owner_lifecycle_guard_update_failed") from error

    def delete_resources(self, *, account_id, operation_id, resources):
        current_operation_key = self._operation_key(operation_id)
        # Invitation rows are live one-time workflow records, not retained
        # profile history. Remove the exact frozen member/household scope before
        # deleting its canonical graph so nothing can later rehydrate a card.
        self._delete_scoped_invitations(resources)
        # Cloud seats are household-owned accounting references, not records
        # owned by the deleted member account. Release the exact frozen seat
        # before deleting that membership so successful lifecycle completion
        # cannot leave a deleted profile visible or consume a household seat.
        self._release_cloud_seats(resources)
        for resource in self._ordered(resources):
            if str(resource.get("resource_type") or "") == "app_session_family":
                for item in self._family_session_items(str(resource.get("resource_id") or "")):
                    token_hash = str(item.get("token_hash") or "")
                    if token_hash:
                        self.app_sessions_table.delete_item(Key={"token_hash": token_hash})
                continue
            target = self._business_key(account_id, resource)
            if target is not None:
                table_name, key = target
                table = self.tables.get(table_name)
                if table is None:
                    raise LifecycleV2ExecutionError("kaevo_table_missing")
                table.delete_item(Key=key)
        for resource in resources:
            if str(resource.get("resource_type") or "") == "owner_lifecycle_guard":
                self._reconcile_owner_guard(resource)
        for resource in resources:
            self.lifecycle_table.delete_item(Key={
                "account_id": account_id,
                "record_key": str(resource.get("resource_key") or ""),
            })
        self.lifecycle_table.delete_item(Key={"account_id": account_id, "record_key": "root"})
        # Preserve exactly one operation as the terminal receipt. Every older
        # unconfirmed/retry operation belongs to the deleted account and must
        # not survive as an orphaned lifecycle record.
        for item in self._lifecycle_partition(account_id):
            record_key = str(item.get("record_key") or "")
            if (
                item.get("record_type") == "account_lifecycle_operation"
                and record_key != current_operation_key
            ):
                self.lifecycle_table.delete_item(Key={
                    "account_id": account_id,
                    "record_key": record_key,
                })

    def resources_absent(self, *, account_id, operation_id, resources):
        current_operation_key = self._operation_key(operation_id)
        if not self._scoped_invitations_absent(resources):
            return False
        if not self._cloud_seats_absent(resources):
            return False
        for resource in resources:
            if str(resource.get("resource_type") or "") == "app_session_family":
                if self._family_sessions_present(str(resource.get("resource_id") or "")):
                    return False
            target = self._business_key(account_id, resource)
            if target is not None:
                table_name, key = target
                table = self.tables.get(table_name)
                if table is None or table.get_item(Key=key, ConsistentRead=True).get("Item") is not None:
                    return False
            lifecycle_item = self.lifecycle_table.get_item(Key={
                "account_id": account_id,
                "record_key": str(resource.get("resource_key") or ""),
            }, ConsistentRead=True).get("Item")
            if lifecycle_item is not None:
                return False
        if self.lifecycle_table.get_item(
            Key={"account_id": account_id, "record_key": "root"},
            ConsistentRead=True,
        ).get("Item") is not None:
            return False
        remaining = self._lifecycle_partition(account_id)
        return all(
            item.get("record_type") == "account_lifecycle_operation"
            and str(item.get("record_key") or "") == current_operation_key
            and str(item.get("operation_id") or "") == operation_id
            for item in remaining
        )
