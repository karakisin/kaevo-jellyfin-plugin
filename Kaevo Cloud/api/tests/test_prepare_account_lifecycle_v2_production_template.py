import copy
import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[2] / "scripts" / "prepare-account-lifecycle-v2-production-template.py"
SPEC = importlib.util.spec_from_file_location("prepare_lifecycle_v2", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def resource(kind="Safe::Resource", **properties):
    return {"Type": kind, "Properties": properties}


def role(lifecycle=False):
    statements = [
        {"Sid": "ReadInvitationAndOnboardingAuthority", "Resource": ["profiles"]},
        {"Sid": "AtomicallyAdvanceHouseholdJoinOnboarding", "Resource": ["profiles"]},
        {"Sid": "PutProfileSetupRecordsTransactionally", "Resource": ["profiles"]},
    ]
    if lifecycle:
        for statement in statements:
            statement["Resource"].append({"Fn::GetAtt": ["KaevoAccountLifecycleV2Table", "Arn"]})
        statements.append({
            "Sid": "UpdateLifecycleV2OwnershipGuardTransactionally",
            "Resource": {"Fn::GetAtt": ["KaevoAccountLifecycleV2Table", "Arn"]},
        })
    return resource(Policies=[{"PolicyDocument": {"Statement": statements}}], Tags=["keep"])


def templates():
    deployed = {
        "Resources": {
            "Unrelated": resource(Value="unchanged", Tags=["keep"]),
            "KaevoCloudHttpApi": resource(Body={"paths": {"/v3/health": {"get": {}}}}),
            "KaevoCloudHttpApiStage": resource(RouteSettings={"GET /v3/health": {"Rate": 1}}),
            "KaevoHouseholdJoinFunction": resource(
                Code={"S3Key": "old"},
                Environment={"Variables": {"EXISTING": "keep"}},
                Tags=["keep"],
            ),
            "KaevoHouseholdJoinFunctionRole": role(),
        }
    }
    candidate = copy.deepcopy(deployed)
    resources = candidate["Resources"]
    resources["KaevoAccountLifecycleV2Table"] = resource(kind="AWS::DynamoDB::Table")
    for path in [
        "/v4/account-lifecycle/enroll-owner",
        "/v4/account-lifecycle/deletion-preflights",
        "/v4/account-lifecycle/deletions/{operationId}",
        "/v4/account-lifecycle/deletions/{operationId}/confirm",
    ]:
        resources["KaevoCloudHttpApi"]["Properties"]["Body"]["paths"][path] = {"post": {}}
    resources["KaevoCloudHttpApiStage"]["Properties"]["RouteSettings"][
        "POST /v4/account-lifecycle/enroll-owner"
    ] = {"ThrottlingRateLimit": 1}
    resources["KaevoHouseholdJoinFunction"]["Properties"]["Code"] = {"S3Key": "v2"}
    resources["KaevoHouseholdJoinFunction"]["Properties"]["Environment"]["Variables"][
        "ACCOUNT_LIFECYCLE_V2_TABLE"
    ] = {"Ref": "KaevoAccountLifecycleV2Table"}
    resources["KaevoHouseholdJoinFunctionRole"] = role(lifecycle=True)
    return deployed, candidate


def test_prepared_template_preserves_every_unrelated_resource_and_property():
    deployed, candidate = templates()
    prepared = MODULE.prepare_template(deployed, candidate)

    assert prepared["Resources"]["Unrelated"] == deployed["Resources"]["Unrelated"]
    assert prepared["Resources"]["KaevoHouseholdJoinFunction"]["Properties"]["Tags"] == ["keep"]
    assert prepared["Resources"]["KaevoHouseholdJoinFunction"]["Properties"]["Code"] == {"S3Key": "v2"}
    assert "KaevoAccountLifecycleV2Table" in prepared["Resources"]
    assert len(prepared["Resources"]["KaevoCloudHttpApi"]["Properties"]["Body"]["paths"]) == 5


def test_existing_v2_resource_fails_closed_instead_of_overwriting():
    deployed, candidate = templates()
    deployed["Resources"]["KaevoAccountLifecycleV2Table"] = resource(Value="existing")

    with pytest.raises(MODULE.ScopeError, match="already exist"):
        MODULE.prepare_template(deployed, candidate)


def test_candidate_route_drift_fails_closed():
    deployed, candidate = templates()
    candidate["Resources"]["KaevoCloudHttpApi"]["Properties"]["Body"]["paths"].pop(
        "/v4/account-lifecycle/deletion-preflights"
    )

    with pytest.raises(MODULE.ScopeError, match="route set"):
        MODULE.prepare_template(deployed, candidate)


def test_migration_deployment_contract_includes_expected_cognito_issuer():
    cloud_root = Path(__file__).parents[2]
    main_template = (cloud_root / "infra" / "template.yaml").read_text()
    migration = main_template.split(
        "  KaevoAccountLifecycleV2MigrationFunction:", 1,
    )[1].split("  KaevoAccountLifecycleV2MigrationLogGroup:", 1)[0]
    assert (
        "EXPECTED_COGNITO_ISSUER: !Sub "
        "https://cognito-idp.${AWS::Region}.amazonaws.com/${KaevoUserPool}"
    ) in migration

    production_template = (
        cloud_root / "infra" / "account-lifecycle-v2-migration-production.yaml"
    ).read_text()
    production_migration = production_template.split(
        "  MigrationFunction:", 1,
    )[1].split("  MigrationIntegration:", 1)[0]
    assert "EXPECTED_COGNITO_ISSUER: !Ref ExpectedCognitoIssuer" in production_migration
    assert (
        "Default: https://cognito-idp.us-west-2.amazonaws.com/"
        "us-west-2_alttn6ama"
    ) in production_template


def test_migration_role_can_authorize_atomic_snapshot_condition_checks():
    cloud_root = Path(__file__).parents[2]
    main_template = (cloud_root / "infra" / "template.yaml").read_text()
    migration = main_template.split(
        "  KaevoAccountLifecycleV2MigrationFunction:", 1,
    )[1].split("  KaevoAccountLifecycleV2MigrationLogGroup:", 1)[0]
    assert "- dynamodb:ConditionCheckItem" in migration
    assert "ForAnyValue:StringEquals:" in migration

    production_template = (
        cloud_root / "infra" / "account-lifecycle-v2-migration-production.yaml"
    ).read_text()
    migration_role = production_template.split(
        "  MigrationRole:", 1,
    )[1].split("  MigrationFunction:", 1)[0]
    assert "- dynamodb:ConditionCheckItem" in migration_role
    assert "ForAnyValue:StringEquals:" in migration_role


def test_owner_enrollment_can_put_only_exact_transactional_records():
    cloud_root = Path(__file__).parents[2]
    main_template = (cloud_root / "infra" / "template.yaml").read_text()
    enrollment = main_template.split(
        "  KaevoAccountLifecycleV2EnrollmentFunction:", 1,
    )[1].split("  KaevoAccountLifecycleV2EnrollmentLogGroup:", 1)[0]

    assert "Sid: PutExactAccountLifecycleV2EnrollmentRecords" in enrollment
    assert "- dynamodb:PutItem" in enrollment
    assert "ForAnyValue:StringEquals:" in enrollment
    assert "dynamodb:EnclosingOperation:" in enrollment
    assert "- TransactWriteItems" in enrollment
    for table in (
        "KaevoAccountLifecycleV2Table",
        "KaevoAccountsTable",
        "KaevoAuthIdentitiesTable",
        "KaevoPrincipalsTable",
        "KaevoIdentityMembershipsTable",
        "KaevoHouseholdMembershipsTable",
        "KaevoIdentityHouseholdsTable",
        "KaevoIdentityProfilesTable",
        "KaevoProfilesTable",
        "KaevoProfileBindingsTable",
        "KaevoSecurityAuditTable",
    ):
        assert f"!GetAtt {table}.Arn" in enrollment
