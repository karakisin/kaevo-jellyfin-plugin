"""Least-privilege contract for the dedicated Identity V3 IAM policy."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


def _template_generator():
    script = Path(__file__).resolve().parents[2] / "scripts" / "prepare-identity-v3-minimal-template.py"
    spec = spec_from_file_location("identity_v3_template_generator", script)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_existing_account_migration_has_only_required_transactional_put_item_permissions():
    policy = _template_generator().identity_v3_data_policy()
    statements = policy["Properties"]["PolicyDocument"]["Statement"]
    statement = next(item for item in statements if item["Sid"] == "WriteExistingAccountMigrationRecords")

    assert statement["Action"] == ["dynamodb:PutItem"]
    assert statement["Resource"] == [
        {"Fn::GetAtt": ["KaevoAccountsTable", "Arn"]},
        {"Fn::GetAtt": ["KaevoAuthIdentitiesTable", "Arn"]},
    ]


def test_household_membership_migration_has_only_required_transactional_put_item_permission():
    policy = _template_generator().identity_v3_data_policy()
    statements = policy["Properties"]["PolicyDocument"]["Statement"]
    statement = next(item for item in statements if item["Sid"] == "WriteHouseholdMembershipMigrationRecords")

    assert statement["Action"] == ["dynamodb:PutItem"]
    assert statement["Resource"] == [{"Fn::GetAtt": ["KaevoHouseholdMembershipsTable", "Arn"]}]


def test_profile_bootstrap_has_only_required_transactional_put_item_permissions():
    policy = _template_generator().identity_v3_data_policy()
    statements = policy["Properties"]["PolicyDocument"]["Statement"]
    statement = next(item for item in statements if item["Sid"] == "WriteProfileBootstrapRecords")

    assert statement["Action"] == ["dynamodb:PutItem"]
    assert statement["Resource"] == [
        {"Fn::GetAtt": ["KaevoProfilesTable", "Arn"]},
        {"Fn::GetAtt": ["KaevoProfileBindingsTable", "Arn"]},
        {"Fn::GetAtt": ["KaevoProfileMappingsTable", "Arn"]},
    ]
