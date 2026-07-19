from __future__ import annotations

import os
import pathlib
import sys

import pytest

os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

import claim_issuer
from claim_issuer import issue_claims
from identity_authority import AuthorityError, derive_authoritative_claims


class FakeTable:
    def __init__(self, key):
        self.key = key
        self.items = {}

    def get_item(self, *, Key, ConsistentRead=False):
        assert ConsistentRead is True
        item = self.items.get(Key[self.key])
        return {"Item": dict(item)} if item else {}


class FakeDynamo:
    def __init__(self, tables):
        self.tables = tables

    def Table(self, name):
        return self.tables[name]


class FakeCognito:
    def __init__(self, *, pool_name="kaevo-test-users", client_name="kaevo-test-ios-tvos", client_overrides=None):
        self.pool_name = pool_name
        self.client_name = client_name
        self.client_overrides = client_overrides or {}

    def describe_user_pool(self, *, UserPoolId):
        return {"UserPool": {"Id": UserPoolId, "Name": self.pool_name}}

    def describe_user_pool_client(self, *, UserPoolId, ClientId):
        client = {"ClientName": self.client_name, "ClientId": ClientId, "UserPoolId": UserPoolId}
        client.update(self.client_overrides)
        return {"UserPoolClient": client}


@pytest.fixture(autouse=True)
def issuer_environment(monkeypatch):
    values = {
        "PRINCIPALS_TABLE": "principals",
        "IDENTITY_MEMBERSHIPS_TABLE": "memberships",
        "IDENTITY_HOUSEHOLDS_TABLE": "households",
        "IDENTITY_PROFILES_TABLE": "profiles",
        "EXPECTED_USER_POOL_NAME": "kaevo-test-users",
        "EXPECTED_MAIN_CLIENT_NAME": "kaevo-test-ios-tvos",
        "EXPECTED_ENROLLMENT_CLIENT_NAME": "kaevo-test-owner-enrollment",
        "EXPECTED_NATIVE_CLIENT_NAME": "kaevo-security-stage-native-oidc",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def graph():
    principal = {
        "principal_id": "user-1", "account_id": "account-1", "household_id": "household-1",
        "role": "owner", "authz_version": 7, "profile_ids": ["profile-1"], "state": "active", "revoked": False,
    }
    membership = {
        "principal_id": "user-1", "account_id": "account-1", "household_id": "household-1",
        "profile_id": "profile-1", "role": "owner", "authz_version": 7, "state": "active",
    }
    household = {
        "household_id": "household-1", "account_id": "account-1", "owner_principal_id": "user-1", "state": "active",
    }
    profile = {
        "profile_id": "profile-1", "account_id": "account-1", "household_id": "household-1",
        "owner_principal_id": "user-1", "profile_type": "adult", "state": "active",
    }
    tables = {
        "principals": FakeTable("principal_id"), "memberships": FakeTable("principal_id"),
        "households": FakeTable("household_id"), "profiles": FakeTable("profile_id"),
    }
    tables["principals"].items["user-1"] = principal
    tables["memberships"].items["user-1"] = membership
    tables["households"].items["household-1"] = household
    tables["profiles"].items["profile-1"] = profile
    return FakeDynamo(tables), (principal, membership, household, profile)


def event(**overrides):
    value = {
        "version": "2",
        "triggerSource": "TokenGeneration_Authentication",
        "userPoolId": "us-west-2_pool",
        "callerContext": {"clientId": "main-client"},
        "request": {
            "userAttributes": {
                "sub": "user-1",
                "custom:account_id": "forged-account",
                "custom:role": "owner",
            },
            "clientMetadata": {"role": "owner", "household_id": "forged-household"},
        },
        "response": {},
    }
    value.update(overrides)
    return value


def native_cognito(**overrides):
    configuration = {
        "AllowedOAuthFlowsUserPoolClient": True,
        "EnableTokenRevocation": True,
        "AllowedOAuthFlows": ["code"],
        "AllowedOAuthScopes": ["openid"],
        "SupportedIdentityProviders": ["COGNITO"],
        "CallbackURLs": ["kaevo-security-stage://oauth/callback"],
        "LogoutURLs": ["kaevo-security-stage://oauth/logout"],
        "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
        "DefaultRedirectURI": "kaevo-security-stage://oauth/callback",
    }
    configuration.update(overrides)
    return FakeCognito(client_name="kaevo-security-stage-native-oidc", client_overrides=configuration)


def native_event(**overrides):
    values = {"triggerSource": "TokenGeneration_HostedAuth", "callerContext": {"clientId": "native-client"}}
    values.update(overrides)
    return event(**values)


def test_issuer_uses_only_authoritative_records_and_access_token():
    dynamo, _ = graph()
    result = issue_claims(event(), dynamodb=dynamo, cognito=FakeCognito())
    details = result["response"]["claimsAndScopeOverrideDetails"]
    claims = details["accessTokenGeneration"]["claimsToAddOrOverride"]
    assert claims == {
        "account_id": "account-1", "household_id": "household-1", "profile_id": "profile-1",
        "role": "owner", "authz_version": "7", "identity_schema_version": "1",
    }
    assert "claimsToAddOrOverride" not in details["idTokenGeneration"]
    assert set(details["idTokenGeneration"]["claimsToSuppress"]) == set(claims)


def test_enrollment_client_never_receives_kaevo_authority_claims():
    dynamo, _ = graph()
    result = issue_claims(event(), dynamodb=dynamo, cognito=FakeCognito(client_name="kaevo-test-owner-enrollment"))
    access = result["response"]["claimsAndScopeOverrideDetails"]["accessTokenGeneration"]
    assert "claimsToAddOrOverride" not in access
    assert "account_id" in access["claimsToSuppress"]


def test_native_hosted_auth_receives_equivalent_authoritative_claims():
    dynamo, _ = graph()
    main = issue_claims(event(), dynamodb=dynamo, cognito=FakeCognito())
    native = issue_claims(native_event(), dynamodb=dynamo, cognito=native_cognito())
    assert native["response"]["claimsAndScopeOverrideDetails"] == main["response"]["claimsAndScopeOverrideDetails"]


@pytest.mark.parametrize("trigger", [
    "TokenGeneration_Authentication",
    "TokenGeneration_NewPasswordChallenge",
    "TokenGeneration_AuthenticateDevice",
    "TokenGeneration_RefreshTokens",
    "TokenGeneration_ClientCredentials",
])
def test_native_rejects_every_non_hosted_auth_trigger(trigger):
    dynamo, _ = graph()
    with pytest.raises(AuthorityError):
        issue_claims(native_event(triggerSource=trigger), dynamodb=dynamo, cognito=native_cognito())


@pytest.mark.parametrize("client_name", [
    "kaevo-security-stage-native-oidc-lookalike",
    "prefix-kaevo-security-stage-native-oidc",
    "Kaevo-security-stage-native-oidc",
])
def test_native_client_name_matching_is_exact_and_case_sensitive(client_name):
    dynamo, _ = graph()
    with pytest.raises(AuthorityError):
        issue_claims(native_event(), dynamodb=dynamo, cognito=FakeCognito(client_name=client_name))


@pytest.mark.parametrize("field,value", [
    ("ClientSecret", "must-not-exist"),
    ("AllowedOAuthFlows", ["code", "implicit"]),
    ("AllowedOAuthScopes", ["openid", "email"]),
    ("SupportedIdentityProviders", ["COGNITO", "Google"]),
    ("CallbackURLs", ["kaevo-security-stage://oauth/callback", "kaevo://oauth/callback"]),
    ("ExplicitAuthFlows", ["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_SRP_AUTH"]),
])
def test_native_client_configuration_mismatch_fails_closed(field, value):
    dynamo, _ = graph()
    with pytest.raises(AuthorityError, match="unexpected_native_client_configuration"):
        issue_claims(native_event(), dynamodb=dynamo, cognito=native_cognito(**{field: value}))


def test_client_metadata_cannot_spoof_native_identity_role_or_household():
    dynamo, _ = graph()
    forged = native_event(request={
        "userAttributes": {"sub": "user-1", "custom:role": "owner", "custom:household_id": "forged"},
        "clientMetadata": {"clientId": "main-client", "role": "owner", "household_id": "forged"},
    })
    result = issue_claims(forged, dynamodb=dynamo, cognito=native_cognito())
    claims = result["response"]["claimsAndScopeOverrideDetails"]["accessTokenGeneration"]["claimsToAddOrOverride"]
    assert claims["household_id"] == "household-1"
    assert claims["role"] == "owner"


@pytest.mark.parametrize("missing", ["principals", "memberships", "households", "profiles"])
def test_missing_authoritative_record_fails_closed(missing):
    dynamo, _ = graph()
    dynamo.tables[missing].items.clear()
    with pytest.raises(AuthorityError):
        issue_claims(event(), dynamodb=dynamo, cognito=FakeCognito())


@pytest.mark.parametrize("record_index", [0, 1, 2, 3])
def test_disabled_or_revoked_graph_record_fails_closed(record_index):
    _, records = graph()
    records[record_index]["state"] = "disabled"
    with pytest.raises(AuthorityError):
        derive_authoritative_claims("user-1", *records)


def test_revoked_principal_and_unsupported_role_fail_closed():
    _, records = graph()
    records[0]["revoked"] = True
    with pytest.raises(AuthorityError):
        derive_authoritative_claims("user-1", *records)
    records[0]["revoked"] = False
    records[0]["role"] = "support"
    records[1]["role"] = "support"
    with pytest.raises(AuthorityError, match="unsupported_human_role"):
        derive_authoritative_claims("user-1", *records)


def test_profile_household_account_and_missing_version_fail_closed():
    _, records = graph()
    records[3]["household_id"] = "other-household"
    with pytest.raises(AuthorityError):
        derive_authoritative_claims("user-1", *records)
    _, records = graph()
    records[2]["account_id"] = "other-account"
    with pytest.raises(AuthorityError):
        derive_authoritative_claims("user-1", *records)
    _, records = graph()
    records[0].pop("authz_version")
    with pytest.raises(AuthorityError, match="invalid_authz_version"):
        derive_authoritative_claims("user-1", *records)


@pytest.mark.parametrize("field,value", [
    ("account_id", "other-account"), ("household_id", "other-household"),
    ("role", "support"), ("authz_version", 8),
])
def test_relationship_role_and_version_tampering_fails_closed(field, value):
    _, records = graph()
    records[1][field] = value
    with pytest.raises(AuthorityError):
        derive_authoritative_claims("user-1", *records)


def test_wrong_pool_wrong_client_and_unsupported_event_fail_closed():
    dynamo, _ = graph()
    for candidate, cognito in (
        (event(), FakeCognito(pool_name="wrong-pool")),
        (event(), FakeCognito(client_name="unknown-client")),
        (event(version="3"), FakeCognito()),
        (event(triggerSource="TokenGeneration_ClientCredentials"), FakeCognito()),
    ):
        with pytest.raises(AuthorityError):
            issue_claims(candidate, dynamodb=dynamo, cognito=cognito)


def test_malformed_subject_and_duplicate_profile_membership_fail_closed():
    dynamo, records = graph()
    with pytest.raises(AuthorityError):
        issue_claims(event(request={"userAttributes": {"sub": "bad\nsubject"}}), dynamodb=dynamo, cognito=FakeCognito())
    records[0]["profile_ids"] = ["profile-1", "profile-1"]
    with pytest.raises(AuthorityError):
        derive_authoritative_claims("user-1", *records)


def test_outage_fails_closed_and_logs_no_canary_or_complete_identity(monkeypatch, caplog):
    dynamo, _ = graph()
    dynamo.tables["principals"].items.clear()
    candidate = event(request={
        "userAttributes": {"sub": "complete-principal-canary", "email": "secret-canary@example.test"},
        "clientMetadata": {"password": "CANARY-SECRET", "household_id": "complete-household-canary"},
    })
    monkeypatch.setattr(claim_issuer.boto3, "resource", lambda _service: dynamo)
    monkeypatch.setattr(claim_issuer.boto3, "client", lambda _service: FakeCognito())
    with pytest.raises(RuntimeError, match="Not authorized"):
        claim_issuer.lambda_handler(candidate, None)
    logs = caplog.text
    assert "CANARY-SECRET" not in logs
    assert "secret-canary@example.test" not in logs
    assert "complete-principal-canary" not in logs
    assert "complete-household-canary" not in logs


def test_authority_table_outage_fails_closed_with_generic_client_error(monkeypatch, caplog):
    class OutageTable:
        def get_item(self, **_):
            raise RuntimeError("CANARY-DATABASE-OUTAGE")

    class OutageDynamo:
        def Table(self, _name):
            return OutageTable()

    monkeypatch.setattr(claim_issuer.boto3, "resource", lambda _service: OutageDynamo())
    monkeypatch.setattr(claim_issuer.boto3, "client", lambda _service: FakeCognito())
    with pytest.raises(RuntimeError, match="Not authorized") as error:
        claim_issuer.lambda_handler(event(), None)
    assert "CANARY-DATABASE-OUTAGE" not in str(error.value)
    assert "CANARY-DATABASE-OUTAGE" not in caplog.text
