from __future__ import annotations

import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = (ROOT / "infra" / "template.yaml").read_text(encoding="utf-8")
HANDLER = (ROOT / "api" / "src" / "handler.py").read_text(encoding="utf-8")
SOCIAL = (ROOT / "api" / "src" / "social_identity.py").read_text(encoding="utf-8")
GUARD = (ROOT / "api" / "social_identity_guard" / "social_identity_guard.py").read_text(encoding="utf-8")


def resource_block(logical_id: str, next_logical_id: str) -> str:
    start = TEMPLATE.index(f"  {logical_id}:\n")
    end = TEMPLATE.index(f"  {next_logical_id}:\n", start)
    return TEMPLATE[start:end]


def event_block(api: str, logical_id: str, next_logical_id: str) -> str:
    start = api.index(f"        {logical_id}:\n")
    end = api.index(f"        {next_logical_id}:\n", start)
    return api[start:end]


def test_social_link_routes_are_narrow_and_callbacks_are_not_gateway_authenticated():
    main_api = resource_block("KaevoCloudApiFunction", "KaevoSocialIdentityApiLogGroup")
    api = resource_block("KaevoSocialIdentityApiFunction", "KaevoV3ConnectorControlLogGroup")
    assert "Path: /v2/identity/social-links\n" not in main_api
    assert api.count("Path: /v2/identity/social-links\n") == 2
    assert api.count("Path: /v2/identity/social-links/callback\n") == 2
    assert "Method: GET" in api and "Method: POST" in api
    callback_post_start = api.index("        SocialIdentityLinkCallbackPost:\n")
    callback_post_end = api.index("      Tags:\n", callback_post_start)
    social_events = (
        event_block(api, "ListSocialIdentityLinks", "StartSocialIdentityLink"),
        event_block(api, "StartSocialIdentityLink", "SocialIdentityLinkCallbackGet"),
        event_block(api, "SocialIdentityLinkCallbackGet", "SocialIdentityLinkCallbackPost"),
        api[callback_post_start:callback_post_end],
    )
    assert all("Authorizer:" not in block for block in social_events)
    assert 'if path == "/v2/identity/social-links":' in HANDLER
    assert 'if path == "/v2/identity/social-links/callback" and method in {"GET", "POST"}:' in HANDLER


def test_deployed_v2_pairing_permissions_remain_represented_by_sam_events():
    api = resource_block("KaevoCloudApiFunction", "KaevoSocialIdentityApiLogGroup")
    assert "MintHomeConnectorPairingGrant:" in api
    assert "Path: /v2/home-connectors/pairing/grants" in api
    assert "StartHomeConnectorPairingWithGrant:" in api
    assert "Path: /v2/home-connectors/pairing/start" in api


def test_owner_link_routes_require_bound_session_and_explicit_confirmation():
    assert "session, error_response = owner_bound_session(event)" in HANDLER
    assert 'body.get("confirmed") is not True' in HANDLER
    assert '"explicit_confirmation_required"' in HANDLER
    assert 'session.get("record_type") != "access"' in HANDLER
    assert 'session.get("role") != "owner"' in HANDLER


def test_provider_identity_is_linked_by_stable_subject_not_email():
    assert '"ProviderAttributeName": "Cognito_Subject"' in SOCIAL
    assert '"ProviderAttributeValue": identity.subject' in SOCIAL
    assert "Filter=f'sub =" in SOCIAL
    assert "Filter=f'email =" not in SOCIAL
    assert "admin_link_provider_for_user" not in GUARD
    assert "existing_account_link_required" in GUARD


def test_identity_guard_is_isolated_and_cannot_receive_provider_credentials():
    guard = resource_block("KaevoSocialIdentityGuardFunction", "KaevoSocialIdentityGuardPermission")
    issuer = resource_block("KaevoIdentityClaimIssuerFunction", "KaevoIdentityClaimIssuerLogGroup")
    enrollment = resource_block("KaevoOwnerEnrollmentFunction", "KaevoOwnerEnrollmentLogGroup")
    assert "CodeUri: ../api/social_identity_guard/" in guard
    assert "cognito-idp:ListUsers" in guard
    assert "EXPECTED_USER_POOL_ID: !Ref SocialIdentityUserPoolId" in guard
    assert "userpool/${SocialIdentityUserPoolId}" in guard
    assert "userpool/*" not in guard
    assert "AdminLinkProviderForUser" not in guard
    for block in (guard, issuer, enrollment):
        assert "GOOGLE_IDENTITY_PROVIDER_SECRET_ARN" not in block
        assert "APPLE_IDENTITY_PROVIDER_SECRET_ARN" not in block
        assert "AdminLinkProviderForUser" not in block


def test_only_api_lambda_can_read_provider_secrets_and_link_identity():
    api = resource_block("KaevoCloudApiFunction", "KaevoSocialIdentityApiLogGroup")
    assert "Sid: ManageExplicitSocialIdentityLinks" in api
    assert "cognito-idp:AdminLinkProviderForUser" in api
    assert "Sid: ReadConfiguredSocialIdentityProviderCredentials" in api
    assert "!Ref GoogleIdentityProviderSecretArn" in api
    assert "!Ref AppleIdentityProviderSecretArn" in api


def test_social_route_dispatcher_has_its_own_policy_and_only_invokes_the_exact_api_lambda():
    role = resource_block("KaevoSocialIdentityApiFunctionRole", "KaevoSocialIdentityApiFunction")
    function = resource_block("KaevoSocialIdentityApiFunction", "KaevoV3ConnectorControlLogGroup")
    assert "lambda:InvokeFunction" in role
    assert "Resource: !GetAtt KaevoCloudApiFunction.Arn" in role
    assert "Resource: \"*\"" not in role
    assert "TARGET_FUNCTION_NAME: !Ref KaevoCloudApiFunction" in function
    assert "GOOGLE_IDENTITY_PROVIDER_SECRET_ARN" not in function
    assert "APPLE_IDENTITY_PROVIDER_SECRET_ARN" not in function
    assert "AdminLinkProviderForUser" not in function


def test_oauth_transaction_is_short_lived_hashed_and_privacy_safe():
    assert "LINK_TTL_SECONDS = 5 * 60" in SOCIAL
    assert "hashlib.sha256(state.encode('ascii'))" in SOCIAL
    assert '"token_hash": state_key(state)' in SOCIAL
    assert '"oauth_nonce": nonce' in SOCIAL
    assert 'f"kaevo://oauth/social-link?state={state}"' in HANDLER
    assert "return social_link_redirect(\"failed\")" in HANDLER
    assert "LOGGER" not in SOCIAL
    assert "provider_identity.subject" not in GUARD


def test_social_callback_parameter_has_no_live_default():
    parameter = TEMPLATE[TEMPLATE.index("  SocialIdentityLinkCallbackUrl:\n"):TEMPLATE.index("Conditions:\n")]
    assert 'Default: ""' in parameter
    assert "execute-api" not in parameter
