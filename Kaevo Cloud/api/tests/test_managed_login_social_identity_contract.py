from __future__ import annotations

import base64
import hashlib
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = (ROOT / "infra" / "template.yaml").read_text(encoding="utf-8")
FORM_LOGO = ROOT / "infra" / "assets" / "KaevoAppIconWordmark-Cognito-512.png"


def resource_block(logical_id: str, next_logical_id: str) -> str:
    start = TEMPLATE.index(f"  {logical_id}:\n")
    end = TEMPLATE.index(f"  {next_logical_id}:\n", start)
    return TEMPLATE[start:end]


def test_managed_login_uses_kaevo_graphite_and_champagne_branding():
    block = resource_block(
        "KaevoSecurityStageManagedLoginBranding",
        "KaevoIdentityClaimIssuerPermission",
    )
    assert "UseCognitoProvidedValues: false" in block
    assert block.count("Category: FORM_LOGO") == 1
    assert "&KaevoManagedLoginFormLogo" in block
    assert "<<: *KaevoManagedLoginFormLogo" not in block
    assert "ColorMode: LIGHT" not in block
    assert "ColorMode: DARK" not in block
    assert "ColorMode: DYNAMIC" in block
    assert "Extension: PNG" in block
    assert "enabled: true" in block
    assert "colorSchemeMode: DARK" in block
    assert "backgroundColor: e6c083ff" in block
    assert "textColor: 111318ff" in block
    assert "color: 090b0eff" in block
    assert "borderRadius: 24" in block


def test_managed_login_embeds_the_reviewed_combined_kaevo_artwork():
    block = resource_block(
        "KaevoSecurityStageManagedLoginBranding",
        "KaevoIdentityClaimIssuerPermission",
    )
    match = re.search(r"^\s+Bytes:\s+([A-Za-z0-9+/=]+)$", block, re.MULTILINE)
    assert match is not None
    embedded = base64.b64decode(match.group(1), validate=True)
    reviewed = FORM_LOGO.read_bytes()
    assert embedded == reviewed
    assert hashlib.sha256(embedded).hexdigest() == (
        "6ee6468fc9ac7313688e4f259d88320d569ad785165a83403e016c7a75b028ac"
    )


def test_social_identity_providers_are_optional_and_secret_backed():
    assert "GoogleIdentityProviderSecretArn:" in TEMPLATE
    assert "AppleIdentityProviderSecretArn:" in TEMPLATE
    assert "HasGoogleIdentityProvider:" in TEMPLATE
    assert "HasAppleIdentityProvider:" in TEMPLATE

    google = resource_block("KaevoGoogleIdentityProvider", "KaevoAppleIdentityProvider")
    apple = resource_block("KaevoAppleIdentityProvider", "KaevoSecurityStageUserPoolDomain")
    assert "Condition: HasGoogleIdentityProvider" in google
    assert "ProviderType: Google" in google
    assert "SecretString:client_id" in google
    assert "SecretString:client_secret" in google
    assert "Condition: HasAppleIdentityProvider" in apple
    assert "ProviderType: SignInWithApple" in apple
    for key in ("client_id", "team_id", "key_id", "private_key"):
        assert f"SecretString:{key}" in apple


def test_native_client_and_claim_issuer_share_the_same_provider_allowlist():
    client = resource_block(
        "KaevoSecurityStageNativeOidcClient",
        "KaevoGoogleIdentityProvider",
    )
    assert "!If [HasGoogleIdentityProvider, !Ref KaevoGoogleIdentityProvider" in client
    assert "!If [HasAppleIdentityProvider, !Ref KaevoAppleIdentityProvider" in client

    issuer = resource_block("KaevoIdentityClaimIssuerFunction", "KaevoIdentityClaimIssuerLogGroup")
    assert 'EXPECTED_NATIVE_GOOGLE_ENABLED: !If [HasGoogleIdentityProvider, "true", "false"]' in issuer
    assert 'EXPECTED_NATIVE_APPLE_ENABLED: !If [HasAppleIdentityProvider, "true", "false"]' in issuer
    assert "GoogleIdentityProviderSecretArn" not in issuer
    assert "AppleIdentityProviderSecretArn" not in issuer
    assert "SecretString:" not in issuer


def test_template_contains_no_social_provider_secret_values():
    assert "YourGoogleAppId" not in TEMPLATE
    assert "YourGoogleAppSecret" not in TEMPLATE
    assert "YourApplePrivateKey" not in TEMPLATE
    assert "BEGIN PRIVATE KEY" not in TEMPLATE
