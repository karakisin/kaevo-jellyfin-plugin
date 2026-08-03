from __future__ import annotations

import base64

import pytest

from scripts.managed_login_branding_semantics import BrandingAssetMismatch, compare_custom_assets


def asset(mode="DYNAMIC", payload=b"kaevo-logo", category="FORM_LOGO", extension="PNG"):
    return {
        "Category": category,
        "ColorMode": mode,
        "Extension": extension,
        "Bytes": base64.b64encode(payload).decode("ascii"),
    }


def test_exact_dynamic_custom_asset_equals_registered_template():
    result = compare_custom_assets([asset()], [asset()])
    assert result["equivalent"] is True
    assert result["representation"] == "EXACT_DYNAMIC"


def test_journal_base64_representation_equals_live_binary_asset():
    journal_asset = asset()
    journal_asset["BytesBase64"] = journal_asset.pop("Bytes")
    live_asset = asset()
    live_asset["Bytes"] = base64.b64decode(live_asset["Bytes"])
    assert compare_custom_assets([journal_asset], [live_asset])["representation"] == "EXACT_DYNAMIC"


def test_identical_dynamic_materialization_is_equivalent():
    result = compare_custom_assets([asset()], [asset("DARK"), asset("DYNAMIC"), asset("LIGHT")])
    assert result["representation"] == "COGNITO_DYNAMIC_MATERIALIZATION"
    assert result["materialized_modes"] == ["DARK", "DYNAMIC", "LIGHT"]


@pytest.mark.parametrize("actual", [
    [asset("DARK"), asset("DYNAMIC"), asset("LIGHT", payload=b"unexpected")],
    [asset("DARK"), asset("DYNAMIC"), asset("DYNAMIC")],
    [asset("DARK"), asset("DYNAMIC"), asset("LIGHT", category="FAVICON")],
    [asset("DARK"), asset("DYNAMIC")],
])
def test_any_nonlossless_or_unexpected_custom_asset_fails_closed(actual):
    with pytest.raises(BrandingAssetMismatch):
        compare_custom_assets([asset()], actual)


def test_template_must_be_single_dynamic_asset():
    with pytest.raises(BrandingAssetMismatch, match="TEMPLATE_ASSET"):
        compare_custom_assets([asset("LIGHT")], [asset("LIGHT")])
