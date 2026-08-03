"""Fail-closed semantic comparison for Cognito managed-login custom assets.

The Cognito response model documents ``DYNAMIC`` as a browser-adaptive asset.
Some responses materialize that one supplied asset as identical LIGHT, DARK, and
DYNAMIC records.  This module permits *only* that lossless representation
expansion; it never treats a different byte stream or asset category as equal.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping, Sequence


_COLOR_MODES = frozenset({"LIGHT", "DARK", "DYNAMIC"})


class BrandingAssetMismatch(ValueError):
    """Raised when actual custom assets are not semantically identical."""


def _raw_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        try:
            return base64.b64decode(value, validate=True)
        except ValueError as error:
            raise BrandingAssetMismatch("ASSET_BYTES_INVALID") from error
    raise BrandingAssetMismatch("ASSET_BYTES_INVALID")


def _fingerprint(asset: Mapping[str, object]) -> tuple[str, str, str, int]:
    """Return non-sensitive asset identity: category, extension, digest, size."""
    category = asset.get("Category")
    extension = asset.get("Extension")
    if not isinstance(category, str) or not isinstance(extension, str):
        raise BrandingAssetMismatch("ASSET_METADATA_INVALID")
    # Live boto3 responses carry binary ``Bytes``.  The protected journal
    # deliberately serializes that value as ``BytesBase64`` so it can be
    # rechecked without retaining an arbitrary JSON representation of bytes.
    has_bytes = "Bytes" in asset
    has_base64 = "BytesBase64" in asset
    if has_bytes and has_base64:
        raise BrandingAssetMismatch("ASSET_BYTES_AMBIGUOUS")
    raw = _raw_bytes(asset.get("Bytes") if has_bytes else asset.get("BytesBase64"))
    return category, extension, hashlib.sha256(raw).hexdigest(), len(raw)


def _single_dynamic_template(template_assets: Sequence[Mapping[str, object]]) -> Mapping[str, object]:
    if len(template_assets) != 1:
        raise BrandingAssetMismatch("TEMPLATE_ASSET_COUNT_INVALID")
    asset = template_assets[0]
    if asset.get("ColorMode") != "DYNAMIC":
        raise BrandingAssetMismatch("TEMPLATE_ASSET_NOT_DYNAMIC")
    _fingerprint(asset)
    return asset


def compare_custom_assets(
    template_assets: Sequence[Mapping[str, object]], actual_assets: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    """Prove a one-asset DYNAMIC template equals a custom Cognito response.

    Returns redacted, durable evidence only.  An exact one-item response is
    accepted.  The sole alternate representation is the complete light/dark/
    dynamic triplet with the same category, extension, digest, and byte count.
    """
    template = _single_dynamic_template(template_assets)
    expected = _fingerprint(template)
    if len(actual_assets) == 1:
        actual = actual_assets[0]
        if actual.get("ColorMode") == "DYNAMIC" and _fingerprint(actual) == expected:
            return {
                "equivalent": True,
                "representation": "EXACT_DYNAMIC",
                "asset_sha256": expected[2],
                "asset_size": expected[3],
            }
        raise BrandingAssetMismatch("CUSTOM_ASSET_MISMATCH")

    if len(actual_assets) != 3:
        raise BrandingAssetMismatch("CUSTOM_ASSET_COUNT_MISMATCH")
    modes = [asset.get("ColorMode") for asset in actual_assets]
    if set(modes) != _COLOR_MODES or len(set(modes)) != 3:
        raise BrandingAssetMismatch("CUSTOM_ASSET_MODES_MISMATCH")
    if any(_fingerprint(asset) != expected for asset in actual_assets):
        raise BrandingAssetMismatch("CUSTOM_ASSET_MISMATCH")
    return {
        "equivalent": True,
        "representation": "COGNITO_DYNAMIC_MATERIALIZATION",
        "asset_sha256": expected[2],
        "asset_size": expected[3],
        "materialized_modes": sorted(_COLOR_MODES),
    }
