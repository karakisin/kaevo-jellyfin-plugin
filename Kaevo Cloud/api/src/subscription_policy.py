"""Canonical Kaevo subscription products and server-side capabilities.

This module maps only an already-verified App Store subscription result. It
does not parse receipts, accept client assertions, or activate subscriptions.
The production App Store Server integration must call this policy only after
Apple transaction verification succeeds.
"""

ACTIVE_SUBSCRIPTION_STATES = frozenset({"active", "trialing", "grace_period"})

LOCAL_INDIVIDUAL_MONTHLY = "com.sumagang.kaevo.local.individual.monthly"
LOCAL_FAMILY_MONTHLY = "com.sumagang.kaevo.local.family.monthly"
CLOUD_INDIVIDUAL_MONTHLY = "com.sumagang.kaevo.personal.monthly"
CLOUD_FAMILY_MONTHLY = "com.sumagang.kaevo.family.monthly"

PRODUCT_POLICIES = {
    LOCAL_INDIVIDUAL_MONTHLY: {
        "plan": "local_individual",
        "cloud_enabled": False,
        "family_enabled": False,
        "family_seats": 1,
        "feature_flags": {},
    },
    LOCAL_FAMILY_MONTHLY: {
        "plan": "local_family",
        "cloud_enabled": False,
        "family_enabled": True,
        "family_seats": 6,
        "feature_flags": {
            "family_profiles": True,
            "household_participants": True,
        },
    },
    CLOUD_INDIVIDUAL_MONTHLY: {
        "plan": "cloud_individual",
        "cloud_enabled": True,
        "family_enabled": False,
        "family_seats": 1,
        "feature_flags": {
            "cloud_sync": True,
            "cross_device_continue_watching": True,
            "personalized_cloud_home": True,
            "remote_jellyfin_metadata": True,
            "remote_playback": True,
        },
    },
    CLOUD_FAMILY_MONTHLY: {
        "plan": "cloud_family",
        "cloud_enabled": True,
        "family_enabled": True,
        "family_seats": 6,
        "feature_flags": {
            "cloud_sync": True,
            "cross_device_continue_watching": True,
            "personalized_cloud_home": True,
            "remote_jellyfin_metadata": True,
            "remote_playback": True,
            "family_profiles": True,
            "household_participants": True,
            "household_playback_sync": True,
        },
    },
}


def entitlements_for_verified_subscription(
    product_id,
    subscription_state,
    *,
    source,
    renews_at="",
    expires_at="",
):
    """Return fail-closed capabilities for one Apple-verified product."""
    policy = PRODUCT_POLICIES.get(str(product_id or "").strip())
    if policy is None:
        raise ValueError("unsupported_subscription_product")
    normalized_state = str(subscription_state or "").strip().lower()
    active = normalized_state in ACTIVE_SUBSCRIPTION_STATES
    return {
        "plan": policy["plan"],
        "subscription_state": normalized_state or "inactive",
        "cloud_enabled": active and policy["cloud_enabled"],
        "family_enabled": active and policy["family_enabled"],
        "family_seats": policy["family_seats"] if active else 1,
        "product_id": str(product_id),
        "source": str(source or "app_store_verified"),
        "renews_at": str(renews_at or ""),
        "expires_at": str(expires_at or ""),
        "feature_flags": {
            key: bool(value) and active
            for key, value in policy["feature_flags"].items()
        },
    }
