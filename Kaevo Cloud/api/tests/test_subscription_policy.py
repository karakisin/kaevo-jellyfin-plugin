import pytest

from subscription_policy import (
    CLOUD_FAMILY_MONTHLY,
    CLOUD_INDIVIDUAL_MONTHLY,
    LOCAL_FAMILY_MONTHLY,
    LOCAL_INDIVIDUAL_MONTHLY,
    PRODUCT_POLICIES,
    entitlements_for_verified_subscription,
)


@pytest.mark.parametrize(
    ("product_id", "plan", "cloud_enabled", "family_enabled", "family_seats"),
    [
        (LOCAL_INDIVIDUAL_MONTHLY, "local_individual", False, False, 1),
        (LOCAL_FAMILY_MONTHLY, "local_family", False, True, 6),
        (CLOUD_INDIVIDUAL_MONTHLY, "cloud_individual", True, False, 1),
        (CLOUD_FAMILY_MONTHLY, "cloud_family", True, True, 6),
    ],
)
def test_verified_active_products_map_to_exact_capabilities(
    product_id,
    plan,
    cloud_enabled,
    family_enabled,
    family_seats,
):
    entitlements = entitlements_for_verified_subscription(
        product_id,
        "active",
        source="app_store_server_api",
    )

    assert entitlements["plan"] == plan
    assert entitlements["cloud_enabled"] is cloud_enabled
    assert entitlements["family_enabled"] is family_enabled
    assert entitlements["family_seats"] == family_seats
    assert entitlements["product_id"] == product_id
    assert entitlements["source"] == "app_store_server_api"


def test_local_family_never_inherits_remote_or_family_sync_capabilities():
    entitlements = entitlements_for_verified_subscription(
        LOCAL_FAMILY_MONTHLY,
        "trialing",
        source="app_store_server_api",
    )

    assert entitlements["family_enabled"] is True
    assert entitlements["cloud_enabled"] is False
    assert entitlements["feature_flags"] == {
        "family_profiles": True,
        "household_participants": True,
    }


@pytest.mark.parametrize("state", ["expired", "revoked", "billing_retry", ""])
def test_inactive_states_fail_closed_without_discarding_product_identity(state):
    entitlements = entitlements_for_verified_subscription(
        CLOUD_FAMILY_MONTHLY,
        state,
        source="app_store_server_api",
    )

    assert entitlements["plan"] == "cloud_family"
    assert entitlements["cloud_enabled"] is False
    assert entitlements["family_enabled"] is False
    assert entitlements["family_seats"] == 1
    assert not any(entitlements["feature_flags"].values())


def test_unknown_product_is_rejected_instead_of_inferred():
    with pytest.raises(ValueError, match="unsupported_subscription_product"):
        entitlements_for_verified_subscription(
            "com.sumagang.kaevo.unknown",
            "active",
            source="app_store_server_api",
        )


def test_catalog_contains_only_the_four_explicit_products():
    assert set(PRODUCT_POLICIES) == {
        LOCAL_INDIVIDUAL_MONTHLY,
        LOCAL_FAMILY_MONTHLY,
        CLOUD_INDIVIDUAL_MONTHLY,
        CLOUD_FAMILY_MONTHLY,
    }
