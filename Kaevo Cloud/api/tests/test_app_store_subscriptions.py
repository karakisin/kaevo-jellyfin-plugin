from types import SimpleNamespace
import hashlib

import pytest

from app_store_subscriptions import (
    AppStoreBindingConflict,
    AppStoreBindingMissing,
    AppStoreVerificationError,
    load_root_certificates,
    process_signed_notification,
    sync_signed_transaction,
)


def test_bundled_apple_roots_match_the_reviewed_pki_fingerprints():
    certificates = load_root_certificates()

    assert [hashlib.sha256(value).hexdigest() for value in certificates] == [
        "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
        "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
        "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
    ]


class FakeTable:
    def __init__(self, key_name):
        self.key_name = key_name
        self.items = {}

    def get_item(self, *, Key, **_kwargs):
        item = self.items.get(Key[self.key_name])
        return {"Item": dict(item)} if item else {}

    def put_item(self, *, Item, **_kwargs):
        self.items[Item[self.key_name]] = dict(Item)
        return {}


class FakeVerifier:
    def __init__(self, *, transaction=None, notification=None):
        self.transaction = transaction
        self.notification = notification

    def verify_and_decode_signed_transaction(self, _signed_value):
        if isinstance(self.transaction, Exception):
            raise self.transaction
        return self.transaction

    def verify_and_decode_notification(self, _signed_value):
        if isinstance(self.notification, Exception):
            raise self.notification
        return self.notification


def transaction(
    *,
    product_id="com.sumagang.kaevo.personal.monthly",
    original_transaction_id="original-1",
    transaction_id="transaction-1",
    signed_date=2_000,
    expires_date=4_102_444_800_000,
    environment="Sandbox",
):
    return SimpleNamespace(
        bundleId="com.sumagang.kaevo",
        rawEnvironment=environment,
        originalTransactionId=original_transaction_id,
        transactionId=transaction_id,
        productId=product_id,
        expiresDate=expires_date,
        signedDate=signed_date,
        revocationDate=None,
        isUpgraded=False,
    )


def owner_session(account_id="acct_owner"):
    return {
        "record_type": "access",
        "role": "owner",
        "account_id": account_id,
        "household_id": "household-1",
        "profile_id": "profile-owner",
    }


def test_verified_local_sync_binds_account_without_granting_cloud_or_family_sync():
    bindings = FakeTable("original_transaction_id")
    entitlements = FakeTable("profile_id")

    result = sync_signed_transaction(
        signed_transaction="signed-transaction",
        environment="Sandbox",
        session=owner_session(),
        transactions_table=bindings,
        entitlements_table=entitlements,
        verifier=FakeVerifier(transaction=transaction()),
    )

    assert result["state"] == "subscription_updated"
    assert result["entitlements"]["cloud_enabled"] is False
    assert result["entitlements"]["family_enabled"] is False
    assert bindings.items["original-1"]["account_id"] == "acct_owner"
    assert entitlements.items["profile-owner"]["app_store_signed_date_ms"] == 2_000


def test_existing_transaction_cannot_be_rebound_to_another_kaevo_account():
    bindings = FakeTable("original_transaction_id")
    entitlements = FakeTable("profile_id")
    verifier = FakeVerifier(transaction=transaction())
    sync_signed_transaction(
        signed_transaction="signed-transaction",
        environment="Sandbox",
        session=owner_session("acct_owner"),
        transactions_table=bindings,
        entitlements_table=entitlements,
        verifier=verifier,
    )

    with pytest.raises(AppStoreBindingConflict):
        sync_signed_transaction(
            signed_transaction="signed-transaction",
            environment="Sandbox",
            session=owner_session("acct_other"),
            transactions_table=bindings,
            entitlements_table=entitlements,
            verifier=verifier,
        )


def test_family_notification_projects_six_seats_after_client_binding_exists():
    bindings = FakeTable("original_transaction_id")
    entitlements = FakeTable("profile_id")
    family_transaction = transaction(
        product_id="com.sumagang.kaevo.family.monthly",
        transaction_id="transaction-2",
        signed_date=3_000,
    )
    sync_signed_transaction(
        signed_transaction="signed-transaction",
        environment="Sandbox",
        session=owner_session(),
        transactions_table=bindings,
        entitlements_table=entitlements,
        verifier=FakeVerifier(transaction=transaction()),
    )
    notification = SimpleNamespace(
        rawNotificationType="DID_RENEW",
        signedDate=4_000,
        notificationUUID="notification-1",
        data=SimpleNamespace(
            signedTransactionInfo="signed-family-transaction",
            rawStatus=1,
        ),
    )

    result = process_signed_notification(
        signed_payload="signed-notification",
        environment="Sandbox",
        transactions_table=bindings,
        entitlements_table=entitlements,
        verifier=FakeVerifier(
            transaction=family_transaction,
            notification=notification,
        ),
    )

    assert result["entitlements"]["cloud_enabled"] is True
    assert result["entitlements"]["family_enabled"] is True
    assert result["entitlements"]["family_seats"] == 6
    assert bindings.items["original-1"]["last_notification_uuid"] == "notification-1"


def test_notification_without_prior_authenticated_binding_fails_closed():
    notification = SimpleNamespace(
        rawNotificationType="DID_RENEW",
        signedDate=4_000,
        notificationUUID="notification-1",
        data=SimpleNamespace(signedTransactionInfo="signed-transaction", rawStatus=1),
    )

    with pytest.raises(AppStoreBindingMissing):
        process_signed_notification(
            signed_payload="signed-notification",
            environment="Sandbox",
            transactions_table=FakeTable("original_transaction_id"),
            entitlements_table=FakeTable("profile_id"),
            verifier=FakeVerifier(
                transaction=transaction(),
                notification=notification,
            ),
        )


def test_verified_test_notification_is_acknowledged_without_a_transaction():
    result = process_signed_notification(
        signed_payload="signed-test-notification",
        environment="Production",
        transactions_table=FakeTable("original_transaction_id"),
        entitlements_table=FakeTable("profile_id"),
        verifier=FakeVerifier(
            notification=SimpleNamespace(rawNotificationType="TEST")
        ),
    )

    assert result == {"state": "test_notification_verified"}


def test_older_notification_cannot_overwrite_a_newer_projection():
    bindings = FakeTable("original_transaction_id")
    entitlements = FakeTable("profile_id")
    bindings.items["original-1"] = {
        "original_transaction_id": "original-1",
        "account_id": "acct_owner",
        "household_id": "household-1",
        "profile_id": "profile-owner",
        "environment": "Sandbox",
        "subscription_state": "active",
        "last_signed_date_ms": 9_000,
    }
    entitlements.items["profile-owner"] = {
        "profile_id": "profile-owner",
        "entitlements_json": "newer",
        "app_store_signed_date_ms": 9_000,
    }
    notification = SimpleNamespace(
        rawNotificationType="EXPIRED",
        signedDate=8_000,
        notificationUUID="notification-old",
        data=SimpleNamespace(signedTransactionInfo="signed-old", rawStatus=2),
    )

    result = process_signed_notification(
        signed_payload="signed-notification",
        environment="Sandbox",
        transactions_table=bindings,
        entitlements_table=entitlements,
        verifier=FakeVerifier(
            transaction=transaction(signed_date=7_000),
            notification=notification,
        ),
    )

    assert result == {
        "state": "stale_update_ignored",
        "subscription_state": "active",
    }
    assert entitlements.items["profile-owner"]["entitlements_json"] == "newer"


def test_unknown_product_is_rejected_after_signature_verification():
    with pytest.raises(
        AppStoreVerificationError,
        match="unsupported_subscription_product",
    ):
        sync_signed_transaction(
            signed_transaction="signed-transaction",
            environment="Sandbox",
            session=owner_session(),
            transactions_table=FakeTable("original_transaction_id"),
            entitlements_table=FakeTable("profile_id"),
            verifier=FakeVerifier(
                transaction=transaction(product_id="com.sumagang.kaevo.retired")
            ),
        )
