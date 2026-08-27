import pytest

from account_lifecycle_v2_status_token import (
    LifecycleV2StatusTokenCodec,
    LifecycleV2StatusTokenError,
)


def test_status_token_is_operation_and_account_scoped():
    codec = LifecycleV2StatusTokenCodec("s" * 64, clock=lambda: 100)
    token = codec.issue(operation_id="ald2_operation", account_id="acct_account")

    assert codec.verify(token, expected_operation_id="ald2_operation")["account_id"] == "acct_account"


def test_status_token_rejects_operation_substitution_and_expiration():
    issuer = LifecycleV2StatusTokenCodec("s" * 64, clock=lambda: 100, ttl_seconds=10)
    token = issuer.issue(operation_id="ald2_operation", account_id="acct_account")

    with pytest.raises(LifecycleV2StatusTokenError):
        issuer.verify(token, expected_operation_id="ald2_other")
    expired = LifecycleV2StatusTokenCodec("s" * 64, clock=lambda: 111)
    with pytest.raises(LifecycleV2StatusTokenError):
        expired.verify(token, expected_operation_id="ald2_operation")
