import json
from types import SimpleNamespace

from account_lifecycle_v2_registry_sync import ExactLifecycleV2ProviderRegistrySync


ACCOUNT_ID = "acct_0123456789abcdef01234567"
PROFILE_ID = "profile_0123456789abcdef"


class ReadTable:
    def __init__(self, key, items):
        self.key = key
        self.items = {item[key]: dict(item) for item in items}

    def get_item(self, *, Key, ConsistentRead):
        assert ConsistentRead is True
        item = self.items.get(Key[self.key])
        return {"Item": dict(item)} if item else {}


class Client:
    def __init__(self):
        self.transactions = []

    def transact_write_items(self, *, TransactItems):
        self.transactions.append(TransactItems)


class Lifecycle:
    name = "lifecycle"

    def __init__(self):
        self.meta = SimpleNamespace(client=Client())


def records():
    return [
        {
            "account_id": ACCOUNT_ID, "record_key": "root",
            "record_type": "account_lifecycle_root", "revision": 3,
            "state": "active", "account_role": "owner",
            "owner_deletion_state": "sole_member",
        },
        {
            "account_id": ACCOUNT_ID, "record_key": "resource#identity_profile#one",
            "record_type": "account_lifecycle_resource",
            "resource_type": "identity_profile", "resource_id": PROFILE_ID,
            "state": "active",
        },
    ]


def test_exact_profile_and_signed_connector_capability_are_registered():
    lifecycle = Lifecycle()
    profiles = ReadTable("profile_id", [{
        "profile_id": PROFILE_ID,
        "account_id": ACCOUNT_ID,
        "state": "active",
        "jellyfin_binding_state": "active",
        "jellyfin_connector_id": "connector-1",
        "jellyfin_user_id": "0123456789abcdef0123456789abcdef",
        "seerr_binding_state": "active",
        "seerr_connector_id": "connector-1",
        "seerr_jellyfin_user_id": "0123456789abcdef0123456789abcdef",
        "seerr_user_id": "42",
    }])
    connectors = ReadTable("connector_id", [{
        "connector_id": "connector-1",
        "protocol_version": "kaevo-pairing-v3",
        "state": "active",
        "auth_state": "v3_active",
        "revoked": False,
        "last_seen_epoch": 1_800_000_000,
        "provider_status_json": json.dumps({
            "profile_deletion": {"configured": True, "ok": True, "reason": None},
        }),
    }])
    sync = ExactLifecycleV2ProviderRegistrySync(
        lifecycle_table=lifecycle,
        identity_profiles_table=profiles,
        home_connectors_table=connectors,
        clock=lambda: 1_800_000_000,
    )

    sync.synchronize(account_id=ACCOUNT_ID, registry_records=records())

    transaction = lifecycle.meta.client.transactions[0]
    resource = transaction[0]["Put"]["Item"]
    assert resource["resource_type"] == "provider_binding"
    assert resource["attributes"] == {
        "profile_id": PROFILE_ID,
        "connector_id": "connector-1",
        "jellyfin_user_id": "0123456789abcdef0123456789abcdef",
        "seerr_user_id": "42",
        "two_way_profile_deletion": "enabled",
    }


def test_no_provider_edge_creates_no_deletion_authority():
    lifecycle = Lifecycle()
    sync = ExactLifecycleV2ProviderRegistrySync(
        lifecycle_table=lifecycle,
        identity_profiles_table=ReadTable("profile_id", [{
            "profile_id": PROFILE_ID, "account_id": ACCOUNT_ID, "state": "active",
        }]),
        home_connectors_table=ReadTable("connector_id", []),
        clock=lambda: 1_800_000_000,
    )

    sync.synchronize(account_id=ACCOUNT_ID, registry_records=records())

    assert lifecycle.meta.client.transactions == []
