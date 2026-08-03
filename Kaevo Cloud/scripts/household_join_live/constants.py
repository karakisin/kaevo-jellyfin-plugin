"""Stable, non-secret bindings for the development-only fixture preflight."""

from __future__ import annotations

AWS_PROFILE = "kaevo-dev"
AWS_REGION = "us-west-2"
AWS_ACCOUNT_ID = "295055514343"
STACK_NAME = "kaevo-cloud-dev"
FIXTURE_ROOT = "/Volumes/Apple Developer/Kaevo Pairing V3/.kaevo-household-join-fixtures"
JOIN_LOGICAL_ID = "KaevoHouseholdJoinFunction"
JOIN_TRANSACTIONS_LOGICAL_ID = "KaevoHouseholdJoinTransactionsTable"
JOIN_TRANSACTION_INVITATION_INDEX = "invitation_id-created_at_epoch-index"

# These are exact logical IDs, not name fragments.  The Lambda configuration
# must bind every one to the matching stack resource before any live mutation
# could be considered.
TABLE_BINDINGS = {
    "HOUSEHOLD_JOIN_TRANSACTIONS_TABLE": "KaevoHouseholdJoinTransactionsTable",
    "HOUSEHOLD_INVITATIONS_TABLE": "KaevoHouseholdInvitationsTable",
    "PRINCIPALS_TABLE": "KaevoPrincipalsTable",
    "IDENTITY_MEMBERSHIPS_TABLE": "KaevoIdentityMembershipsTable",
    "IDENTITY_PROFILES_TABLE": "KaevoIdentityProfilesTable",
    "ACCOUNTS_TABLE": "KaevoAccountsTable",
    "AUTH_IDENTITIES_TABLE": "KaevoAuthIdentitiesTable",
    "HOUSEHOLD_MEMBERSHIPS_TABLE": "KaevoHouseholdMembershipsTable",
    "CLOUD_PROFILES_TABLE": "KaevoProfilesTable",
    "PROFILE_BINDINGS_TABLE": "KaevoProfileBindingsTable",
    "PROFILE_MAPPINGS_TABLE": "KaevoProfileMappingsTable",
    "ENTITLEMENTS_TABLE": "KaevoEntitlementsTable",
}

SAFE_FAILURE_UNQUERYABLE = "UNQUERYABLE_WITHOUT_SCAN"
SAFE_FAILURE_PREFLIGHT = "PREFLIGHT_FAILED"
