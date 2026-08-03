# Household Join Negative-Scenario Coverage

This matrix records deterministic evidence available before Fixture B.  It
does not turn a unit test into a claim of physical-device coverage.  The live
matrix is deliberately limited to scenarios that require real Cognito,
HTTP-API, or device lifecycle behavior.

| Boundary | Negative conditions covered deterministically | Primary direct evidence | Status |
|---|---|---|---|
| Invitation input and lookup | malformed code; lowercase/whitespace canonicalization; nonexistent invitation; expired invitation; consumed invitation | `test_household_join_fixture.py` canonicalization/rejection tests; `test_household_join_routing_contract.py`; `test_household_join_completion_conflicts.py` | PASS |
| Invitation ownership | wrong household; replayed invitation; multiple `/begin`; one routed transaction; abandoned/expired transaction | `test_household_invitation_contract.py:test_parent_managed_profile_rejects_adult_and_cross_household_binding`; `test_household_join_expiry_contract.py`; `test_isolated_household_join_contract.py` route-auth retry test | PASS |
| Route authentication | missing state/challenge/nonce; state mismatch; route-auth replay; provider-account enumeration; bounded retry | `test_isolated_household_join_contract.py:test_route_auth_retries_only_the_same_nonce_and_authorize_uses_stored_nonce`; `test_household_join_routing_contract.py` | PASS |
| OAuth authorization-code handoff | callback route validation; provider error safety; token-exchange failure recovery; PKCE S256; unsupported/missing challenge; reused code rejection | `test_isolated_household_join_contract.py:test_route_auth_returns_one_kaevo_continuation_shape`; iOS `KaevoOIDCContractTests.swift` and `KaevoAppEntryPolicyTests.swift` | PASS — 57/57 focused physical-iOS tests (2026-07-28) |
| OIDC validation | nonce mismatch; issuer mismatch; audience/client mismatch; expired token; signature/claims failure | `test_production_identity_contract.py:test_id_token_wrong_issuer_client_and_schema_are_rejected`; `...:test_expired_and_future_access_tokens_are_rejected`; iOS `KaevoOIDCContractTests.swift` | PASS — Cloud and 57/57 focused physical-iOS tests (2026-07-28) |
| DPoP proof | missing/malformed proof; wrong key; wrong `htu`; wrong method; stale/future `iat`; repeated `jti`; token-key binding | `test_household_join_dpop_negative_contract.py`; `test_production_identity_contract.py:test_stolen_access_token_fails_with_another_installation_key`; `...:test_dpop_replay_is_rejected` | PASS |
| Session and installation | expired/revoked session; another device/installation; subject mismatch | `test_cloud_trial_session_contract.py:test_expired_or_wrong_app_session_is_rejected`; `test_production_identity_contract.py`; `test_isolated_household_join_contract.py:test_onboarding_status_401_emits_one_safe_dpop_reason_without_secret_material` | PASS |
| Object authorization | another account reading/completing Join; another household setup; unrelated profile mapping/binding/entitlement; installation reassignment; pending-pointer takeover; cross-household profile creation | `test_production_identity_contract.py:test_cross_household_target_does_not_leak_existence`; `test_account_foundation_contract.py` mapping/membership tests; `test_household_join_completion_conflicts.py` | PASS |
| Completion idempotency | duplicate `/complete`; duplicate Profile Setup; duplicate installation registration; response loss after complete/Profile Setup/installation | `test_account_foundation_contract.py:test_profile_binding_is_idempotent_concurrent_and_never_reactivates`; `test_household_join_completion_conflicts.py`; iOS recovery/mapping-store tests | PASS — Cloud and 57/57 focused physical-iOS tests (2026-07-28) |
| Recovery lifecycle | relaunch after acceptance; relaunch/bootstrap network loss; bootstrap retry without OAuth; Profile Setup recovery with same profile; account/household switch during recovery | `test_isolated_household_join_contract.py:test_pending_recovery_is_a_direct_subject_and_device_pointer_without_scan`; iOS `KaevoAppEntryPolicyTests.swift`, `KaevoPendingOnboardingIntentStoreTests.swift`, `KaevoCloudProfileMappingStoreTests.swift` | PASS — 57/57 focused physical-iOS tests (2026-07-28) |
| Cleanup safety | crash before delete; crash after delete before journal; crash after journal before verification; conditional mismatch; transport ambiguity; already absent/TTL/Cognito/credential absence; manifest failure; shared-resource protection; attribution ambiguity; restart; exact absence | `test_household_join_fixture.py`; `test_household_join_cleanup_request.py`; fixture cleanup journal evidence | PASS |

## Coverage disposition

All Cloud-side launch-critical conditions above have executable deterministic
coverage.  The selected iOS suites also passed 57/57 on the physical Debug
device on 2026-07-28. Their physical-device manifestations remain Fixture-B
or focused live negative-scenario candidates, not reasons to create an extra
fixture now.

The only remaining live-only candidates are exactly: a real managed-login
callback/relaunch, a controlled network interruption during bootstrap, and an
isolated response-loss observation after a committed protected mutation.  Each
requires a disposable manifest and exact cleanup; none is performed against a
personal account.
