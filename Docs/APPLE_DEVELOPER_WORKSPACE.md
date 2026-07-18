# Apple Developer workspace

The canonical active source is `/Volumes/Apple Developer/StageDoorNative`. The encrypted `Apple Developer` volume must be mounted and unlocked before builds or scripts run. The internal source remains a temporary rollback copy and is not replaced by a symlink.

Cloud scripts derive `Kaevo Cloud` from their own location, so repository-local operations need no environment variables and work from unrelated current directories. Supported explicit roots are `KAEVO_WORKSPACE_ROOT`, `KAEVO_SOURCE_ROOT`, `KAEVO_CLOUD_ROOT`, `KAEVO_SECURITY_ROOT`, `KAEVO_ROLLBACK_ROOT`, `KAEVO_BUILD_ROOT`, and `KAEVO_TEMP_ROOT`. `KAEVO_CLOUD_ROOT` overrides the derived Cloud root and must contain `infra/template.yaml`. `KAEVO_TEMP_ROOT` must already exist and redirects provider-test output beneath `provider-tests`.

Recommended session values are:

```bash
export KAEVO_WORKSPACE_ROOT="/Volumes/Apple Developer"
export KAEVO_SOURCE_ROOT="$KAEVO_WORKSPACE_ROOT/StageDoorNative"
export KAEVO_CLOUD_ROOT="$KAEVO_SOURCE_ROOT/Kaevo Cloud"
export KAEVO_SECURITY_ROOT="$KAEVO_WORKSPACE_ROOT/KaevoSecurity"
export KAEVO_ROLLBACK_ROOT="$KAEVO_WORKSPACE_ROOT/KaevoRollback"
export KAEVO_BUILD_ROOT="$KAEVO_WORKSPACE_ROOT/KaevoBuilds"
export KAEVO_TEMP_ROOT="$KAEVO_WORKSPACE_ROOT/Temporary"
```

Use `/Volumes/Apple Developer/DerivedData` and `/Volumes/Apple Developer/ResultBundles` explicitly for Xcode output. Historical evidence retains its original absolute paths and must not be rewritten merely because the active workspace moved.
