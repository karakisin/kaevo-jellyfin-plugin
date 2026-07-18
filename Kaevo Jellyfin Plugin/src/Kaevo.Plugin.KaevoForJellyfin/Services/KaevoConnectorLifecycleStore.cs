using System.Security.Cryptography;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed record KaevoConnectorLifecycleState(
    string Environment,
    string ServerId,
    string ConnectorId = "",
    int CredentialVersion = 0,
    string CurrentKeyFile = "",
    string RecoveryKeyFile = "recovery-key.pem",
    string PendingKeyFile = "",
    string PendingOperation = "",
    string CurrentKeyThumbprint = "",
    string RecoveryKeyThumbprint = "",
    string State = "unenrolled");

public sealed class KaevoConnectorLifecycleStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _directory;
    private readonly string _statePath;
    private readonly string _environment;

    public KaevoConnectorLifecycleStore()
        : this(Path.Combine(KaevoPlugin.Instance?.DataFolderPath
            ?? throw new InvalidOperationException("Kaevo plugin data folder is unavailable."), "lifecycle"),
            Environment.GetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT")?.Trim() ?? "production")
    {
    }

    internal KaevoConnectorLifecycleStore(string directory, string environment)
    {
        _directory = directory;
        _statePath = Path.Combine(directory, "connector-state.json");
        _environment = environment;
        KaevoFilePermissions.OwnerOnlyDirectory(directory);
    }

    internal string DirectoryPath => _directory;
    internal string StatePath => _statePath;

    public async Task<KaevoConnectorLifecycleState> LoadOrInitializeAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (File.Exists(_statePath))
            {
                var state = JsonSerializer.Deserialize<KaevoConnectorLifecycleState>(await File.ReadAllBytesAsync(_statePath, cancellationToken).ConfigureAwait(false), JsonOptions)
                    ?? throw new InvalidOperationException("connectorLifecycleStateInvalid");
                if (!string.Equals(state.Environment, _environment, StringComparison.Ordinal)
                    || !state.ServerId.StartsWith("srv_", StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("connectorLifecycleEnvironmentMismatch");
                }
                KaevoFilePermissions.OwnerOnlyFile(_statePath);
                return state;
            }

            var initialized = new KaevoConnectorLifecycleState(
                _environment,
                "srv_" + KaevoConnectorIdentity.Base64Url(RandomNumberGenerator.GetBytes(32)));
            using var recovery = KaevoConnectorIdentity.LoadOrCreate(Path.Combine(_directory, initialized.RecoveryKeyFile));
            initialized = initialized with { RecoveryKeyThumbprint = recovery.Thumbprint };
            WriteState(initialized);
            return initialized;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<(KaevoConnectorLifecycleState State, KaevoConnectorIdentity Identity)> BeginTransitionAsync(string operation, CancellationToken cancellationToken = default)
    {
        if (operation is not ("pair" or "rotate" or "recover"))
        {
            throw new ArgumentException("connectorLifecycleOperationInvalid", nameof(operation));
        }
        var state = await LoadOrInitializeAsync(cancellationToken).ConfigureAwait(false);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!string.IsNullOrEmpty(state.PendingKeyFile))
            {
                throw new InvalidOperationException("connectorLifecycleTransitionPending");
            }
            var pendingName = $"connector-key-v{state.CredentialVersion + 1}.pending.pem";
            var identity = KaevoConnectorIdentity.LoadOrCreate(Path.Combine(_directory, pendingName));
            var pending = state with { PendingKeyFile = pendingName, PendingOperation = operation, State = operation + "_pending" };
            WriteState(pending);
            return (pending, identity);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<KaevoConnectorLifecycleState> CommitTransitionAsync(string connectorId, int credentialVersion, CancellationToken cancellationToken = default)
    {
        var state = await LoadOrInitializeAsync(cancellationToken).ConfigureAwait(false);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (string.IsNullOrEmpty(state.PendingKeyFile) || credentialVersion != state.CredentialVersion + 1)
            {
                throw new InvalidOperationException("connectorLifecycleVersionInvalid");
            }
            var pendingPath = Path.Combine(_directory, state.PendingKeyFile);
            using var identity = KaevoConnectorIdentity.LoadOrCreate(pendingPath);
            var finalName = $"connector-key-v{credentialVersion}.pem";
            var finalPath = Path.Combine(_directory, finalName);
            File.Move(pendingPath, finalPath, true);
            KaevoFilePermissions.OwnerOnlyFile(finalPath);
            var committed = state with
            {
                ConnectorId = connectorId,
                CredentialVersion = credentialVersion,
                CurrentKeyFile = finalName,
                PendingKeyFile = "",
                PendingOperation = "",
                CurrentKeyThumbprint = identity.Thumbprint,
                State = "active"
            };
            WriteState(committed);
            if (!string.IsNullOrEmpty(state.CurrentKeyFile) && !string.Equals(state.CurrentKeyFile, finalName, StringComparison.Ordinal))
            {
                SecureDelete(Path.Combine(_directory, state.CurrentKeyFile));
            }
            return committed;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<KaevoConnectorLifecycleState> AbortTransitionAsync(CancellationToken cancellationToken = default)
    {
        var state = await LoadOrInitializeAsync(cancellationToken).ConfigureAwait(false);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!string.IsNullOrEmpty(state.PendingKeyFile))
            {
                SecureDelete(Path.Combine(_directory, state.PendingKeyFile));
            }
            var restored = state with { PendingKeyFile = "", PendingOperation = "", State = state.CredentialVersion > 0 ? "active" : "unenrolled" };
            WriteState(restored);
            return restored;
        }
        finally
        {
            _gate.Release();
        }
    }

    public KaevoConnectorIdentity LoadCurrent(KaevoConnectorLifecycleState state)
    {
        if (state.CredentialVersion < 1 || string.IsNullOrEmpty(state.CurrentKeyFile))
        {
            throw new InvalidOperationException("lifecycle_upgrade_required");
        }
        return KaevoConnectorIdentity.LoadOrCreate(Path.Combine(_directory, state.CurrentKeyFile));
    }

    public KaevoConnectorIdentity LoadRecovery(KaevoConnectorLifecycleState state) =>
        KaevoConnectorIdentity.LoadOrCreate(Path.Combine(_directory, state.RecoveryKeyFile));

    public KaevoConnectorIdentity LoadPending(KaevoConnectorLifecycleState state)
    {
        if (string.IsNullOrEmpty(state.PendingKeyFile)) throw new InvalidOperationException("connectorLifecycleTransitionMissing");
        return KaevoConnectorIdentity.LoadOrCreate(Path.Combine(_directory, state.PendingKeyFile));
    }

    public async Task<KaevoConnectorLifecycleState> SetTerminalStateAsync(string terminalState, CancellationToken cancellationToken = default)
    {
        if (terminalState is not ("revoked" or "unpaired")) throw new ArgumentException("connectorLifecycleStateInvalid", nameof(terminalState));
        var state = await LoadOrInitializeAsync(cancellationToken).ConfigureAwait(false);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var updated = state with { State = terminalState, PendingKeyFile = "", PendingOperation = "" };
            WriteState(updated);
            return updated;
        }
        finally
        {
            _gate.Release();
        }
    }

    private void WriteState(KaevoConnectorLifecycleState state)
    {
        var temporary = Path.Combine(_directory, ".connector-state-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, state, JsonOptions);
                stream.Flush(true);
            }
            KaevoFilePermissions.OwnerOnlyFile(temporary);
            File.Move(temporary, _statePath, true);
            KaevoFilePermissions.OwnerOnlyFile(_statePath);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static void SecureDelete(string path)
    {
        if (!File.Exists(path)) return;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
            var zeros = new byte[Math.Min(4096, checked((int)Math.Min(stream.Length, 4096)))];
            long remaining = stream.Length;
            while (remaining > 0)
            {
                var count = (int)Math.Min(zeros.Length, remaining);
                stream.Write(zeros, 0, count);
                remaining -= count;
            }
            stream.Flush(true);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
