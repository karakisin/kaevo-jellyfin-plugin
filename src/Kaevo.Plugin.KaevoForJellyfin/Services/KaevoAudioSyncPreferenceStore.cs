using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

/// Durable preferences only. Slider movement never invokes a server encoder.
public sealed class KaevoAudioSyncPreferenceStore
{
    private readonly string _directory;
    private readonly object _gate = new();
    public KaevoAudioSyncPreferenceStore() : this(Path.Combine(
        KaevoPlugin.Instance?.DataFolderPath ?? throw new InvalidOperationException("pluginDataUnavailable"),
        "audio-sync-preferences-v1")) { }
    internal KaevoAudioSyncPreferenceStore(string directory)
    {
        _directory = directory;
        Directory.CreateDirectory(directory);
        KaevoFilePermissions.OwnerOnlyDirectory(directory);
    }

    internal sealed record Preference(int Version, string Key, int OffsetMs);
    internal static string Key(string connector, string account, string profile, string item, string scope)
    {
        if (new[] { connector, account, profile }.Any(value => !Regex.IsMatch(value ?? "", @"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z"))
            || !Regex.IsMatch(item ?? "", @"\A[0-9a-fA-F]{32}\z") || scope is not ("user" or "account"))
            throw new InvalidOperationException("audioSyncScopeInvalid");
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new[] {
            "audio-sync-v1", connector, account, scope, scope == "user" ? profile : "", item.ToLowerInvariant()
        }))).ToLowerInvariant();
    }
    internal int? Read(string key)
    {
        lock (_gate) return ReadLocked(key);
    }
    private int? ReadLocked(string key)
    {
        if (!Regex.IsMatch(key, @"\A[0-9a-f]{64}\z")) throw new InvalidOperationException("audioSyncKeyInvalid");
        var path = Path.Combine(_directory, key + ".json");
        if (!File.Exists(path)) return null;
        if (new FileInfo(path).Length > 1024) throw new InvalidOperationException("audioSyncStoreInvalid");
        var value = JsonSerializer.Deserialize<Preference>(File.ReadAllText(path));
        if (value is null || value.Version != 1 || value.Key != key || value.OffsetMs is < -20000 or > 20000)
            throw new InvalidOperationException("audioSyncStoreInvalid");
        return value.OffsetMs;
    }
    internal int Write(string key, int offset)
    {
        if (offset is < -20000 or > 20000) throw new InvalidOperationException("audioSyncOffsetInvalid");
        lock (_gate)
        {
            _ = ReadLocked(key); // Validate key and existing record; never hide corruption.
            var path = Path.Combine(_directory, key + ".json");
            if (!File.Exists(path) && Directory.EnumerateFiles(_directory, "*.json").Take(100000).Count() >= 100000)
                throw new InvalidOperationException("audioSyncStoreFull");
            var temporary = Path.Combine(_directory, Guid.NewGuid().ToString("N") + ".pending");
            try
            {
                var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write,
                    Share = FileShare.None, Options = FileOptions.WriteThrough };
                if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                using (var stream = new FileStream(temporary, options))
                {
                    JsonSerializer.Serialize(stream, new Preference(1, key, offset));
                    stream.Flush(flushToDisk: true);
                }
                File.Move(temporary, path, overwrite: true);
                KaevoFilePermissions.OwnerOnlyFile(path);
                if (ReadLocked(key) != offset) throw new IOException("audioSyncWriteUnconfirmed");
                return offset;
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }
}
