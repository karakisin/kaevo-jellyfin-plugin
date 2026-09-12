using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// Records only that this exact verification reached the unbind boundary.
// It permits another absence READ after a lost reply, never another DELETE.
// Every retry still queries Jellyfin before reporting current absence.
internal sealed class KaevoAccountDeletionVerificationStore
{
    private readonly string _directory;

    internal KaevoAccountDeletionVerificationStore(string directory)
    {
        _directory = directory;
        KaevoFilePermissions.OwnerOnlyDirectory(directory);
    }

    private static string Digest(KaevoCloudConnectorService.AccountLifecycleV2CommandContext context) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new[]
        {
            "kaevo-deletion-verification-v1", context.OperationId, context.LifecycleBindingId,
            context.ConnectorId, context.ProfileId, context.JellyfinUserId
        }))).ToLowerInvariant();

    internal bool Contains(KaevoCloudConnectorService.AccountLifecycleV2CommandContext context)
    {
        var digest = Digest(context);
        var path = Path.Combine(_directory, digest + ".verified");
        if (!File.Exists(path)) return false;
        if (new FileInfo(path).Length != 65
            || File.ReadAllText(path, Encoding.ASCII) != digest + "\n")
            throw new InvalidOperationException("accountLifecycleV2VerificationStoreInvalid");
        return true;
    }

    internal void RecordBeforeUnbind(KaevoCloudConnectorService.AccountLifecycleV2CommandContext context)
    {
        if (Contains(context)) return;
        var digest = Digest(context);
        var path = Path.Combine(_directory, digest + ".verified");
        var temporary = Path.Combine(_directory, Guid.NewGuid().ToString("N") + ".pending");
        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write,
                Share = FileShare.None, Options = FileOptions.WriteThrough
            };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temporary, options))
            {
                stream.Write(Encoding.ASCII.GetBytes(digest + "\n"));
                stream.Flush(flushToDisk: true);
            }
            try { File.Move(temporary, path, overwrite: false); }
            catch (IOException) when (Contains(context)) { /* An identical verification won. */ }
            KaevoFilePermissions.OwnerOnlyFile(path);
            if (!Contains(context)) throw new IOException("accountLifecycleV2VerificationNotSaved");
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }
}
