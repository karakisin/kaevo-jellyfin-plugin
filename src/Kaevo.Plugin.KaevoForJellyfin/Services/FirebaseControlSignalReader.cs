using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// Local transport preparation only: not selected by RunControlLoopAsync.
// A signal is a hint, never a claim, provider payload, or permission to execute.
// The eventual adapter must authenticate an exact channel, reject redirects,
// redact credential-bearing URLs and recheck every hint through signed claim.
internal static class FirebaseControlSignalReader
{
    internal const int MaximumEventCharacters = 65_536;
    internal const int MaximumSignalsPerEvent = 64;

    internal static async IAsyncEnumerable<string> ReadAsync(
        Stream stream, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // Throw on corrupt UTF-8. Leave the caller-owned response stream open.
        using var reader = new StreamReader(stream, new UTF8Encoding(false, true),
            detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
        var buffer = new char[1024];
        var line = new StringBuilder();
        var data = new StringBuilder();
        string? eventType = null;
        var eventCharacters = 0;
        while (true)
        {
            int count;
            try { count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false); }
            catch (DecoderFallbackException) { throw Invalid(); }
            if (count == 0)
            {
                if (line.Length != 0 || data.Length != 0 || eventType is not null)
                    throw Invalid(); // Never emit an incomplete event at EOF.
                yield break;
            }
            for (var index = 0; index < count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++eventCharacters > MaximumEventCharacters) throw Invalid();
                var character = buffer[index];
                if (character != '\n')
                {
                    line.Append(character);
                    continue;
                }
                var value = line.ToString().TrimEnd('\r');
                line.Clear();
                if (value.Length == 0)
                {
                    // Validate the ENTIRE event before exposing even one hint.
                    var hints = Decode(eventType, data.ToString());
                    eventType = null;
                    data.Clear();
                    eventCharacters = 0;
                    foreach (var hint in hints) yield return hint;
                    continue;
                }
                if (value.StartsWith(':')) continue;
                var separator = value.IndexOf(':');
                if (separator < 0) throw Invalid();
                var field = value[..separator];
                var content = value[(separator + 1)..];
                if (content.StartsWith(' ')) content = content[1..];
                if (field == "event" && eventType is null) eventType = content;
                else if (field == "data") data.Append(content).Append('\n');
                else throw Invalid();
            }
        }
    }

    private static List<string> Decode(string? eventType, string data)
    {
        if (eventType is null && data.Length == 0) return [];
        if (eventType is "cancel" or "auth_revoked")
            throw new InvalidOperationException("firebaseControlPermissionLost");
        try
        {
            using var document = JsonDocument.Parse(data, new JsonDocumentOptions { MaxDepth = 8 });
            if (eventType == "keep-alive" && document.RootElement.ValueKind == JsonValueKind.Null) return [];
            if (eventType is not ("put" or "patch")) throw Invalid();
            var root = document.RootElement;
            ExactFields(root, "path", "data");
            var path = root.GetProperty("path").GetString();
            var value = root.GetProperty("data");
            var result = new List<string>();
            if (path == "/")
            {
                if (value.ValueKind == JsonValueKind.Null) return result;
                if (value.ValueKind != JsonValueKind.Object) throw Invalid();
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var child in value.EnumerateObject())
                {
                    if (!seen.Add(child.Name) || seen.Count > MaximumSignalsPerEvent) throw Invalid();
                    AddHint(child.Name, child.Value, result);
                }
            }
            else if (path is not null && path.StartsWith('/') && !path[1..].Contains('/') && eventType == "put")
                AddHint(path[1..], value, result);
            else throw Invalid(); // Partial/nested patches require recovery, not guessed merges.
            return result;
        }
        catch (JsonException) { throw Invalid(); }
        catch (InvalidOperationException error) when (error.Message != "firebaseControlSignalInvalid")
        { throw Invalid(); }
        catch (FormatException) { throw Invalid(); }
    }

    private static void AddHint(string key, JsonElement value, List<string> result)
    {
        // Server encodes an ASCII request ID as lowercase hex for an RTDB key.
        if (key.Length is < 2 or > 256 || key.Length % 2 != 0
            || key.Any(character => !(character is >= '0' and <= '9' or >= 'a' and <= 'f')))
            throw Invalid();
        var bytes = Convert.FromHexString(key);
        if (bytes.Any(character => character > 127)) throw Invalid();
        var requestId = Encoding.ASCII.GetString(bytes);
        if (!char.IsAsciiLetterOrDigit(requestId[0])
            || !KaevoCloudConnectorService.IsSafeControlRequestId(requestId)) throw Invalid();
        if (value.ValueKind == JsonValueKind.Null) return; // Exact signal deletion, never a request.
        ExactFields(value, "type", "request_id", "connector_control_protocol");
        if (value.GetProperty("type").GetString() != "remote_request_available"
            || value.GetProperty("request_id").GetString() != requestId
            || !value.GetProperty("connector_control_protocol").TryGetInt32(out var protocol)
            || protocol != 2) throw Invalid();
        result.Add(requestId);
    }

    private static void ExactFields(JsonElement element, params string[] fields)
    {
        if (element.ValueKind != JsonValueKind.Object) throw Invalid();
        var remaining = new HashSet<string>(fields, StringComparer.Ordinal);
        foreach (var field in element.EnumerateObject())
            if (!remaining.Remove(field.Name)) throw Invalid();
        if (remaining.Count != 0) throw Invalid();
    }

    private static InvalidOperationException Invalid() => new("firebaseControlSignalInvalid");
}
