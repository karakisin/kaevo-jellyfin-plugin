using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static class KaevoPlaybackCompatibilityScanner
{
    internal static object Scan(JsonElement payload, int startIndex, int limit)
    {
        var sourceItems = payload.TryGetProperty("Items", out var items) && items.ValueKind == JsonValueKind.Array
            ? items.EnumerateArray().ToArray()
            : Array.Empty<JsonElement>();
        var results = sourceItems.Select(Classify).ToArray();
        var total = payload.TryGetProperty("TotalRecordCount", out var count) && count.TryGetInt32(out var value)
            ? value
            : startIndex + results.Length;

        return new
        {
            start_index = startIndex,
            limit,
            returned = results.Length,
            total_record_count = total,
            has_more = startIndex + results.Length < total,
            bounded = true,
            read_only = true,
            execution_enabled = false,
            summary = new
            {
                direct_play = results.Count(item => item.Recommendation == "direct_play"),
                h264_transcode = results.Count(item => item.Recommendation == "transcode_h264"),
                audio_transcode = results.Count(item => item.Recommendation == "transcode_audio"),
                manual_review = results.Count(item => item.Recommendation == "manual_review")
            },
            items = results.Select(item => new
            {
                item_id = item.ItemId,
                title = item.Title,
                show_name = item.ShowName,
                episode_name = item.EpisodeName,
                item_type = item.ItemType,
                container = item.Container,
                video_codec = item.VideoCodec,
                audio_codec = item.AudioCodec,
                audio_channels = item.AudioChannels,
                width = item.Width,
                height = item.Height,
                bitrate = item.Bitrate,
                recommendation = item.Recommendation,
                reason = item.Reason
            })
        };
    }

    internal static object PlanDirectPlay(JsonElement item, OptimizerPlan? executionPlan = null)
    {
        var result = Classify(item);
        var eligible = executionPlan?.UseProtectedOriginalAudio == true
            || result.Recommendation is "transcode_h264" or "transcode_audio";
        var steps = new List<string>();
        if (executionPlan?.Strategy == OptimizerConversionStrategy.FullVideo || (executionPlan is null && result.Recommendation == "transcode_h264"))
        {
            steps.Add("convert_video_to_h264");
        }
        if (executionPlan?.Strategy is OptimizerConversionStrategy.AudioOnly or OptimizerConversionStrategy.FullVideo
            || (executionPlan is null && (result.Recommendation == "transcode_audio" || result.AudioCodec is not "aac")))
        {
            steps.Add(executionPlan?.UseProtectedOriginalAudio == true
                ? "restore_audio_from_protected_original"
                : "convert_audio_to_aac");
        }
        if (executionPlan?.Strategy == OptimizerConversionStrategy.RemuxOnly || result.Container is not "mp4" and not "m4v")
        {
            steps.Add("package_as_mp4");
        }

        return new
        {
            item_id = result.ItemId,
            title = result.Title,
            plan_id = executionPlan?.PlanId,
            approval_token = executionPlan?.ApprovalToken,
            expires_at = executionPlan?.ExpiresAt,
            eligible,
            current = new
            {
                container = result.Container,
                video_codec = result.VideoCodec,
                audio_codec = result.AudioCodec,
                width = result.Width,
                height = result.Height,
                bitrate = result.Bitrate,
                recommendation = result.Recommendation,
                reason = result.Reason
            },
            target = new
            {
                container = "mp4",
                video_codec = executionPlan is null || executionPlan.Strategy == OptimizerConversionStrategy.FullVideo ? "h264" : result.VideoCodec,
                audio_codec = executionPlan?.Strategy == OptimizerConversionStrategy.RemuxOnly ? result.AudioCodec : "aac",
                method = executionPlan?.Strategy switch
                {
                    OptimizerConversionStrategy.RemuxOnly => "remux_only",
                    OptimizerConversionStrategy.AudioOnly => "copy_video_convert_audio",
                    _ => "full_video_conversion"
                },
                goal = "direct_play"
            },
            steps,
            safety = new
            {
                read_only_plan = true,
                execution_enabled = executionPlan is not null,
                single_title_only = true,
                original_preserved = true,
                disk_space_check_required = true,
                output_verification_required = true,
                source_bytes = executionPlan?.SourceBytes,
                available_bytes = executionPlan?.AvailableBytes
            },
            reason = eligible ? "direct_play_conversion_available" : result.Recommendation == "direct_play"
                ? "already_direct_play"
                : "manual_review_required"
        };
    }

    private static CompatibilityItem Classify(JsonElement item)
    {
        var streams = MediaStreams(item);
        var video = streams.FirstOrDefault(stream => String(stream, "Type").Equals("Video", StringComparison.OrdinalIgnoreCase));
        var audio = streams.FirstOrDefault(stream => String(stream, "Type").Equals("Audio", StringComparison.OrdinalIgnoreCase));
        var videoCodec = String(video, "Codec").ToLowerInvariant();
        var audioCodec = String(audio, "Codec").ToLowerInvariant();
        var audioChannels = Int(audio, "Channels");
        var container = Container(item).ToLowerInvariant();
        var width = Int(video, "Width");
        var height = Int(video, "Height");
        var bitrate = Int(video, "BitRate");
        if (bitrate <= 0 && item.TryGetProperty("MediaSources", out var mediaSources) && mediaSources.ValueKind == JsonValueKind.Array)
        {
            bitrate = Int(mediaSources.EnumerateArray().FirstOrDefault(), "Bitrate");
        }

        var recommendation = "manual_review";
        var reason = "metadata_incomplete";
        if (videoCodec is "hevc" or "h265" or "x265")
        {
            recommendation = "transcode_h264";
            reason = "direct_play_requires_h264";
        }
        else if (videoCodec is "av1" or "vp9" or "vp8")
        {
            recommendation = "transcode_h264";
            reason = "video_codec_requires_conversion";
        }
        else if (videoCodec is "h264" or "avc" or "mpeg4")
        {
            if (audioCodec is "truehd" or "dts" or "dca" or "mlp"
                || (audioCodec == "aac" && audioChannels > 2))
            {
                recommendation = "transcode_audio";
                reason = audioCodec == "aac"
                    ? "audio_channels_require_stereo_conversion"
                    : "audio_codec_requires_conversion";
            }
            else
            {
                recommendation = "direct_play";
                reason = "kaevo_compatible";
            }
        }

        var itemType = String(item, "Type");
        var episodeName = String(item, "Name");
        var showName = itemType.Equals("Episode", StringComparison.OrdinalIgnoreCase)
            ? String(item, "SeriesName")
            : string.Empty;
        var displayTitle = DisplayTitle(showName, episodeName);

        return new CompatibilityItem(
            String(item, "Id"),
            displayTitle,
            showName,
            episodeName,
            itemType,
            container,
            videoCodec,
            audioCodec,
            audioChannels,
            width,
            height,
            bitrate,
            recommendation,
            reason);
    }

    internal static string DisplayTitle(JsonElement item)
        => DisplayTitle(String(item, "SeriesName"), String(item, "Name"));

    internal static string DisplayTitle(string showName, string episodeName)
    {
        if (string.IsNullOrWhiteSpace(showName)) return episodeName;
        if (string.IsNullOrWhiteSpace(episodeName)) return showName;
        return $"{showName} — {episodeName}";
    }

    internal static OptimizerConversionDecision SelectConversion(JsonElement item)
    {
        var classified = Classify(item);
        var video = MediaStreams(item).FirstOrDefault(stream => String(stream, "Type").Equals("Video", StringComparison.OrdinalIgnoreCase));
        // Kaevo's physical iPhone validation found HEVC sources that AVPlayer
        // accepted and advanced while rendering no frames. Until the native
        // player validates HEVC profile/level per source, optimization must
        // match the proven playback policy and create H.264.
        var videoCanCopy = classified.VideoCodec is "h264" or "avc";
        // Stereo AAC-LC is the deliberately conservative common target for
        // iPhone and Apple TV. Multichannel AAC can probe as supported while
        // AVPlayer produces silence for some layouts, so downmix it explicitly.
        var audioCanCopy = classified.AudioCodec == "aac" && classified.AudioChannels is > 0 and <= 2;

        var strategy = videoCanCopy
            ? audioCanCopy ? OptimizerConversionStrategy.RemuxOnly : OptimizerConversionStrategy.AudioOnly
            : OptimizerConversionStrategy.FullVideo;
        return new OptimizerConversionDecision(strategy, classified.VideoCodec, classified.AudioCodec);
    }

    private static JsonElement[] MediaStreams(JsonElement item)
    {
        if (item.TryGetProperty("MediaStreams", out var direct) && direct.ValueKind == JsonValueKind.Array)
        {
            return direct.EnumerateArray().ToArray();
        }

        if (item.TryGetProperty("MediaSources", out var sources) && sources.ValueKind == JsonValueKind.Array)
        {
            var source = sources.EnumerateArray().FirstOrDefault();
            if (source.ValueKind == JsonValueKind.Object
                && source.TryGetProperty("MediaStreams", out var nested)
                && nested.ValueKind == JsonValueKind.Array)
            {
                return nested.EnumerateArray().ToArray();
            }
        }

        return Array.Empty<JsonElement>();
    }

    private static string Container(JsonElement item)
    {
        var direct = String(item, "Container");
        if (!string.IsNullOrWhiteSpace(direct))
        {
            return direct;
        }

        if (item.TryGetProperty("MediaSources", out var sources) && sources.ValueKind == JsonValueKind.Array)
        {
            return String(sources.EnumerateArray().FirstOrDefault(), "Container");
        }

        return string.Empty;
    }

    private static string String(JsonElement element, string property)
    {
        return element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(property, out var value)
            && value.ValueKind == JsonValueKind.String
                ? value.GetString() ?? string.Empty
                : string.Empty;
    }

    private static int Int(JsonElement element, string property)
        => element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(property, out var value)
            && value.TryGetInt32(out var result)
                ? result
                : 0;

    private sealed record CompatibilityItem(
        string ItemId,
        string Title,
        string ShowName,
        string EpisodeName,
        string ItemType,
        string Container,
        string VideoCodec,
    string AudioCodec,
    int AudioChannels,
        int Width,
        int Height,
        int Bitrate,
        string Recommendation,
        string Reason);
}

internal sealed record OptimizerConversionDecision(
    OptimizerConversionStrategy Strategy,
    string VideoCodec,
    string AudioCodec);
