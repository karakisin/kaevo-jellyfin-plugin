# Kaevo Travel Downloads — Product Spec

## Feature name

**Travel Downloads**

## Helper name

**Kaevo Assist**

## One-line description

Travel Downloads prepares movies and shows for offline watching by letting the user choose a mobile-friendly quality, remember their last setup, and optionally allow Kaevo Assist to recover safe download issues.

## Product promise

Kaevo makes offline downloads understandable for normal users:

- More episodes with 480p.
- Better phone quality with 720p.
- Larger-screen quality with 1080p when available.
- Original quality when the user wants the full file.
- No hidden downgrades.
- No media hosted by Kaevo Cloud.

## Architecture rule

Kaevo Cloud is a coordinator only.

Cloud can store:

- user/profile preference metadata
- selected quality
- job status
- retry count
- failure reason
- notification preference
- audit metadata

Cloud must not store:

- media files
- preview frames
- transcoded files
- provider API keys in Apple clients
- direct server credentials in the app

Actual media work happens through:

1. Existing Jellyfin capabilities, where possible.
2. Future Kaevo Local Bridge running on the user's home server.

## Supported content

Travel Downloads should eventually support:

- movie
- TV episode
- multiple episodes
- full season
- mixed batch of movies and episodes

MVP can start with movies and individual episodes.

## Dynamic quality options

Kaevo should inspect source quality first and only show sensible choices.

| Source quality | Options shown |
|---|---|
| 4K / 2160p | 480p, 720p, 1080p, Original 4K |
| 1080p | 480p, 720p, Original 1080p |
| 720p | 480p, Original 720p |
| 480p or lower | Original |
| Unknown | 480p, 720p, Original, with estimates marked uncertain |

Do not show duplicate quality choices. If the source is 720p, do not show a separate 720p option. That is just Original.

## Quality option user meaning

### Storage Saver 480p

Best for users who want more episodes, faster downloads, smaller phone storage use, or kids/travel downloads.

### Recommended 720p

Best default for most phone users.

### High Quality 1080p

Best for iPad, hotel TV, larger screens, or premium users downloading from 4K sources.

### Original Quality

Best quality, largest file, least predictable transfer time. No preparation needed if the source file is already playable/downloadable.

## Use Last Setup behavior

When the user starts another Travel Download and `useLastSetup` is enabled, Kaevo should show:

```text
Use your last Travel Download setup?

Last time you chose:
720p Recommended
Kaevo Assist: Retry safe issues automatically
Notifications: On

Use Last Setup
Change for This Download
Ask Me Every Time

You can change this anytime in Settings > Downloads > Travel Downloads.
```

Rules:

- `Use Last Setup` continues with saved last setup.
- `Change for This Download` shows the full quality and issue-handling flow.
- `Ask Me Every Time` saves the preference and always shows full options on future downloads.
- Last setup should update after a successful job is started or after the user confirms the setup, not after a failed accidental tap.

## Settings location

```text
Settings > Downloads > Travel Downloads
```

## Settings for MVP

- Default Quality
- Use Last Setup
- Download Issue Handling
- Notifications
- Suggest Smaller Quality If Download Fails

## Future settings

- Cellular downloads
- Storage cleanup
- Auto-remove watched downloads after sync
- Generate preview comparison frames
- Travel mode defaults per profile
- Kids profile quality cap

## Kaevo Assist modes

### Kaevo Assist Recommended

Kaevo can retry safe download issues automatically and notify the user if something needs attention.

### Ask Before Fixing

Kaevo detects the issue, explains it, and asks before trying to fix it.

### Manual

Kaevo shows the issue only. The user handles it.

### Ask Every Time

Kaevo asks how to handle issues for every Travel Download.

## Kaevo Assist hard limits

Kaevo Assist must never silently downgrade quality, delete original media, change Jellyfin library paths, or change Sonarr/Radarr provider settings.

## Estimate strategy

Kaevo should show estimates, not promises.

For prepared versions:

```text
Preparing on home server: about 12 minutes
Downloading to phone: about 6 minutes
Total: about 18 minutes
```

For original:

```text
Preparing: Not needed
Downloading to phone: about 1 hour 20 minutes
```

## MVP recommendation

Build the foundation in this order:

1. Settings model.
2. Settings UI.
3. Dynamic quality option logic.
4. Last setup flow.
5. Placeholder estimate model.
6. Job model.
7. Kaevo Assist modes.
8. Tests.
9. Documentation.

Do not build actual transcoding or file transfer yet.
