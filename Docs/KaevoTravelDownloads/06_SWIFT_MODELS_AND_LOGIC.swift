import Foundation

// MARK: - Travel Download Quality

public enum TravelDownloadQuality: String, Codable, CaseIterable, Equatable, Sendable {
    case smart
    case p480
    case p720
    case p1080
    case original
    case askEveryTime

    public var sortRank: Int {
        switch self {
        case .smart: return 0
        case .p480: return 480
        case .p720: return 720
        case .p1080: return 1080
        case .original: return 9999
        case .askEveryTime: return 10_000
        }
    }
}

public enum TravelDownloadIssueHandlingMode: String, Codable, CaseIterable, Equatable, Sendable {
    case kaevoAssist
    case askBeforeFixing
    case manual
    case askEveryTime
}

public enum SuggestLowerQualityPolicy: String, Codable, CaseIterable, Equatable, Sendable {
    case askFirst
    case never
}

public enum TravelDownloadJobStatus: String, Codable, CaseIterable, Equatable, Sendable {
    case queued
    case preparing
    case readyToDownload
    case downloading
    case paused
    case completed
    case failed
    case cancelled
    case expired
}

public enum TravelDownloadPrepareStatus: String, Codable, CaseIterable, Equatable, Sendable {
    case waiting
    case notNeeded
    case running
    case completed
    case failed
}

public enum TravelDownloadTransferStatus: String, Codable, CaseIterable, Equatable, Sendable {
    case notStarted
    case running
    case paused
    case completed
    case failed
}

public enum TravelDownloadFailureReason: String, Codable, CaseIterable, Equatable, Sendable {
    case serverOffline
    case insufficientPhoneStorage
    case insufficientServerStorage
    case prepareFailed
    case downloadInterrupted
    case networkTooSlow
    case fileValidationFailed
    case unsupportedSource
    case permissionDenied
    case unknown
}

public enum TravelDownloadMediaProvider: String, Codable, CaseIterable, Equatable, Sendable {
    case jellyfin
    case kaevoLocal
}

public enum TravelDownloadMediaType: String, Codable, CaseIterable, Equatable, Sendable {
    case movie
    case episode
    case season
    case batch
}

// MARK: - Settings

public struct TravelDownloadSettings: Codable, Equatable, Sendable {
    public var enabled: Bool
    public var defaultQualityMode: TravelDownloadQuality
    public var useLastSetup: Bool
    public var askEveryTime: Bool
    public var issueHandlingMode: TravelDownloadIssueHandlingMode
    public var notifyIssues: Bool
    public var suggestLowerQualityOnFailure: SuggestLowerQualityPolicy
    public var maxRetryCount: Int
    public var allowCellularDownloads: Bool
    public var lastSetup: LastTravelDownloadSetup?

    public init(
        enabled: Bool = true,
        defaultQualityMode: TravelDownloadQuality = .smart,
        useLastSetup: Bool = true,
        askEveryTime: Bool = false,
        issueHandlingMode: TravelDownloadIssueHandlingMode = .kaevoAssist,
        notifyIssues: Bool = true,
        suggestLowerQualityOnFailure: SuggestLowerQualityPolicy = .askFirst,
        maxRetryCount: Int = 3,
        allowCellularDownloads: Bool = false,
        lastSetup: LastTravelDownloadSetup? = nil
    ) {
        self.enabled = enabled
        self.defaultQualityMode = defaultQualityMode
        self.useLastSetup = useLastSetup
        self.askEveryTime = askEveryTime
        self.issueHandlingMode = issueHandlingMode
        self.notifyIssues = notifyIssues
        self.suggestLowerQualityOnFailure = suggestLowerQualityOnFailure
        self.maxRetryCount = max(0, maxRetryCount)
        self.allowCellularDownloads = allowCellularDownloads
        self.lastSetup = lastSetup
    }

    public static let `default` = TravelDownloadSettings()
}

public struct LastTravelDownloadSetup: Codable, Equatable, Sendable {
    public var quality: TravelDownloadQuality
    public var sourceQuality: SourceQualityLabel
    public var issueHandlingMode: TravelDownloadIssueHandlingMode
    public var notifyIssues: Bool
    public var usedAt: Date

    public init(
        quality: TravelDownloadQuality,
        sourceQuality: SourceQualityLabel,
        issueHandlingMode: TravelDownloadIssueHandlingMode,
        notifyIssues: Bool,
        usedAt: Date = Date()
    ) {
        self.quality = quality
        self.sourceQuality = sourceQuality
        self.issueHandlingMode = issueHandlingMode
        self.notifyIssues = notifyIssues
        self.usedAt = usedAt
    }
}

public enum SourceQualityLabel: String, Codable, CaseIterable, Equatable, Sendable {
    case p480
    case p720
    case p1080
    case p4k
    case unknown

    public init(sourceHeight: Int?) {
        guard let sourceHeight else {
            self = .unknown
            return
        }

        if sourceHeight >= 2000 {
            self = .p4k
        } else if sourceHeight > 720 {
            self = .p1080
        } else if sourceHeight > 480 {
            self = .p720
        } else if sourceHeight > 0 {
            self = .p480
        } else {
            self = .unknown
        }
    }

    public var displayText: String {
        switch self {
        case .p480: return "480p"
        case .p720: return "720p"
        case .p1080: return "1080p"
        case .p4k: return "4K"
        case .unknown: return "Original"
        }
    }
}

// MARK: - Source Metadata

public struct TravelDownloadSourceMediaInfo: Codable, Equatable, Sendable {
    public var sourceHeight: Int?
    public var sourceWidth: Int?
    public var durationSeconds: TimeInterval?
    public var sourceSizeBytes: Int64?
    public var videoCodec: String?
    public var audioCodec: String?
    public var container: String?
    public var isHDR: Bool
    public var isDolbyVision: Bool

    public init(
        sourceHeight: Int?,
        sourceWidth: Int? = nil,
        durationSeconds: TimeInterval? = nil,
        sourceSizeBytes: Int64? = nil,
        videoCodec: String? = nil,
        audioCodec: String? = nil,
        container: String? = nil,
        isHDR: Bool = false,
        isDolbyVision: Bool = false
    ) {
        self.sourceHeight = sourceHeight
        self.sourceWidth = sourceWidth
        self.durationSeconds = durationSeconds
        self.sourceSizeBytes = sourceSizeBytes
        self.videoCodec = videoCodec
        self.audioCodec = audioCodec
        self.container = container
        self.isHDR = isHDR
        self.isDolbyVision = isDolbyVision
    }
}

// MARK: - Quality Options

public struct TravelDownloadQualityOption: Identifiable, Codable, Equatable, Sendable {
    public var id: TravelDownloadQuality { quality }
    public var quality: TravelDownloadQuality
    public var title: String
    public var subtitle: String
    public var detail: String?
    public var sourceLabel: String?
    public var estimatedSizeBytes: Int64?
    public var estimatedPrepareSeconds: TimeInterval?
    public var estimatedDownloadSeconds: TimeInterval?
    public var confidence: EstimateConfidence

    public init(
        quality: TravelDownloadQuality,
        title: String,
        subtitle: String,
        detail: String? = nil,
        sourceLabel: String? = nil,
        estimatedSizeBytes: Int64? = nil,
        estimatedPrepareSeconds: TimeInterval? = nil,
        estimatedDownloadSeconds: TimeInterval? = nil,
        confidence: EstimateConfidence = .unknown
    ) {
        self.quality = quality
        self.title = title
        self.subtitle = subtitle
        self.detail = detail
        self.sourceLabel = sourceLabel
        self.estimatedSizeBytes = estimatedSizeBytes
        self.estimatedPrepareSeconds = estimatedPrepareSeconds
        self.estimatedDownloadSeconds = estimatedDownloadSeconds
        self.confidence = confidence
    }
}

public enum EstimateConfidence: String, Codable, CaseIterable, Equatable, Sendable {
    case low
    case medium
    case high
    case unknown
}

public enum TravelDownloadQualityOptionBuilder {
    public static func availableQualities(for sourceHeight: Int?) -> [TravelDownloadQuality] {
        guard let sourceHeight, sourceHeight > 0 else {
            return [.p480, .p720, .original]
        }

        if sourceHeight >= 2000 {
            return [.p480, .p720, .p1080, .original]
        }

        if sourceHeight > 720 {
            return [.p480, .p720, .original]
        }

        if sourceHeight > 480 {
            return [.p480, .original]
        }

        return [.original]
    }

    public static func options(
        for mediaInfo: TravelDownloadSourceMediaInfo,
        observedBytesPerSecond: Double? = nil
    ) -> [TravelDownloadQualityOption] {
        let qualities = availableQualities(for: mediaInfo.sourceHeight)

        return qualities.map { quality in
            var option = baseOption(for: quality, sourceHeight: mediaInfo.sourceHeight)
            let estimate = TravelDownloadEstimator.estimate(
                quality: quality,
                mediaInfo: mediaInfo,
                observedBytesPerSecond: observedBytesPerSecond
            )
            option.estimatedSizeBytes = estimate.sizeBytes
            option.estimatedPrepareSeconds = estimate.prepareSeconds
            option.estimatedDownloadSeconds = estimate.downloadSeconds
            option.confidence = estimate.confidence
            return option
        }
    }

    public static func baseOption(for quality: TravelDownloadQuality, sourceHeight: Int?) -> TravelDownloadQualityOption {
        switch quality {
        case .p480:
            return TravelDownloadQualityOption(
                quality: .p480,
                title: "Storage Saver 480p",
                subtitle: "Good enough for phone screens. Downloads faster and lets you fit more.",
                detail: "Best if you want more episodes or need the download to finish sooner."
            )
        case .p720:
            return TravelDownloadQualityOption(
                quality: .p720,
                title: "Recommended 720p",
                subtitle: "Sharper and better for most phones. Uses more storage than 480p.",
                detail: "Best balance of quality, storage, and download time."
            )
        case .p1080:
            return TravelDownloadQualityOption(
                quality: .p1080,
                title: "High Quality 1080p",
                subtitle: "Great for iPad, hotel TVs, or larger screens. Smaller than 4K but still sharp."
            )
        case .original:
            let label = SourceQualityLabel(sourceHeight: sourceHeight).displayText
            return TravelDownloadQualityOption(
                quality: .original,
                title: "Original Quality \(label)",
                subtitle: "Best available quality. Largest file and may take much longer.",
                sourceLabel: label
            )
        case .smart:
            return TravelDownloadQualityOption(
                quality: .smart,
                title: "Smart Recommended",
                subtitle: "Kaevo chooses the best balance of quality, storage, and download time."
            )
        case .askEveryTime:
            return TravelDownloadQualityOption(
                quality: .askEveryTime,
                title: "Ask Every Time",
                subtitle: "Choose download quality each time you start a Travel Download."
            )
        }
    }
}

// MARK: - Estimates

public struct TravelDownloadEstimate: Codable, Equatable, Sendable {
    public var quality: TravelDownloadQuality
    public var sizeBytes: Int64?
    public var prepareSeconds: TimeInterval?
    public var downloadSeconds: TimeInterval?
    public var confidence: EstimateConfidence
}

public enum TravelDownloadEstimator {
    /// Combined video+audio rough mobile targets.
    /// These are intentionally conservative and should be refined with real bridge measurements later.
    private static let targetMegabitsPerSecond: [TravelDownloadQuality: Double] = [
        .p480: 1.25,
        .p720: 3.25,
        .p1080: 6.50
    ]

    public static func estimate(
        quality: TravelDownloadQuality,
        mediaInfo: TravelDownloadSourceMediaInfo,
        observedBytesPerSecond: Double?
    ) -> TravelDownloadEstimate {
        let estimatedSize = estimateSizeBytes(quality: quality, mediaInfo: mediaInfo)
        let downloadSeconds = estimateDownloadSeconds(sizeBytes: estimatedSize, observedBytesPerSecond: observedBytesPerSecond)
        let prepareSeconds = estimatePrepareSeconds(quality: quality, mediaInfo: mediaInfo)

        let confidence: EstimateConfidence
        if quality == .original, mediaInfo.sourceSizeBytes != nil {
            confidence = .high
        } else if estimatedSize != nil, mediaInfo.durationSeconds != nil {
            confidence = .medium
        } else {
            confidence = .low
        }

        return TravelDownloadEstimate(
            quality: quality,
            sizeBytes: estimatedSize,
            prepareSeconds: prepareSeconds,
            downloadSeconds: downloadSeconds,
            confidence: confidence
        )
    }

    public static func estimateSizeBytes(
        quality: TravelDownloadQuality,
        mediaInfo: TravelDownloadSourceMediaInfo
    ) -> Int64? {
        if quality == .original {
            return mediaInfo.sourceSizeBytes
        }

        guard let durationSeconds = mediaInfo.durationSeconds,
              let mbps = targetMegabitsPerSecond[quality]
        else {
            return nil
        }

        let bytesPerSecond = (mbps * 1_000_000.0) / 8.0
        let containerOverheadMultiplier = 1.03
        return Int64((bytesPerSecond * durationSeconds * containerOverheadMultiplier).rounded())
    }

    public static func estimateDownloadSeconds(
        sizeBytes: Int64?,
        observedBytesPerSecond: Double?
    ) -> TimeInterval? {
        guard let sizeBytes,
              let observedBytesPerSecond,
              observedBytesPerSecond > 0
        else {
            return nil
        }

        return Double(sizeBytes) / observedBytesPerSecond
    }

    public static func estimatePrepareSeconds(
        quality: TravelDownloadQuality,
        mediaInfo: TravelDownloadSourceMediaInfo
    ) -> TimeInterval? {
        guard quality != .original else { return 0 }
        guard let durationSeconds = mediaInfo.durationSeconds else { return nil }

        // Placeholder only. Real estimates should be bridge-measured per server.
        // Assume 2x realtime for easy 1080p -> 720p, slower for 4K/HDR.
        let sourceHeight = mediaInfo.sourceHeight ?? 0
        let multiplier: Double

        if sourceHeight >= 2000 || mediaInfo.isHDR || mediaInfo.isDolbyVision {
            multiplier = 0.85 // About 0.85x runtime as a placeholder for heavy sources.
        } else {
            multiplier = 0.40 // About 0.4x runtime for easier sources.
        }

        return max(60, durationSeconds * multiplier)
    }
}

// MARK: - Job Model

public struct TravelDownloadJob: Codable, Equatable, Identifiable, Sendable {
    public var id: String { jobId }
    public var jobId: String
    public var userId: String
    public var profileId: String
    public var deviceId: String
    public var serverId: String
    public var mediaProvider: TravelDownloadMediaProvider
    public var mediaItemId: String
    public var mediaType: TravelDownloadMediaType
    public var requestedQuality: TravelDownloadQuality
    public var sourceQuality: SourceQualityLabel
    public var status: TravelDownloadJobStatus
    public var prepareStatus: TravelDownloadPrepareStatus
    public var downloadStatus: TravelDownloadTransferStatus
    public var issueHandlingMode: TravelDownloadIssueHandlingMode
    public var notifyIssues: Bool
    public var retryCount: Int
    public var maxRetryCount: Int
    public var failureReason: TravelDownloadFailureReason?
    public var createdAt: Date
    public var updatedAt: Date

    public init(
        jobId: String,
        userId: String,
        profileId: String,
        deviceId: String,
        serverId: String,
        mediaProvider: TravelDownloadMediaProvider,
        mediaItemId: String,
        mediaType: TravelDownloadMediaType,
        requestedQuality: TravelDownloadQuality,
        sourceQuality: SourceQualityLabel,
        status: TravelDownloadJobStatus = .queued,
        prepareStatus: TravelDownloadPrepareStatus = .waiting,
        downloadStatus: TravelDownloadTransferStatus = .notStarted,
        issueHandlingMode: TravelDownloadIssueHandlingMode = .kaevoAssist,
        notifyIssues: Bool = true,
        retryCount: Int = 0,
        maxRetryCount: Int = 3,
        failureReason: TravelDownloadFailureReason? = nil,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.jobId = jobId
        self.userId = userId
        self.profileId = profileId
        self.deviceId = deviceId
        self.serverId = serverId
        self.mediaProvider = mediaProvider
        self.mediaItemId = mediaItemId
        self.mediaType = mediaType
        self.requestedQuality = requestedQuality
        self.sourceQuality = sourceQuality
        self.status = status
        self.prepareStatus = prepareStatus
        self.downloadStatus = downloadStatus
        self.issueHandlingMode = issueHandlingMode
        self.notifyIssues = notifyIssues
        self.retryCount = max(0, retryCount)
        self.maxRetryCount = max(0, maxRetryCount)
        self.failureReason = failureReason
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

// MARK: - Last Setup Decision

public enum TravelDownloadStartDecision: Equatable, Sendable {
    case useLastSetup(LastTravelDownloadSetup)
    case showFullFlow
}

public enum TravelDownloadStartFlowPolicy {
    public static func initialDecision(for settings: TravelDownloadSettings) -> TravelDownloadStartDecision {
        if settings.askEveryTime || settings.defaultQualityMode == .askEveryTime || settings.issueHandlingMode == .askEveryTime {
            return .showFullFlow
        }

        if settings.useLastSetup, let lastSetup = settings.lastSetup {
            return .useLastSetup(lastSetup)
        }

        return .showFullFlow
    }
}

// MARK: - Kaevo Assist Action Policy

public enum KaevoAssistAction: String, Codable, CaseIterable, Equatable, Sendable {
    case retryFailedDownload
    case resumeInterruptedDownload
    case reconnectToHomeServer
    case recheckPhoneStorage
    case recheckServerAvailability
    case validatePreparedFile
    case rebuildFailedMobileVersion
    case pauseOnPoorConnectionAndResumeLater

    case trySmallerQuality
    case deletePreparedTemporaryFiles
    case clearLocalOfflineDownloads
    case switchFromWiFiToCellular
    case useCellularForLargeDownload

    case deleteOriginalMedia
    case changeJellyfinLibraryPaths
    case changeServerPaths
    case changeProviderSettings
    case removeUserFiles
    case silentlyDowngradeQuality
}

public enum KaevoAssistActionPermission: String, Codable, Equatable, Sendable {
    case allowedAutomatically
    case askFirst
    case never
}

public enum KaevoAssistPolicy {
    public static func permission(for action: KaevoAssistAction) -> KaevoAssistActionPermission {
        switch action {
        case .retryFailedDownload,
             .resumeInterruptedDownload,
             .reconnectToHomeServer,
             .recheckPhoneStorage,
             .recheckServerAvailability,
             .validatePreparedFile,
             .rebuildFailedMobileVersion,
             .pauseOnPoorConnectionAndResumeLater:
            return .allowedAutomatically

        case .trySmallerQuality,
             .deletePreparedTemporaryFiles,
             .clearLocalOfflineDownloads,
             .switchFromWiFiToCellular,
             .useCellularForLargeDownload:
            return .askFirst

        case .deleteOriginalMedia,
             .changeJellyfinLibraryPaths,
             .changeServerPaths,
             .changeProviderSettings,
             .removeUserFiles,
             .silentlyDowngradeQuality:
            return .never
        }
    }

    public static func canRunAutomatically(
        action: KaevoAssistAction,
        mode: TravelDownloadIssueHandlingMode,
        retryCount: Int,
        maxRetryCount: Int
    ) -> Bool {
        guard mode == .kaevoAssist else { return false }
        guard retryCount < maxRetryCount else { return false }
        return permission(for: action) == .allowedAutomatically
    }
}

// MARK: - Display Helpers

public enum TravelDownloadDisplayFormatter {
    public static func fileSize(_ bytes: Int64?) -> String {
        guard let bytes else { return "Estimated size unavailable" }
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useMB, .useGB]
        formatter.countStyle = .file
        return formatter.string(fromByteCount: bytes)
    }

    public static func duration(_ seconds: TimeInterval?) -> String {
        guard let seconds else { return "Estimate unavailable" }

        let minutes = Int((seconds / 60).rounded())
        if minutes < 1 { return "less than 1 minute" }
        if minutes < 60 { return "about \(minutes) minutes" }

        let hours = minutes / 60
        let remainingMinutes = minutes % 60
        if remainingMinutes == 0 {
            return "about \(hours) hour\(hours == 1 ? "" : "s")"
        }
        return "about \(hours) hour\(hours == 1 ? "" : "s") \(remainingMinutes) minutes"
    }
}
