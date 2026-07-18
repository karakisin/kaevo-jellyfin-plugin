import XCTest
@testable import Kaevo

final class TravelDownloadQualityOptionTests: XCTestCase {
    func test4KSourceShows4807201080AndOriginal() {
        let qualities = TravelDownloadQualityOptionBuilder.availableQualities(for: 2160)
        XCTAssertEqual(qualities, [.p480, .p720, .p1080, .original])
    }

    func test1080pSourceShows480720AndOriginal() {
        let qualities = TravelDownloadQualityOptionBuilder.availableQualities(for: 1080)
        XCTAssertEqual(qualities, [.p480, .p720, .original])
    }

    func test720pSourceShows480AndOriginalOnly() {
        let qualities = TravelDownloadQualityOptionBuilder.availableQualities(for: 720)
        XCTAssertEqual(qualities, [.p480, .original])
    }

    func test480pSourceShowsOriginalOnly() {
        let qualities = TravelDownloadQualityOptionBuilder.availableQualities(for: 480)
        XCTAssertEqual(qualities, [.original])
    }

    func testUnknownSourceShowsSafeGenericChoices() {
        let qualities = TravelDownloadQualityOptionBuilder.availableQualities(for: nil)
        XCTAssertEqual(qualities, [.p480, .p720, .original])
    }

    func testOriginalTitleUsesSourceLabel() {
        let option = TravelDownloadQualityOptionBuilder.baseOption(for: .original, sourceHeight: 1080)
        XCTAssertEqual(option.title, "Original Quality 1080p")
    }

    func testLastSetupIsUsedWhenEnabled() {
        let lastSetup = LastTravelDownloadSetup(
            quality: .p720,
            sourceQuality: .p1080,
            issueHandlingMode: .kaevoAssist,
            notifyIssues: true
        )

        let settings = TravelDownloadSettings(useLastSetup: true, lastSetup: lastSetup)
        let decision = TravelDownloadStartFlowPolicy.initialDecision(for: settings)

        XCTAssertEqual(decision, .useLastSetup(lastSetup))
    }

    func testAskEveryTimeOverridesLastSetup() {
        let lastSetup = LastTravelDownloadSetup(
            quality: .p720,
            sourceQuality: .p1080,
            issueHandlingMode: .kaevoAssist,
            notifyIssues: true
        )

        let settings = TravelDownloadSettings(
            useLastSetup: true,
            askEveryTime: true,
            lastSetup: lastSetup
        )

        XCTAssertEqual(TravelDownloadStartFlowPolicy.initialDecision(for: settings), .showFullFlow)
    }
}

final class TravelDownloadEstimatorTests: XCTestCase {
    func testOriginalUsesSourceSize() {
        let info = TravelDownloadSourceMediaInfo(
            sourceHeight: 1080,
            durationSeconds: 7200,
            sourceSizeBytes: 18_000_000_000
        )

        let estimate = TravelDownloadEstimator.estimate(
            quality: .original,
            mediaInfo: info,
            observedBytesPerSecond: 8_000_000
        )

        XCTAssertEqual(estimate.sizeBytes, 18_000_000_000)
        XCTAssertEqual(estimate.prepareSeconds, 0)
        XCTAssertEqual(estimate.confidence, .high)
        XCTAssertNotNil(estimate.downloadSeconds)
    }

    func testMobileQualityEstimatesSizeFromDuration() {
        let info = TravelDownloadSourceMediaInfo(
            sourceHeight: 1080,
            durationSeconds: 3600,
            sourceSizeBytes: 12_000_000_000
        )

        let estimate480 = TravelDownloadEstimator.estimate(
            quality: .p480,
            mediaInfo: info,
            observedBytesPerSecond: nil
        )

        let estimate720 = TravelDownloadEstimator.estimate(
            quality: .p720,
            mediaInfo: info,
            observedBytesPerSecond: nil
        )

        XCTAssertNotNil(estimate480.sizeBytes)
        XCTAssertNotNil(estimate720.sizeBytes)
        XCTAssertLessThan(estimate480.sizeBytes!, estimate720.sizeBytes!)
        XCTAssertEqual(estimate480.confidence, .medium)
    }
}

final class KaevoAssistPolicyTests: XCTestCase {
    func testRetryCanRunAutomaticallyInKaevoAssistMode() {
        XCTAssertTrue(
            KaevoAssistPolicy.canRunAutomatically(
                action: .retryFailedDownload,
                mode: .kaevoAssist,
                retryCount: 0,
                maxRetryCount: 3
            )
        )
    }

    func testRetryCannotRunAutomaticallyInManualMode() {
        XCTAssertFalse(
            KaevoAssistPolicy.canRunAutomatically(
                action: .retryFailedDownload,
                mode: .manual,
                retryCount: 0,
                maxRetryCount: 3
            )
        )
    }

    func testRetryStopsAtLimit() {
        XCTAssertFalse(
            KaevoAssistPolicy.canRunAutomatically(
                action: .retryFailedDownload,
                mode: .kaevoAssist,
                retryCount: 3,
                maxRetryCount: 3
            )
        )
    }

    func testTrySmallerQualityRequiresAskFirst() {
        XCTAssertEqual(KaevoAssistPolicy.permission(for: .trySmallerQuality), .askFirst)
    }

    func testDeleteOriginalMediaIsNeverAllowed() {
        XCTAssertEqual(KaevoAssistPolicy.permission(for: .deleteOriginalMedia), .never)
    }

    func testSilentDowngradeIsNeverAllowed() {
        XCTAssertEqual(KaevoAssistPolicy.permission(for: .silentlyDowngradeQuality), .never)
    }
}
