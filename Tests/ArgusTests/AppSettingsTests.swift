import XCTest
@testable import Argus

final class NotificationThresholdTests: XCTestCase {
    func testOffNeverNotifies() {
        for severity in Severity.allCases {
            XCTAssertFalse(NotificationThreshold.off.shouldNotify(for: severity))
        }
    }

    func testCriticalOnly() {
        XCTAssertFalse(NotificationThreshold.criticalOnly.shouldNotify(for: .elevated))
        XCTAssertTrue(NotificationThreshold.criticalOnly.shouldNotify(for: .critical))
    }

    func testElevatedAndAbove() {
        XCTAssertFalse(NotificationThreshold.elevatedAndAbove.shouldNotify(for: .watch))
        XCTAssertTrue(NotificationThreshold.elevatedAndAbove.shouldNotify(for: .elevated))
        XCTAssertTrue(NotificationThreshold.elevatedAndAbove.shouldNotify(for: .critical))
    }

    func testAllMatchesExcludesInfo() {
        // .info is the "benign ambient" marker used for unmatched processes —
        // it should never actually reach notification logic, but the
        // threshold itself should still exclude it for safety.
        XCTAssertFalse(NotificationThreshold.allMatches.shouldNotify(for: .info))
        XCTAssertTrue(NotificationThreshold.allMatches.shouldNotify(for: .watch))
        XCTAssertTrue(NotificationThreshold.allMatches.shouldNotify(for: .critical))
    }
}

@MainActor
final class AppSettingsTests: XCTestCase {
    private func makeDefaults() -> UserDefaults {
        let suiteName = "argus-tests-\(UUID().uuidString)"
        return UserDefaults(suiteName: suiteName)!
    }

    func testDefaults() {
        let settings = AppSettings(defaults: makeDefaults())
        XCTAssertEqual(settings.pollIntervalSeconds, 1.2)
        XCTAssertEqual(settings.riskDecayHalfLifeSeconds, 55.0)
        XCTAssertEqual(settings.notificationThreshold, .criticalOnly)
    }

    func testValuesClampToRange() {
        let defaults = makeDefaults()
        defaults.set(999.0, forKey: "argus.pollIntervalSeconds")
        defaults.set(-10.0, forKey: "argus.riskDecayHalfLifeSeconds")

        let settings = AppSettings(defaults: defaults)
        XCTAssertEqual(settings.pollIntervalSeconds, AppSettings.pollIntervalRange.upperBound)
        XCTAssertEqual(settings.riskDecayHalfLifeSeconds, AppSettings.decayHalfLifeRange.lowerBound)
    }

    func testPersistsAcrossInstances() {
        let defaults = makeDefaults()
        let settings = AppSettings(defaults: defaults)
        settings.pollIntervalSeconds = 2.5
        settings.notificationThreshold = .allMatches

        let reloaded = AppSettings(defaults: defaults)
        XCTAssertEqual(reloaded.pollIntervalSeconds, 2.5)
        XCTAssertEqual(reloaded.notificationThreshold, .allMatches)
    }
}
