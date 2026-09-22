import AppKit
import CodexBarCore
import Foundation
import SwiftUI
import Testing
import XCTest
@testable import CodexBar

struct MenuCardMuseAppTests {
    @Test
    func `additional token balance is detail instead of a reset`() throws {
        let now = Date(timeIntervalSince1970: 1_758_528_000)
        let metadata = try #require(ProviderDefaults.metadata[.museapp])
        let snapshot = UsageSnapshot(
            primary: RateWindow(
                usedPercent: 2,
                windowMinutes: 7 * 24 * 60,
                resetsAt: nil,
                resetDescription: "Weekly limit resets on Sep 26"),
            secondary: RateWindow(
                usedPercent: 0,
                windowMinutes: nil,
                resetsAt: nil,
                resetDescription: "1B tokens left"),
            updatedAt: now)

        let model = UsageMenuCardView.Model.make(.init(
            provider: .museapp,
            metadata: metadata,
            snapshot: snapshot,
            credits: nil,
            creditsError: nil,
            dashboardError: nil,
            tokenSnapshot: nil,
            tokenError: nil,
            account: AccountInfo(email: nil, plan: nil),
            isRefreshing: false,
            lastError: nil,
            usageBarsShowUsed: false,
            resetTimeDisplayStyle: .countdown,
            tokenCostUsageEnabled: false,
            showOptionalCreditsAndExtraUsage: true,
            hidePersonalInfo: false,
            now: now))

        let secondary = try #require(model.metrics.first { $0.id == "secondary" })
        #expect(secondary.resetText == nil)
        #expect(secondary.detailText == "1B tokens left")
    }
}

@MainActor
final class MuseAppScreenshotRenderTests: XCTestCase {
    func test_renderFixedBalanceCard() throws {
        guard let path = ProcessInfo.processInfo.environment["CODEXBAR_MUSEAPP_SCREENSHOT_DIR"] else {
            throw XCTSkip("Set CODEXBAR_MUSEAPP_SCREENSHOT_DIR to render the rebuilt Muse app card.")
        }
        let directory = URL(fileURLWithPath: path, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let now = Date(timeIntervalSince1970: 1_758_528_000)
        let metadata = try XCTUnwrap(ProviderDefaults.metadata[.museapp])
        let snapshot = UsageSnapshot(
            primary: RateWindow(
                usedPercent: 2,
                windowMinutes: 7 * 24 * 60,
                resetsAt: nil,
                resetDescription: "Weekly limit resets on Sep 26"),
            secondary: RateWindow(
                usedPercent: 0,
                windowMinutes: nil,
                resetsAt: nil,
                resetDescription: "1B tokens left"),
            updatedAt: now)
        let model = UsageMenuCardView.Model.make(.init(
            provider: .museapp,
            metadata: metadata,
            snapshot: snapshot,
            credits: nil,
            creditsError: nil,
            dashboardError: nil,
            tokenSnapshot: nil,
            tokenError: nil,
            account: AccountInfo(email: nil, plan: nil),
            isRefreshing: false,
            lastError: nil,
            usageBarsShowUsed: false,
            resetTimeDisplayStyle: .countdown,
            tokenCostUsageEnabled: false,
            showOptionalCreditsAndExtraUsage: true,
            hidePersonalInfo: true,
            now: now))
        let view = AnyView(UsageMenuCardView(model: model, width: 380)
            .environment(\.locale, Locale(identifier: "en_US_POSIX"))
            .environment(\.colorScheme, .light)
            .environment(\.displayScale, 2)
            .background(Color(nsColor: .windowBackgroundColor)))
        let hosting = NSHostingView(rootView: view)
        hosting.appearance = NSAppearance(named: .aqua)
        let png = try XCTUnwrap(MenuLayoutScreenshotRenderTests.pngDataWithWindow(hosting: hosting))
        try png.write(to: directory.appendingPathComponent("muse-app-fixed-balance.png"), options: .atomic)
    }
}
