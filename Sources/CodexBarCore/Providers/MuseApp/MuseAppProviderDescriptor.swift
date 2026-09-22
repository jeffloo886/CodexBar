import Foundation

public struct MuseAppUsageData: Equatable, Sendable {
    public let weeklyPercent: Double
    public let weeklyResetDescription: String
    public let weeklyResetsAt: Date?
    public let additionalPercent: Double
    public let additionalBalanceDescription: String?

    public init(
        weeklyPercent: Double,
        weeklyResetDescription: String,
        weeklyResetsAt: Date?,
        additionalPercent: Double,
        additionalBalanceDescription: String?)
    {
        self.weeklyPercent = weeklyPercent
        self.weeklyResetDescription = weeklyResetDescription
        self.weeklyResetsAt = weeklyResetsAt
        self.additionalPercent = additionalPercent
        self.additionalBalanceDescription = additionalBalanceDescription
    }
}

public enum MuseAppUsageParser {
    public enum ParseError: Error, Equatable {
        case usageUnavailable
        case malformedUsage
    }

    public static func parse(values: [String], now: Date = .now) throws -> MuseAppUsageData {
        let text = values
            .map { $0.replacingOccurrences(of: "\\n", with: " ") }
            .joined(separator: " ")
            .replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)

        guard let weeklyPercent = Self.firstDouble(
            pattern: #"(?i)Free plan.*?(\d+(?:\.\d+)?)%\s+used"#,
            in: text)
        else {
            throw ParseError.usageUnavailable
        }

        guard let additionalPercent = Self.firstDouble(
            pattern: #"(?i)Additional tokens.*?(\d+(?:\.\d+)?)%\s+used"#,
            in: text)
        else {
            throw ParseError.malformedUsage
        }

        let resetDescription = Self.firstMatch(
            pattern: #"(?i)(Weekly limit resets on\s+[A-Za-z]{3,9}\s+\d{1,2})"#,
            in: text) ?? "Weekly limit reset"
        let resetDate = Self.parseResetDate(from: resetDescription, now: now)
        let balance = Self.firstMatch(pattern: #"(?i)Additional tokens.*?\(([^)]+)\)"#, in: text)

        return MuseAppUsageData(
            weeklyPercent: weeklyPercent,
            weeklyResetDescription: resetDescription,
            weeklyResetsAt: resetDate,
            additionalPercent: additionalPercent,
            additionalBalanceDescription: balance)
    }

    private static func firstDouble(pattern: String, in text: String) -> Double? {
        guard let match = firstMatch(pattern: pattern, in: text), let value = Double(match) else { return nil }
        guard value.isFinite, value >= 0 else { return nil }
        return value
    }

    private static func firstMatch(pattern: String, in text: String) -> String? {
        guard let expression = try? NSRegularExpression(pattern: pattern),
              let match = expression.firstMatch(in: text, range: NSRange(text.startIndex..., in: text))
        else { return nil }

        let range = match.numberOfRanges > 1 ? match.range(at: 1) : match.range
        guard let swiftRange = Range(range, in: text) else { return nil }
        return String(text[swiftRange])
    }

    private static func parseResetDate(from description: String, now: Date) -> Date? {
        let pattern = #"(?i)resets on\s+([A-Za-z]{3,9}\s+\d{1,2})"#
        guard let monthDay = Self.firstMatch(pattern: pattern, in: description) else { return nil }

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.dateFormat = "MMM d yyyy"
        guard let calendar = formatter.calendar else { return nil }
        let year = calendar.component(.year, from: now)
        guard var date = formatter.date(from: "\(monthDay) \(year)") else { return nil }
        if date < now, let nextYear = calendar.date(byAdding: .year, value: 1, to: date) {
            date = nextYear
        }
        return date
    }
}

public enum MuseAppUsageProbeError: Error, LocalizedError, Equatable {
    case applicationNotRunning
    case accessibilityUnavailable
    case settingsWindowUnavailable
    case usageUnavailable

    public var errorDescription: String? {
        switch self {
        case .applicationNotRunning:
            "Muse is not running. Open Muse and its Settings → General → Usage page."
        case .accessibilityUnavailable:
            "CodexBar needs Accessibility access to read the Muse settings window."
        case .settingsWindowUnavailable:
            "Muse Settings is not open. Open Muse → Settings and leave the General Usage section visible."
        case .usageUnavailable:
            "Muse usage is not visible yet. Leave the Usage section visible and refresh CodexBar."
        }
    }
}

#if os(macOS)
import AppKit
import ApplicationServices

public struct MuseAppUsageProbe: Sendable {
    public static let bundleIdentifier = "com.meta.endo"

    public init() {}

    public func isAvailable() -> Bool {
        NSWorkspace.shared.runningApplications.contains { $0.bundleIdentifier == Self.bundleIdentifier }
            && AXIsProcessTrusted()
    }

    public func fetch(now: Date = .now) throws -> MuseAppUsageData {
        guard AXIsProcessTrusted() else { throw MuseAppUsageProbeError.accessibilityUnavailable }
        guard let application = NSWorkspace.shared.runningApplications.first(where: {
            $0.bundleIdentifier == Self.bundleIdentifier
        }) else {
            throw MuseAppUsageProbeError.applicationNotRunning
        }

        let applicationElement = AXUIElementCreateApplication(application.processIdentifier)
        var windowsValue: CFTypeRef?
        guard AXUIElementCopyAttributeValue(
            applicationElement,
            kAXWindowsAttribute as CFString,
            &windowsValue) == .success,
            let windows = windowsValue as? [AXUIElement]
        else {
            throw MuseAppUsageProbeError.settingsWindowUnavailable
        }

        guard let settingsWindow = windows.first(where: Self.isSettingsWindow) else {
            throw MuseAppUsageProbeError.settingsWindowUnavailable
        }

        let values = Self.accessibilityValues(in: settingsWindow)
        if let parsed = try? MuseAppUsageParser.parse(values: values, now: now) {
            return parsed
        }
        throw MuseAppUsageProbeError.usageUnavailable
    }

    private static func isSettingsWindow(_ window: AXUIElement) -> Bool {
        var title: CFTypeRef?
        guard AXUIElementCopyAttributeValue(window, kAXTitleAttribute as CFString, &title) == .success,
              let title = title as? String
        else { return false }
        return title.localizedCaseInsensitiveContains("Settings")
    }

    private static func accessibilityValues(in root: AXUIElement) -> [String] {
        var values: [String] = []
        Self.walk(root, depth: 0, values: &values)
        return values
    }

    private static func walk(_ element: AXUIElement, depth: Int, values: inout [String]) {
        guard depth < 16 else { return }
        for attribute in [kAXTitleAttribute, kAXValueAttribute, kAXDescriptionAttribute, kAXHelpAttribute] {
            var value: CFTypeRef?
            guard AXUIElementCopyAttributeValue(element, attribute as CFString, &value) == .success else { continue }
            if let string = value as? String, !string.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                values.append(string)
            }
        }

        var children: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, kAXChildrenAttribute as CFString, &children) == .success,
              let children = children as? [AXUIElement]
        else { return }
        for child in children {
            Self.walk(child, depth: depth + 1, values: &values)
        }
    }
}
#else
public struct MuseAppUsageProbe: Sendable {
    public init() {}
    public func isAvailable() -> Bool { false }
    public func fetch(now _: Date = .now) throws -> MuseAppUsageData {
        throw MuseAppUsageProbeError.accessibilityUnavailable
    }
}
#endif

public enum MuseAppProviderDescriptor {
    public static let descriptor: ProviderDescriptor = Self.makeDescriptor()

    static func makeDescriptor() -> ProviderDescriptor {
        ProviderDescriptor(
            id: .museapp,
            metadata: ProviderMetadata(
                id: .museapp,
                displayName: "Muse",
                shortDisplayName: "Muse",
                sessionLabel: "Free plan",
                weeklyLabel: "Additional tokens",
                opusLabel: nil,
                supportsOpus: false,
                supportsCredits: false,
                creditsHint: "Muse desktop plan usage.",
                toggleTitle: "Show Muse desktop usage",
                cliName: "muse-app",
                defaultEnabled: false,
                widgetSelectable: false,
                dashboardURL: "https://muse.ai",
                subscriptionDashboardURL: "https://muse.ai",
                statusPageURL: nil),
            branding: ProviderBranding(
                iconStyle: .init(provider: .museapp),
                iconResourceName: "ProviderIcon-museapp",
                color: ProviderColor(red: 0.37, green: 0.37, blue: 0.37),
                confettiPalette: [
                    ProviderColor(hex: 0x6B7280),
                    ProviderColor(hex: 0xD1D5DB),
                    ProviderColor(hex: 0xFFFFFF),
                ]),
            tokenCost: ProviderTokenCostConfig(
                supportsTokenCost: false,
                noDataMessage: { "Muse desktop usage is read from the visible Muse Settings page." }),
            presentation: ProviderUsagePresentation(
                rateWindowLabeler: { _, _, _ in
                    ProviderRateWindowLabels(
                        primary: "Free plan",
                        secondary: "Additional tokens",
                        tertiary: "",
                        showsTertiary: false)
                },
                primarySemanticWindow: .weekly,
                secondarySemanticWindow: .weekly,
                menuBarLayoutPrimaryLabel: "Free plan",
                menuBarLayoutSecondaryLabel: "Additional tokens"),
            fetchPlan: ProviderFetchPlan(
                sourceModes: [.auto],
                pipeline: ProviderFetchPipeline(resolveStrategies: { _ in [MuseAppLocalFetchStrategy()] })),
            cli: ProviderCLIConfig(
                name: "muse-app",
                versionDetector: nil))
    }
}

struct MuseAppLocalFetchStrategy: ProviderFetchStrategy {
    let id: String = "museapp.local"
    let kind: ProviderFetchKind = .localProbe

    func isAvailable(_: ProviderFetchContext) async -> Bool {
        MuseAppUsageProbe().isAvailable()
    }

    func fetch(_: ProviderFetchContext) async throws -> ProviderFetchResult {
        let data = try MuseAppUsageProbe().fetch()
        let usage = UsageSnapshot(
            primary: RateWindow(
                usedPercent: data.weeklyPercent,
                windowMinutes: 7 * 24 * 60,
                resetsAt: data.weeklyResetsAt,
                resetDescription: data.weeklyResetDescription),
            secondary: RateWindow(
                usedPercent: data.additionalPercent,
                windowMinutes: nil,
                resetsAt: nil,
                resetDescription: data.additionalBalanceDescription ?? "Never expires"),
            updatedAt: Date())
        return self.makeResult(usage: usage, sourceLabel: "Muse settings")
    }

    func shouldFallback(on _: Error, context _: ProviderFetchContext) -> Bool {
        false
    }
}
