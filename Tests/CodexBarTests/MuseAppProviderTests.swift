import CodexBarCore
import Foundation
import Testing

struct MuseAppProviderTests {
    @Test
    func parsesVisibleMuseUsage() throws {
        let calendar = Calendar(identifier: .gregorian)
        let now = try #require(calendar.date(from: DateComponents(year: 2026, month: 9, day: 22, hour: 12)))
        let data = try MuseAppUsageParser.parse(
            values: [
                "Usage",
                "Free plan Weekly limit resets on Sep 26 2% used",
                "Additional tokens Never expires 0% used (1B tokens left)",
            ],
            now: now)

        #expect(data.weeklyPercent == 2)
        #expect(data.additionalPercent == 0)
        #expect(data.weeklyResetDescription == "Weekly limit resets on Sep 26")
        #expect(data.additionalBalanceDescription == "1B tokens left")
        #expect(data.weeklyResetsAt != nil)
    }

    @Test
    func rejectsMissingAdditionalTokensRow() {
        #expect(throws: MuseAppUsageParser.ParseError.malformedUsage) {
            try MuseAppUsageParser.parse(values: ["Free plan 2% used"])
        }
    }

    @Test
    func descriptorUsesDedicatedMuseAppIdentity() {
        let descriptor = MuseAppProviderDescriptor.descriptor
        #expect(descriptor.id == .museapp)
        #expect(descriptor.metadata.displayName == "Muse")
        #expect(descriptor.branding.iconResourceName == "ProviderIcon-museapp")
        #expect(descriptor.metadata.widgetSelectable == false)
    }
}
