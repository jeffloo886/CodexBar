import CodexBarCore
import Foundation

struct MuseAppProviderImplementation: ProviderImplementation {
    let id: UsageProvider = .museapp

    @MainActor
    func isAvailable(context _: ProviderAvailabilityContext) -> Bool {
        MuseAppUsageProbe().isAvailable()
    }
}
