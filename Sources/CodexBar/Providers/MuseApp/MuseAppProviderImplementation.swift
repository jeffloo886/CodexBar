import CodexBarCore
import Foundation

struct MuseAppProviderImplementation: ProviderImplementation {
    let id: UsageProvider = .museapp

    @MainActor
    func isAvailable(context _: ProviderAvailabilityContext) -> Bool {
        // Availability is deliberately optimistic so an enabled provider can run its guarded fetch and
        // show the specific Accessibility/Muse/Settings recovery message.
        true
    }
}
