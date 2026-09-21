import Foundation
import Testing
@testable import CodexBarCore
#if os(macOS)
import Security
#endif

#if os(macOS)
/// Covers the memoization of `SecTrustedApplicationValidateWithPath`, which otherwise re-runs a full
/// static code-signature validation of the invoking app bundle on every Keychain ACL preflight.
///
/// No Keychain item is accessed: trust objects are built from fixture binaries in a temporary directory.
struct KeychainTrustedApplicationValidationCacheTests {
    @Test
    func `repeated validation of one executable runs a single real code-signature check`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let trusted = try fixture.trustedApplication(at: fixture.helper)
        let path = fixture.helper.path

        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: path) == 0)
        let first = KeychainAccessPreflight.trustedApplication(trusted, validatesExecutableAt: path)
        #expect(first == errSecSuccess)
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: path) == 1)

        for _ in 0..<8 {
            #expect(KeychainAccessPreflight.trustedApplication(trusted, validatesExecutableAt: path) == first)
        }
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: path) == 1)
    }

    @Test
    func `a different executable path is validated on its own`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let trusted = try fixture.trustedApplication(at: fixture.helper)
        let other = try fixture.makeExecutable(named: "Other", from: "/bin/echo")

        #expect(KeychainAccessPreflight.trustedApplication(
            trusted,
            validatesExecutableAt: fixture.helper.path) == errSecSuccess)

        let mismatch = KeychainAccessPreflight.trustedApplication(trusted, validatesExecutableAt: other.path)
        #expect(mismatch == OSStatus(CSSMERR_CSP_VERIFY_FAILED))
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: other.path) == 1)

        // The rejection is memoized under its own key, never borrowed from the matching path.
        #expect(KeychainAccessPreflight.trustedApplication(trusted, validatesExecutableAt: other.path) == mismatch)
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: other.path) == 1)
    }

    @Test
    func `rewriting the executable discards the memoized verdict`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let trusted = try fixture.trustedApplication(at: fixture.helper)
        let path = fixture.helper.path

        #expect(KeychainAccessPreflight.trustedApplication(trusted, validatesExecutableAt: path) == errSecSuccess)
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: path) == 1)

        try FileManager.default.removeItem(atPath: path)
        try FileManager.default.copyItem(atPath: "/bin/echo", toPath: path)

        let afterRewrite = KeychainAccessPreflight.trustedApplication(trusted, validatesExecutableAt: path)
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: path) == 2)
        #expect(afterRewrite == OSStatus(CSSMERR_CSP_VERIFY_FAILED))
    }

    @Test
    func `distinct trusted applications do not share a memoized verdict`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let matching = try fixture.trustedApplication(at: fixture.helper)
        let other = try fixture.makeExecutable(named: "Other", from: "/bin/echo")
        let mismatching = try fixture.trustedApplication(at: other)
        let path = fixture.helper.path

        let viaMatching = KeychainAccessPreflight.trustedApplication(matching, validatesExecutableAt: path)
        let viaMismatching = KeychainAccessPreflight.trustedApplication(mismatching, validatesExecutableAt: path)

        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: path) == 2)
        #expect(viaMatching == errSecSuccess)
        #expect(viaMismatching == OSStatus(CSSMERR_CSP_VERIFY_FAILED))
    }

    @Test
    func `the memo stays bounded when many executables are validated`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let trusted = try fixture.trustedApplication(at: fixture.helper)

        for index in 0..<(KeychainAccessPreflight.validationCacheCapacity + 8) {
            let copy = try fixture.makeExecutable(named: "Bounded-\(index)", from: "/bin/sleep")
            _ = KeychainAccessPreflight.trustedApplication(trusted, validatesExecutableAt: copy.path)
        }

        #expect(KeychainAccessPreflight.trustedApplicationValidationCacheCountForTesting
            <= KeychainAccessPreflight.validationCacheCapacity)
        // Bounding must not break correctness for a path whose entry was evicted.
        #expect(KeychainAccessPreflight.trustedApplication(
            trusted,
            validatesExecutableAt: fixture.helper.path) == errSecSuccess)
    }

    private struct Fixture {
        let root: URL
        let helper: URL

        init() throws {
            self.root = FileManager.default.temporaryDirectory
                .appendingPathComponent("codexbar-trust-memo-\(UUID().uuidString)", isDirectory: true)
                .resolvingSymlinksInPath()
            try FileManager.default.createDirectory(at: self.root, withIntermediateDirectories: true)
            self.helper = self.root.appendingPathComponent("CodexBarCLI")
            try FileManager.default.copyItem(atPath: "/bin/sleep", toPath: self.helper.path)
        }

        func makeExecutable(named name: String, from source: String) throws -> URL {
            let url = self.root.appendingPathComponent(name)
            try FileManager.default.copyItem(atPath: source, toPath: url.path)
            return url
        }

        func trustedApplication(at url: URL) throws -> SecTrustedApplication {
            let (status, reference) = KeychainCacheStore.createTrustedApplication(path: url.path)
            #expect(status == errSecSuccess)
            return try #require(reference)
        }

        func remove() {
            try? FileManager.default.removeItem(at: self.root)
        }
    }
}
#endif
