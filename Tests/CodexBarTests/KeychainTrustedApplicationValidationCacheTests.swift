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
    func `successful validation is not retained in the process-wide cache`() throws {
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
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: path) == 9)
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

    /// Regression test for a real key collision: `SecTrustedApplicationCopyData` (Apple's implementation
    /// returns only `TrustedApplication::path()`) cannot distinguish two ACL entries that share an install
    /// path but embed different code-signing requirements. Confirmed independently against Apple's open
    /// source (`SecTrustedApplication.cpp`): `CopyData` returns identical bytes for both in that scenario,
    /// while `SecTrustedApplicationCopyExternalRepresentation` — what the cache key now uses — differs.
    /// This constructs that exact scenario with two real, differing `SecRequirement`s at the same
    /// description path and confirms both get their own real validation rather than one reusing the
    /// other's cached verdict.
    @Test
    func `same path with different signing requirements is not a cache collision`() throws {
        let sharedPath = "/Applications/SharedInstallPath.app/Contents/MacOS/Shared"
        let appA = try RequirementTrustedApplication.make(
            description: sharedPath,
            requirement: "identifier \"com.example.codexbar-regression-a\" and anchor apple generic")
        let appB = try RequirementTrustedApplication.make(
            description: sharedPath,
            requirement: "identifier \"com.example.codexbar-regression-b\" and anchor apple generic")

        let fixture = try Fixture()
        defer { fixture.remove() }
        // A fresh Fixture's path is a unique UUID-named temp directory this suite has never validated
        // before, so — matching the same assumption the earlier tests make — the call count for it starts
        // at 0 without needing to reset the process-wide cache.
        let onDiskPath = fixture.helper.path

        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: onDiskPath) == 0)
        _ = KeychainAccessPreflight.trustedApplication(appA, validatesExecutableAt: onDiskPath)
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: onDiskPath) == 1)

        // Under the old CopyData-based key this second call would have hit the cache entry appA just
        // wrote (identical path-only bytes) and skipped real validation. The call count proves it did not.
        _ = KeychainAccessPreflight.trustedApplication(appB, validatesExecutableAt: onDiskPath)
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: onDiskPath) == 2)
    }

    @Test
    func `successful validation is rechecked even before the rejection TTL`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let trusted = try fixture.trustedApplication(at: fixture.helper)
        let path = fixture.helper.path
        let start = Date()

        let first = KeychainAccessPreflight.trustedApplication(trusted, validatesExecutableAt: path, now: start)
        #expect(first == errSecSuccess)
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: path) == 1)

        // Successful results are never retained by the process-wide cache, even immediately afterward.
        let second = KeychainAccessPreflight.trustedApplication(
            trusted,
            validatesExecutableAt: path,
            now: start.addingTimeInterval(1))
        #expect(second == first)
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: path) == 2)
    }

    /// A rejection surviving past its truth only delays a legitimate read (the risk #3301's cooldown
    /// already accepted for the adjacent rejected-ACL case), unlike a stale success, which wrongly
    /// authorizes. This proves the two outcomes really get different windows, not the same constant twice.
    @Test
    func `a cached rejection uses the persistent rejection TTL`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let trusted = try fixture.trustedApplication(at: fixture.helper)
        let mismatched = try fixture.makeExecutable(named: "Mismatched", from: "/bin/echo")
        let path = mismatched.path
        let start = Date()

        let first = KeychainAccessPreflight.trustedApplication(trusted, validatesExecutableAt: path, now: start)
        #expect(first == OSStatus(CSSMERR_CSP_VERIFY_FAILED))
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: path) == 1)

        // Rejections remain cached within their explicit cooldown.
        let stillCached = KeychainAccessPreflight.trustedApplication(
            trusted,
            validatesExecutableAt: path,
            now: start.addingTimeInterval(1))
        #expect(stillCached == first)
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: path) == 1)

        // Past the rejection window: revalidated.
        let afterExpiry = KeychainAccessPreflight.trustedApplication(
            trusted,
            validatesExecutableAt: path,
            now: start.addingTimeInterval(KeychainAccessPreflight.rejectionCacheTTL + 1))
        #expect(afterExpiry == first)
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: path) == 2)
    }

    /// Regression test for caching a transient/unrecognized validator status: only a confirmed
    /// `CSSMERR_CSP_VERIFY_FAILED` rejection is a settled, non-retryable fact. Anything else must never be
    /// written to the cache, or it would silently defeat the bounded retry recovery elsewhere in this file
    /// and freeze a provider's reads on a transient error for the entry's lifetime. A directory path is
    /// real (so it has a valid filesystem identity and a cache key can be formed) but is not a codesign-able
    /// executable, so the validator returns neither cacheable outcome.
    @Test
    func `an unrecognized validator status is never cached`() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let trusted = try fixture.trustedApplication(at: fixture.helper)
        let directoryPath = fixture.root.path

        let first = KeychainAccessPreflight.trustedApplication(trusted, validatesExecutableAt: directoryPath)
        #expect(first != errSecSuccess)
        #expect(first != OSStatus(CSSMERR_CSP_VERIFY_FAILED))
        #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(path: directoryPath) == 1)

        // If this were cached, the count would stay at 1. It does not: every call re-validates.
        for expectedCount in 2...4 {
            _ = KeychainAccessPreflight.trustedApplication(trusted, validatesExecutableAt: directoryPath)
            #expect(KeychainAccessPreflight.trustedApplicationValidationCallCountForTesting(
                path: directoryPath) == expectedCount)
        }
    }

    /// Constructs a `SecTrustedApplication` from an explicit `SecRequirement`, bypassing the on-disk
    /// path entirely — this is how a persisted ACL entry's trust object is really formed
    /// (`TrustedApplication(const std::string &path, SecRequirementRef requirement)`), letting the test
    /// build two entries that share a path but differ only in their embedded requirement.
    /// `SecTrustedApplicationCreateFromRequirement` is not bridged into Swift's `Security` module, so it
    /// is resolved the same way the production code resolves other legacy Security symbols.
    private enum RequirementTrustedApplication {
        private typealias CreateFromRequirementFunction = @convention(c) (
            UnsafePointer<CChar>?,
            SecRequirement?,
            UnsafeMutablePointer<SecTrustedApplication?>) -> OSStatus

        static func make(description: String, requirement expression: String) throws -> SecTrustedApplication {
            var requirement: SecRequirement?
            let requirementStatus = SecRequirementCreateWithString(
                expression as CFString,
                SecCSFlags(),
                &requirement)
            #expect(requirementStatus == errSecSuccess)
            let requirement2 = try #require(requirement)

            guard let handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW),
                  let symbol = dlsym(handle, "SecTrustedApplicationCreateFromRequirement")
            else {
                Issue.record("SecTrustedApplicationCreateFromRequirement unavailable")
                throw CocoaError(.featureUnsupported)
            }
            let create = unsafeBitCast(symbol, to: CreateFromRequirementFunction.self)
            var app: SecTrustedApplication?
            let status = description.withCString { create($0, requirement2, &app) }
            #expect(status == errSecSuccess)
            return try #require(app)
        }
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
