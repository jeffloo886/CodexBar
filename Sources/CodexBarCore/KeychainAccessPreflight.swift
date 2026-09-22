import Foundation

#if os(macOS)
import Darwin
import LocalAuthentication
import os.lock
import Security
#endif

public struct KeychainPromptContext: Sendable {
    public enum Kind: Sendable {
        case claudeOAuth
        case codexCookie
        case claudeCookie
        case cursorCookie
        case opencodeCookie
        case factoryCookie
        case zaiToken
        case syntheticToken
        case copilotToken
        case kimiToken
        case minimaxCookie
        case minimaxToken
        case augmentCookie
        case ampCookie
    }

    public let kind: Kind
    public let service: String
    public let account: String?

    public init(kind: Kind, service: String, account: String?) {
        self.kind = kind
        self.service = service
        self.account = account
    }
}

public enum KeychainPromptHandler {
    final class HandlerStore: @unchecked Sendable {
        let handler: (KeychainPromptContext) -> Void

        init(handler: @escaping (KeychainPromptContext) -> Void) {
            self.handler = handler
        }
    }

    @TaskLocal private static var taskHandlerStore: HandlerStore?
    public nonisolated(unsafe) static var handler: ((KeychainPromptContext) -> Void)?

    public static func notify(_ context: KeychainPromptContext) {
        _ = self.notifyIfHandled(context)
    }

    @discardableResult
    static func notifyIfHandled(_ context: KeychainPromptContext) -> Bool {
        if let taskHandlerStore {
            taskHandlerStore.handler(context)
            return true
        }
        guard let handler else { return false }
        handler(context)
        return true
    }

    #if DEBUG
    static func withHandlerForTesting<T>(
        _ handler: ((KeychainPromptContext) -> Void)?,
        operation: () throws -> T) rethrows -> T
    {
        try self.$taskHandlerStore.withValue(handler.map(HandlerStore.init(handler:))) {
            try operation()
        }
    }

    static func withHandlerForTesting<T>(
        _ handler: ((KeychainPromptContext) -> Void)?,
        operation: () async throws -> T) async rethrows -> T
    {
        try await self.$taskHandlerStore.withValue(handler.map(HandlerStore.init(handler:))) {
            try await operation()
        }
    }
    #endif
}

public enum KeychainAccessPreflight {
    public enum Outcome: Sendable, Equatable {
        case allowed
        /// The item is readable, but its decrypt ACL does not trust the current executable.
        case interactionRequired
        /// The check could not complete without UI (for example a locked keychain), or the decrypt
        /// ACL could not be inspected; unlike `interactionRequired`, nothing proved a stable rejection.
        case temporarilyUnavailable
        case notFound
        case failure(Int)

        public var requiresInteraction: Bool {
            switch self {
            case .interactionRequired, .temporarilyUnavailable:
                true
            case .allowed, .failure, .notFound:
                false
            }
        }
    }

    private struct GenericPasswordKey: Hashable {
        let service: String
        let account: String?
    }

    private final class GenericPasswordCheckMemo: @unchecked Sendable {
        private let lock = NSLock()
        private var outcomes: [GenericPasswordKey: Outcome] = [:]

        func invalidate(service: String) {
            self.lock.withLock {
                self.outcomes = self.outcomes.filter { $0.key.service != service }
            }
        }

        func outcome(
            for key: GenericPasswordKey,
            check: () -> Outcome) -> Outcome
        {
            self.lock.lock()
            defer { self.lock.unlock() }
            if let outcome = self.outcomes[key] {
                return outcome
            }
            let outcome = check()
            self.outcomes[key] = outcome
            return outcome
        }
    }

    private static let log = CodexBarLog.logger(LogCategories.keychainPreflight)
    @TaskLocal private static var genericPasswordCheckMemo: GenericPasswordCheckMemo?

    #if DEBUG
    final class CheckGenericPasswordOverrideStore: @unchecked Sendable {
        let check: (String, String?) -> Outcome
        let retryDelay: () -> Void

        init(check: @escaping (String, String?) -> Outcome, retryDelay: @escaping () -> Void) {
            self.check = check
            self.retryDelay = retryDelay
        }
    }

    @TaskLocal private static var taskCheckGenericPasswordOverrideStore: CheckGenericPasswordOverrideStore?

    static var hasCheckGenericPasswordOverrideForTesting: Bool {
        self.taskCheckGenericPasswordOverrideStore != nil
    }

    static func withCheckGenericPasswordOverrideForTesting<T>(
        _ override: ((String, String?) -> Outcome)?,
        retryDelay: @escaping () -> Void = {},
        operation: () throws -> T) rethrows -> T
    {
        try self.$taskCheckGenericPasswordOverrideStore.withValue(
            override.map { CheckGenericPasswordOverrideStore(check: $0, retryDelay: retryDelay) })
        {
            try operation()
        }
    }

    static func withCheckGenericPasswordOverrideForTesting<T>(
        _ override: ((String, String?) -> Outcome)?,
        retryDelay: @escaping () -> Void = {},
        isolation _: isolated (any Actor)? = #isolation,
        operation: () async throws -> T) async rethrows -> T
    {
        try await self.$taskCheckGenericPasswordOverrideStore.withValue(
            override.map { CheckGenericPasswordOverrideStore(check: $0, retryDelay: retryDelay) })
        {
            try await operation()
        }
    }
    #endif

    /// Reuses identical no-UI generic-password preflights within one synchronous operation.
    /// The scope is deliberately short-lived because Keychain items and their ACLs can change.
    public static func withMemoizedGenericPasswordChecks<T>(
        _ operation: () throws -> T) rethrows -> T
    {
        try self.$genericPasswordCheckMemo.withValue(GenericPasswordCheckMemo()) {
            try operation()
        }
    }

    /// Async counterpart used by one complete provider refresh. Task-local inheritance shares the same
    /// operation memo with child provider tasks, while its lifetime still ends when that refresh finishes.
    public static func withMemoizedGenericPasswordChecks<T>(
        _ operation: () async throws -> T,
        isolation _: isolated (any Actor)? = #isolation) async rethrows -> T
    {
        try await self.$genericPasswordCheckMemo.withValue(GenericPasswordCheckMemo()) {
            try await operation()
        }
    }

    public static func checkGenericPassword(service: String, account: String?) -> Outcome {
        let key = GenericPasswordKey(service: service, account: account)
        if let memo = self.genericPasswordCheckMemo {
            return memo.outcome(for: key) {
                self.checkGenericPasswordUncached(service: service, account: account)
            }
        }
        return self.checkGenericPasswordUncached(service: service, account: account)
    }

    static func invalidateGenericPasswordChecks(service: String) {
        self.genericPasswordCheckMemo?.invalidate(service: service)
    }

    /// Retry only inconclusive no-UI checks; the operation memo above stores their final outcome.
    private static let temporarilyUnavailableRetryCount = 3
    private static let temporarilyUnavailableRetryDelayMicroseconds: UInt32 = 30000

    private static func checkGenericPasswordUncached(service: String, account: String?) -> Outcome {
        #if os(macOS)
        var outcome = self.performGenericPasswordPreflightAttempt(service: service, account: account)
        var attempt = 1
        while case .temporarilyUnavailable = outcome, attempt < self.temporarilyUnavailableRetryCount {
            self.waitBeforePreflightRetry()
            outcome = self.performGenericPasswordPreflightAttempt(service: service, account: account)
            attempt += 1
        }
        return outcome
        #else
        return .notFound
        #endif
    }

    #if os(macOS)
    private static func waitBeforePreflightRetry() {
        #if DEBUG
        if let override = self.taskCheckGenericPasswordOverrideStore {
            override.retryDelay()
            return
        }
        #endif
        usleep(self.temporarilyUnavailableRetryDelayMicroseconds)
    }

    private static func performGenericPasswordPreflightAttempt(service: String, account: String?) -> Outcome {
        #if DEBUG
        if let override = self.taskCheckGenericPasswordOverrideStore {
            return override.check(service, account)
        }
        #endif
        guard !KeychainAccessGate.isDisabled else { return .notFound }
        let query = self.makeGenericPasswordPreflightQuery(service: service, account: account)

        var result: AnyObject?
        let status = KeychainSecurity.copyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let item = self.keychainItem(fromPreflightResult: result) else {
                self.log.info(
                    "Keychain preflight could not inspect the item's decrypt ACL",
                    metadata: ["service": service])
                return .temporarilyUnavailable
            }
            switch self.evaluateDecryptACL(item: item) {
            case .allowed:
                self.log.debug("Keychain preflight allowed", metadata: ["service": service])
                return .allowed
            case .rejected:
                self.log.info(
                    "Keychain preflight requires interaction for the current process",
                    metadata: ["service": service])
                return .interactionRequired
            case .indeterminate:
                self.log.info(
                    "Keychain preflight could not inspect the item's decrypt ACL",
                    metadata: ["service": service])
                return .temporarilyUnavailable
            }
        case errSecItemNotFound:
            self.log.debug(
                "Keychain preflight not found",
                metadata: ["service": service])
            return .notFound
        case errSecInteractionNotAllowed:
            self.log.info(
                "Keychain preflight requires interaction",
                metadata: ["service": service])
            return .temporarilyUnavailable
        default:
            self.log.warning(
                "Keychain preflight failed",
                metadata: ["service": service, "status": "\(status)"])
            return .failure(Int(status))
        }
    }
    #endif

    #if os(macOS)
    static func makeGenericPasswordPreflightQuery(service: String, account: String?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitOne,
            // Preflight should never trigger UI. Avoid requesting the secret payload (`kSecReturnData`) because
            // some macOS configurations have been observed to show the legacy keychain prompt even with UI-fail.
            // The item reference lets us inspect its decrypt ACL before deciding whether a data query is safe.
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true,
        ]
        KeychainNoUIQuery.apply(to: &query)
        if let account {
            query[kSecAttrAccount as String] = account
        }
        return query
    }

    static func evaluateDecryptACL(
        trustedApplicationValidationStatuses: [OSStatus?]?,
        promptSelector: SecKeychainPromptSelector) -> DecryptACLEvaluation
    {
        // Any non-zero selector can require authentication based on the caller's signature state.
        // A background preflight cannot prove that condition safe, so fail closed.
        guard promptSelector.rawValue == 0 else { return .rejected }
        // A nil application list means the ACL does not restrict callers. For an explicit list, at least one
        // stored code-signing requirement must validate against the invoking executable. A path match alone is
        // insufficient: legacy ACLs can retain an old build's signature at the same path and still show UI.
        guard let trustedApplicationValidationStatuses else { return .allowed }
        if trustedApplicationValidationStatuses.contains(errSecSuccess) {
            return .allowed
        }
        // The legacy validator reports a completed signature mismatch as CSSMERR_CSP_VERIFY_FAILED.
        // Missing symbols and other errors cannot establish that the ACL rejects this executable.
        return trustedApplicationValidationStatuses.allSatisfy { $0 == OSStatus(CSSMERR_CSP_VERIFY_FAILED) }
            ? .rejected : .indeterminate
    }

    private static func keychainItem(fromPreflightResult result: AnyObject?) -> SecKeychainItem? {
        guard let attributes = result as? [String: Any],
              let value = attributes[kSecValueRef as String]
        else { return nil }
        return unsafeDowncast(value as AnyObject, to: SecKeychainItem.self)
    }

    /// `.rejected` means validation ran to completion and no trusted application matched this
    /// executable — a stable outcome. `.indeterminate` means inspection itself failed and the
    /// result may differ on retry.
    enum DecryptACLEvaluation: Equatable {
        case allowed
        case rejected
        case indeterminate
    }

    private static func evaluateDecryptACL(item: SecKeychainItem) -> DecryptACLEvaluation {
        guard let copyItemAccess = self.securityFunction(
            named: "SecKeychainItemCopyAccess",
            as: SecKeychainItemCopyAccessFunction.self),
            let copyMatchingACLs = self.securityFunction(
                named: "SecAccessCopyMatchingACLList",
                as: SecAccessCopyMatchingACLListFunction.self),
            let copyACLContents = self.securityFunction(
                named: "SecACLCopyContents",
                as: SecACLCopyContentsFunction.self)
        else { return .indeterminate }

        var access: SecAccess?
        guard copyItemAccess(item, &access) == errSecSuccess,
              let access,
              let rawACLs = copyMatchingACLs(access, kSecACLAuthorizationDecrypt)?.takeRetainedValue(),
              let acls = rawACLs as? [SecACL],
              !acls.isEmpty
        else { return .indeterminate }

        let currentPaths = KeychainCacheStore.invokingApplicationPathsForCacheAccess()
        guard !currentPaths.isEmpty else { return .indeterminate }

        var inspectionIncomplete = false
        for acl in acls {
            var applications: CFArray?
            var description: CFString?
            var selector = SecKeychainPromptSelector()
            guard copyACLContents(acl, &applications, &description, &selector) == errSecSuccess else {
                inspectionIncomplete = true
                continue
            }
            guard let applications else {
                if self.evaluateDecryptACL(
                    trustedApplicationValidationStatuses: nil,
                    promptSelector: selector) == .allowed
                {
                    return .allowed
                }
                continue
            }
            guard let trustedApplications = applications as? [SecTrustedApplication] else {
                inspectionIncomplete = true
                continue
            }
            let validationResults = trustedApplications.flatMap { application in
                currentPaths.map { currentPath in
                    self.trustedApplication(application, validatesExecutableAt: currentPath)
                }
            }
            switch self.evaluateDecryptACL(
                trustedApplicationValidationStatuses: validationResults,
                promptSelector: selector)
            {
            case .allowed:
                return .allowed
            case .indeterminate:
                inspectionIncomplete = true
            case .rejected:
                break
            }
        }
        return inspectionIncomplete ? .indeterminate : .rejected
    }

    /// Validating a stored trusted application against an executable runs a full static code-signature
    /// check of that executable's bundle — reading and hashing every sealed resource, which costs tens of
    /// milliseconds for a large app. The decrypt ACL is re-read on every preflight, so the same
    /// (trusted application, executable) pair gets revalidated many times per refresh across providers and
    /// browsers without the answer ever changing.
    ///
    /// A completed rejection is memoized on the trusted application's full external representation (not
    /// just its path — `SecTrustedApplicationCopyData` returns only the stored path string, so two ACL
    /// entries for the same install path but different embedded code-signing requirements would otherwise
    /// collide; `SecTrustedApplicationCopyExternalRepresentation` serializes the whole ACL subject,
    /// including the requirement or legacy hash that `verifyToDisk` actually checks) plus the executable's
    /// filesystem identity, so a replaced or rewritten binary is revalidated immediately rather than at
    /// the entry's expiry. Successful validation is deliberately not retained in this process-wide cache:
    /// `SecStaticCodeCheckValidity` also covers sealed bundle resources, and no cheap identity can reliably
    /// detect every resource mutation. Successful preflights are deduplicated only by the operation-scoped
    /// generic-password memo above, whose lifetime is bounded by the current refresh/read operation.
    ///
    /// Only a confirmed `CSSMERR_CSP_VERIFY_FAILED` rejection is retained in the process-wide cache.
    /// Successes are scoped to the surrounding generic-password operation. Anything else (a locked
    /// keychain, an I/O error, or any other transient failure the validator can return) is never written
    /// to this cache, so it falls through to a real validation on every call — preserving the existing
    /// bounded retry recovery in `checkGenericPasswordUncached` instead of letting a single transient
    /// error freeze a provider's reads for the entry's lifetime.
    ///
    /// `SecStaticCodeCheckValidity`'s default flags validate every sealed resource under the bundle, not
    /// just the executable file. Reusing a successful process-wide result after a resource edit would let
    /// an obsolete grant reach a credential-read attempt, so only completed signature mismatches use the
    /// persistent rejection cooldown. Nothing about the ACL evaluation itself is cached — callers still
    /// read the live ACL and prompt selector on every preflight, and successful validation is shared only
    /// inside the explicit operation/refresh scope described above.
    static func trustedApplication(
        _ application: SecTrustedApplication,
        validatesExecutableAt path: String,
        now: Date = Date()) -> OSStatus?
    {
        guard let validate = self.securityFunction(
            named: "SecTrustedApplicationValidateWithPath",
            as: SecTrustedApplicationValidateWithPathFunction.self)
        else { return nil }
        guard let key = self.validationCacheKey(for: application, path: path) else {
            // Without a stable key the verdict cannot be memoized safely; validate as before.
            return self.performValidation(application, using: validate, at: path)
        }
        if let cached = self.validationCache.withLock({ $0[key] }),
           cached.expiresAt > now
        {
            return cached.status
        }
        let status = self.performValidation(application, using: validate, at: path)
        guard let ttl = self.cacheTTL(for: status) else {
            // A transient outcome: leave any existing entry alone and never write one, so the next call
            // — including the existing retry loop's own follow-up attempts — always re-validates.
            return status
        }
        self.validationCache.withLock { cache in
            // Bounded so a long-lived process cannot accumulate entries. The working set is one trusted
            // application per ACL entry times the invoking executable paths, far below this bound.
            if cache.count >= self.validationCacheCapacity {
                cache.removeAll(keepingCapacity: true)
            }
            cache[key] = CachedValidation(status: status, expiresAt: now.addingTimeInterval(ttl))
        }
        return status
    }

    /// `nil` means the outcome must never be cached. Only the two outcomes `verifyToDisk` can return as a
    /// settled, non-retryable fact are eligible — an unrecognized status is treated as transient rather
    /// than assumed safe to reuse.
    private static func cacheTTL(for status: OSStatus) -> TimeInterval? {
        switch status {
        case errSecSuccess:
            nil
        case OSStatus(CSSMERR_CSP_VERIFY_FAILED):
            self.rejectionCacheTTL
        default:
            nil
        }
    }

    private static func performValidation(
        _ application: SecTrustedApplication,
        using validate: SecTrustedApplicationValidateWithPathFunction,
        at path: String) -> OSStatus
    {
        #if DEBUG
        self.validationCallCounts.withLock { $0[path, default: 0] += 1 }
        #endif
        return path.withCString { validate(application, $0) }
    }

    private static func validationCacheKey(
        for application: SecTrustedApplication,
        path: String) -> ValidationCacheKey?
    {
        guard let representation = self.trustedApplicationExternalRepresentation(application),
              let executable = ExecutableIdentity(path: path)
        else { return nil }
        return ValidationCacheKey(trustedApplicationRepresentation: representation, path: path, executable: executable)
    }

    /// The full serialized ACL subject for this trusted application — its embedded code-signing
    /// requirement (or, for legacy entries, hash), not merely the path it was constructed from. Two
    /// `SecTrustedApplication` objects sharing a path but holding different requirements (for example, a
    /// stale ACL entry alongside a freshly repaired one for the same install path) produce different
    /// representations here, whereas `SecTrustedApplicationCopyData` would return identical bytes for both.
    private static func trustedApplicationExternalRepresentation(_ application: SecTrustedApplication) -> Data? {
        guard let copyExternal = self.securityFunction(
            named: "SecTrustedApplicationCopyExternalRepresentation",
            as: SecTrustedApplicationCopyExternalRepresentationFunction.self)
        else { return nil }
        var raw: Unmanaged<CFData>?
        guard copyExternal(application, &raw) == errSecSuccess, let raw else { return nil }
        return raw.takeRetainedValue() as Data
    }

    /// Filesystem identity of an executable. Any rewrite, replacement, or truncation changes at least one
    /// field, so a memoized verdict does not outlive the specific binary it was computed against.
    private struct ExecutableIdentity: Hashable {
        let device: Int64
        let inode: UInt64
        let size: Int64
        let modifiedSeconds: Int64
        let modifiedNanoseconds: Int64

        init?(path: String) {
            var info = stat()
            guard stat(path, &info) == 0 else { return nil }
            self.device = Int64(info.st_dev)
            self.inode = UInt64(info.st_ino)
            self.size = Int64(info.st_size)
            self.modifiedSeconds = Int64(info.st_mtimespec.tv_sec)
            self.modifiedNanoseconds = Int64(info.st_mtimespec.tv_nsec)
        }
    }

    private struct ValidationCacheKey: Hashable {
        let trustedApplicationRepresentation: Data
        let path: String
        let executable: ExecutableIdentity
    }

    private struct CachedValidation {
        let status: OSStatus
        let expiresAt: Date
    }

    static let validationCacheCapacity = 64
    /// A rejection reused past its truth only delays a legitimate read, the same risk #3301's cooldown
    /// already accepted for this file's adjacent rejected-ACL case — reuse that precedent's window.
    static let rejectionCacheTTL: TimeInterval = 5 * 60
    private static let validationCache =
        OSAllocatedUnfairLock<[ValidationCacheKey: CachedValidation]>(initialState: [:])

    #if DEBUG
    /// Keyed by path so concurrently running suites cannot perturb each other's counts.
    private static let validationCallCounts = OSAllocatedUnfairLock<[String: Int]>(initialState: [:])

    /// Number of real `SecTrustedApplicationValidateWithPath` calls made for `path`.
    static func trustedApplicationValidationCallCountForTesting(path: String) -> Int {
        self.validationCallCounts.withLock { $0[path] ?? 0 }
    }

    static var trustedApplicationValidationCacheCountForTesting: Int {
        self.validationCache.withLock { $0.count }
    }
    #endif

    private typealias SecKeychainItemCopyAccessFunction = @convention(c) (
        SecKeychainItem,
        UnsafeMutablePointer<SecAccess?>) -> OSStatus
    private typealias SecAccessCopyMatchingACLListFunction = @convention(c) (
        SecAccess,
        CFTypeRef) -> Unmanaged<CFArray>?
    private typealias SecACLCopyContentsFunction = @convention(c) (
        SecACL,
        UnsafeMutablePointer<CFArray?>,
        UnsafeMutablePointer<CFString?>,
        UnsafeMutablePointer<SecKeychainPromptSelector>) -> OSStatus
    private typealias SecTrustedApplicationValidateWithPathFunction = @convention(c) (
        SecTrustedApplication,
        UnsafePointer<CChar>) -> OSStatus
    private typealias SecTrustedApplicationCopyExternalRepresentationFunction = @convention(c) (
        SecTrustedApplication,
        UnsafeMutablePointer<Unmanaged<CFData>?>) -> OSStatus

    private nonisolated(unsafe) static let securityFrameworkHandle: UnsafeMutableRawPointer? = dlopen(
        "/System/Library/Frameworks/Security.framework/Security",
        RTLD_NOW)

    private static func securityFunction<T>(named name: String, as _: T.Type) -> T? {
        guard let securityFrameworkHandle,
              let symbol = dlsym(securityFrameworkHandle, name)
        else { return nil }
        return unsafeBitCast(symbol, to: T.self)
    }
    #endif
}
