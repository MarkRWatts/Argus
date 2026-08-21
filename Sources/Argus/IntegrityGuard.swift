import Foundation
import CryptoKit
import Security

/// Detects (but cannot prevent) out-of-band edits to the on-disk files that
/// back security-relevant state — `rules-state.json` (which rules are
/// disabled) and `allowlist.json` (which rule/executable pairs are
/// suppressed). Both are gated behind Touch ID/password in the UI
/// (`RuleStore.requestToggle`, `AllowlistStore.requestAllow`/`requestRemove`),
/// but that only guards the UI path: the files themselves are plain,
/// same-user-writable JSON, and any process running as this user — in
/// particular the exact kind of LOLBin-style local attacker Argus watches
/// for — can rewrite them directly to blind a detection silently.
///
/// True prevention would require privilege separation (a separate,
/// higher-privileged process owning these files), which is out of scope
/// here. This is evidence, not prevention: every legitimate write goes
/// through `recordAuthenticatedWrite(of:)`, which records an HMAC of the
/// file's contents in a keychain-protected sidecar. At launch, `verify(_:)`
/// recomputes that HMAC and compares it — a mismatch means the file changed
/// through some path other than an authenticated Argus write, and the app
/// reports that as a critical event so the tamper itself becomes visible in
/// the feed, even though it can't be blocked in the first place.
enum IntegrityVerdict: Equatable {
    /// The file's current contents match the last recorded MAC.
    case verified
    /// No MAC was on record for this file yet, so its current contents were
    /// adopted as the baseline. Expected the first time a file is verified
    /// (e.g. a fresh install, or a file that predates this feature).
    case baselineEstablished
    /// The file's current contents don't match the last recorded MAC — it
    /// was modified by something other than an authenticated Argus write.
    case tampered
    /// Verification couldn't be performed at all: no signing key is
    /// available (Keychain access failed or is unavailable, as happens
    /// under `swift test`/CI), or the file couldn't be read.
    case unverifiable
}

/// Supplies the symmetric key `IntegrityGuard` uses to MAC file contents.
/// Abstracted so tests can supply a fixed, in-memory key instead of touching
/// the real Keychain.
protocol IntegrityKeyProvider {
    /// Returns the signing key, or `nil` if one isn't available. A `nil` key
    /// disables verification gracefully rather than crashing — see
    /// `KeychainIntegrityKeyProvider`.
    func key() -> Data?
}

/// Production key provider: a random 32-byte key stored as a generic
/// password in the user's login keychain (service "Argus", account
/// "integrity-key"), created lazily the first time it's needed. Keeping the
/// key in the Keychain rather than alongside the guarded files is the whole
/// point — an attacker who can rewrite `rules-state.json` in place has no
/// reason to also have Keychain access, so the MAC stays trustworthy even
/// against an attacker who knows exactly how this scheme works.
///
/// Any Keychain error (locked, unavailable, sandboxed test environment with
/// no keychain access, denied) is treated the same as "no key": returns
/// `nil` rather than throwing or crashing. This is what makes it safe to run
/// under `swift test`/CI, where Keychain access typically isn't available at
/// all — verification just reports `.unverifiable` instead.
struct KeychainIntegrityKeyProvider: IntegrityKeyProvider {
    private static let service = "Argus"
    private static let account = "integrity-key"
    private static let keyLength = 32

    func key() -> Data? {
        if let existing = readKey() {
            return existing
        }
        var bytes = [UInt8](repeating: 0, count: Self.keyLength)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            DiagnosticsLog.write("integrity-guard: failed to generate a key (SecRandomCopyBytes)")
            return nil
        }
        let generated = Data(bytes)
        guard write(generated) else {
            DiagnosticsLog.write("integrity-guard: failed to store a new key in the Keychain")
            return nil
        }
        return generated
    }

    private func readKey() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return data
    }

    private func write(_ data: Data) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }
}

/// See the type-level rationale above (evidence, not prevention). Owns one
/// sidecar file mapping guarded files' full paths to a hex HMAC-SHA256 of
/// their last authenticated contents, so a single guard instance can cover
/// multiple files (`rules-state.json`, `allowlist.json`, ...). Keyed by full
/// path, not filename — a store pointed at a same-named file elsewhere (a
/// test's temp copy, a second profile) must never collide with the real
/// file's recorded MAC.
final class IntegrityGuard {
    private let keyProvider: IntegrityKeyProvider
    private let sidecarURL: URL

    /// Shared production instance backed by the real Keychain. Individual
    /// stores default their `integrityGuard` init parameter to this so
    /// callers don't have to wire one up explicitly; tests inject their own
    /// instance (fixed key provider, temp-dir sidecar) instead of using this.
    static let shared = IntegrityGuard()

    init(keyProvider: IntegrityKeyProvider = KeychainIntegrityKeyProvider(), sidecarURL: URL? = nil) {
        self.keyProvider = keyProvider
        if let sidecarURL {
            self.sidecarURL = sidecarURL
        } else {
            let dir = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/Argus", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            // Keep the shared Argus support directory owner-only (see EventStore).
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
            self.sidecarURL = dir.appendingPathComponent("integrity.json")
        }
    }

    /// Call this after every legitimate, already-authenticated write to a
    /// guarded file — it recomputes the file's MAC from what's on disk right
    /// now and persists it, so the next `verify(_:)` treats this content as
    /// trusted.
    func recordAuthenticatedWrite(of fileURL: URL) {
        guard let key = keyProvider.key() else {
            DiagnosticsLog.write("integrity-guard: no key available, cannot record \(fileURL.lastPathComponent)")
            return
        }
        guard let mac = mac(for: fileURL, key: key) else {
            DiagnosticsLog.write("integrity-guard: could not read \(fileURL.lastPathComponent) to record its MAC")
            return
        }
        var sidecar = loadSidecar()
        sidecar[fileURL.path] = mac
        saveSidecar(sidecar)
    }

    /// Recomputes `fileURL`'s MAC and compares it against what was last
    /// recorded via `recordAuthenticatedWrite(of:)`.
    ///
    /// After reporting `.tampered`, this re-baselines the file (records its
    /// new MAC as though it had just been authenticated) rather than leaving
    /// the mismatch on record. Without that, the exact same tamper would
    /// re-fire as a fresh `.tampered` verdict on every subsequent launch —
    /// once the app has surfaced the tamper as a critical event, there's
    /// nothing more for a repeat report to add, and re-baselining is what
    /// lets a *new* out-of-band edit be distinguished from the same old one.
    func verify(_ fileURL: URL) -> IntegrityVerdict {
        guard let key = keyProvider.key() else {
            DiagnosticsLog.write("integrity-guard: no key available, cannot verify \(fileURL.lastPathComponent)")
            return .unverifiable
        }
        guard let currentMAC = mac(for: fileURL, key: key) else {
            DiagnosticsLog.write("integrity-guard: could not read \(fileURL.lastPathComponent) to verify it")
            return .unverifiable
        }

        var sidecar = loadSidecar()
        guard let recordedMAC = sidecar[fileURL.path] else {
            sidecar[fileURL.path] = currentMAC
            saveSidecar(sidecar)
            DiagnosticsLog.write("integrity-guard: establishing baseline for \(fileURL.lastPathComponent)")
            return .baselineEstablished
        }

        guard recordedMAC == currentMAC else {
            sidecar[fileURL.path] = currentMAC
            saveSidecar(sidecar)
            return .tampered
        }
        return .verified
    }

    private func mac(for fileURL: URL, key: Data) -> String? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        let code = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
        return Data(code).map { String(format: "%02x", $0) }.joined()
    }

    private func loadSidecar() -> [String: String] {
        guard let data = try? Data(contentsOf: sidecarURL),
              let decoded = try? JSONDecoder().decode([String: String].self, from: data) else { return [:] }
        return decoded
    }

    private func saveSidecar(_ sidecar: [String: String]) {
        guard let data = try? JSONEncoder().encode(sidecar) else { return }
        try? data.write(to: sidecarURL, options: .atomic)
        // An atomic write replaces the file with a fresh inode carrying
        // default (umask) permissions, so re-assert owner-only here (see
        // EventStore.trimIfNeeded).
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: sidecarURL.path)
    }

    /// Builds the critical synthetic `ProcessEvent` reported when `verify(_:)`
    /// returns `.tampered`. Pure (no filesystem, no Keychain) so it's
    /// trivially unit-testable; mirrors `PersistenceEventBuilder.makeEvent`'s
    /// pid/ppid-0 convention for events that describe a file, not an
    /// observed process.
    static func tamperEvent(for fileURL: URL) -> ProcessEvent {
        let filename = fileURL.lastPathComponent
        let rule = MatchedRule(
            name: "Detection state modified outside Argus",
            severity: .critical,
            technique: "T1562.001",
            explanation: "\(filename) was modified without going through Argus's authenticated (Touch ID/password) write path. " +
                "This is how a local attacker would silently disable a detection rule or allowlist a technique to hide their " +
                "own activity — the file's contents no longer match what Argus last wrote."
        )
        return ProcessEvent(pid: 0, ppid: 0, executable: filename, command: fileURL.path, rules: [rule], timestamp: Date())
    }
}
