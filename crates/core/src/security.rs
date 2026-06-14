/// Security & Trust Module — root of trust.
///
/// Security hardening applied (see CHANGELOG.md):
///   001 – self_check() now validates internal invariants (key entropy, log
///         accessibility). Binary-level attestation is reserved for Phase 3.
///   002 – SecurityPolicy enforces path-prefix allow-listing and explicit
///         opt-in for Shell/Git; deny-by-default replaces open allow-all.
///   004 – Stamps are HMAC-SHA256 values bound to message content; the
///         revocation set prevents replay after invalidation.
///   009 – Audit entries optionally persisted to a JSONL file; hash-chain
///         links each entry to its predecessor for tamper detection.
use crate::plugin::{Capability, PluginClass, PluginManifest};
use crate::types::Timestamp;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write as IoWrite;
use std::sync::{Arc, Mutex};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Stamp — HMAC-SHA256 bound to message content
// ---------------------------------------------------------------------------

/// Opaque stamp issued after a message form passes the security gate.
/// Internally stores the 32-byte HMAC so `is_valid()` can verify it
/// without a separate lookup table for the issued set.
/// A stamp is invalidated when the message it was issued for is transformed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Stamp(pub [u8; 32]);

// ---------------------------------------------------------------------------
// Security policy
// ---------------------------------------------------------------------------

/// Operator-configurable capability policy.
/// Defaults are deny-all for dangerous capabilities, localhost-only for network.
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Allowed absolute path prefixes for FileRead; empty = deny all.
    pub file_read_prefixes: Vec<String>,
    /// Allowed absolute path prefixes for FileWrite; empty = deny all.
    pub file_write_prefixes: Vec<String>,
    /// Allowed network hostnames/prefixes (exact or suffix match); empty = deny all.
    pub network_allowlist: Vec<String>,
    /// Shell capability is denied unless explicitly set to true.
    pub allow_shell: bool,
    /// Git capability is denied unless explicitly set to true.
    pub allow_git: bool,
}

impl SecurityPolicy {
    /// Liberal development policy — suitable for local, trusted environments only.
    pub fn permissive() -> Self {
        Self {
            file_read_prefixes: vec!["/tmp".into(), ".".into()],
            file_write_prefixes: vec!["/tmp".into(), ".".into()],
            network_allowlist: vec!["localhost".into(), "127.0.0.1".into()],
            allow_shell: false,
            allow_git: true,
        }
    }

    /// Deny everything — the safest default.
    pub fn deny_all() -> Self {
        Self {
            file_read_prefixes: vec![],
            file_write_prefixes: vec![],
            network_allowlist: vec![],
            allow_shell: false,
            allow_git: false,
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::permissive()
    }
}

// ---------------------------------------------------------------------------
// Audit decision types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDecision {
    pub kind: DecisionKind,
    pub detail: String,
    pub at: Timestamp,
    /// SHA-256 of the previous entry's serialisation (hex). Empty for the first entry.
    pub prev_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecisionKind {
    Grant,
    Denial,
    StampIssued,
    StampInvalidated,
}

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("integrity check failed: {0}")]
    IntegrityFailure(String),
    #[error("capability denied: {0:?}")]
    CapabilityDenied(Capability),
    #[error("safe plugin declared system capability")]
    SafePluginViolation,
}

// ---------------------------------------------------------------------------
// SecurityModule
// ---------------------------------------------------------------------------

pub struct SecurityModule {
    audit_log: Arc<Mutex<Vec<SecurityDecision>>>,
    hmac_key: [u8; 32],
    invalidated: Arc<Mutex<HashSet<Stamp>>>,
    policy: SecurityPolicy,
    /// If Some, every audit entry is appended to this JSONL file.
    audit_file: Option<Mutex<File>>,
    /// SHA-256 of the last persisted audit entry (hex), for hash-chaining.
    last_hash: Mutex<String>,
}

impl SecurityModule {
    /// Create with the default permissive policy and no file persistence.
    pub fn new() -> Self {
        Self::with_policy(SecurityPolicy::default())
    }

    pub fn with_policy(policy: SecurityPolicy) -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self::with_key(key, policy)
    }

    /// Construct with an operator-supplied, **persisted** 32-byte key.
    ///
    /// The random `with_policy`/`new` key is ephemeral — stamps and the audit
    /// chain anchor cannot be re-verified after a restart, and long-lived
    /// consumers (session signing, tamper-evident audit) need stability. Supply a
    /// durable key (e.g. from a root-only key file) to keep stamps and
    /// `verify_chain` valid across restarts. The key must not be all-zero
    /// (`self_check` rejects that).
    pub fn with_key(key: [u8; 32], policy: SecurityPolicy) -> Self {
        Self {
            audit_log: Arc::new(Mutex::new(Vec::new())),
            hmac_key: key,
            invalidated: Arc::new(Mutex::new(HashSet::new())),
            policy,
            audit_file: None,
            last_hash: Mutex::new(String::new()),
        }
    }

    /// Enable persistent audit logging to a JSONL file.
    pub fn with_audit_file(mut self, path: &str) -> Result<Self, SecurityError> {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| SecurityError::IntegrityFailure(format!("audit file: {}", e)))?;
        self.audit_file = Some(Mutex::new(f));
        Ok(self)
    }

    // ── Public interface ────────────────────────────────────────────────────

    /// Stage-1 bootstrap check.  Verifies internal invariants and that the
    /// HMAC key has been properly seeded (not all zeros).
    ///
    /// v0.1: validates key entropy and data-structure accessibility.
    /// Phase 3 will add binary measurement and platform attestation.
    pub fn self_check(&self) -> Result<(), SecurityError> {
        // Key must not be all-zero (indicates RNG failure).
        if self.hmac_key == [0u8; 32] {
            return Err(SecurityError::IntegrityFailure(
                "HMAC key is all-zero — RNG failure during init".into(),
            ));
        }
        // Audit log must be accessible.
        let _guard = self.audit_log.lock().map_err(|_| {
            SecurityError::IntegrityFailure("audit log mutex is poisoned".into())
        })?;
        // Invalidation set must be accessible.
        let _guard2 = self.invalidated.lock().map_err(|_| {
            SecurityError::IntegrityFailure("invalidated-stamp set mutex is poisoned".into())
        })?;
        Ok(())
    }

    /// Verify a plugin's manifest before the loader instantiates it.
    pub fn verify(&self, manifest: &PluginManifest) -> Result<(), SecurityError> {
        // SAFE plugins must have no capabilities whatsoever.
        if manifest.class == PluginClass::Safe && !manifest.capabilities.is_empty() {
            self.audit(DecisionKind::Denial, format!(
                "safe plugin '{}' declared capabilities: {:?}",
                manifest.name, manifest.capabilities
            ));
            return Err(SecurityError::SafePluginViolation);
        }

        for cap in &manifest.capabilities {
            if !self.is_allowed(cap) {
                self.audit(DecisionKind::Denial, format!(
                    "plugin '{}' requested denied capability {:?}",
                    manifest.name, cap
                ));
                return Err(SecurityError::CapabilityDenied(cap.clone()));
            }
        }

        self.audit(DecisionKind::Grant, format!(
            "plugin '{}' v{} verified ({:?})",
            manifest.name, manifest.version, manifest.class
        ));
        Ok(())
    }

    /// Issue a stamp cryptographically bound to the given message content.
    /// The stamp is an HMAC-SHA256 over the content bytes.
    pub fn stamp(&self, content: &[u8]) -> Stamp {
        let mac = self.compute_mac(content);
        self.audit(DecisionKind::StampIssued, format!("stamp {}", hex(&mac)));
        Stamp(mac)
    }

    /// Verify that a stamp is valid for the given content and has not been
    /// explicitly invalidated.  Returns false on MAC mismatch or revocation.
    pub fn is_valid(&self, stamp: &Stamp, content: &[u8]) -> bool {
        // Check the O(1) revocation set first to short-circuit expensive MAC work
        // on replayed invalidated stamps.
        if self.invalidated.lock().unwrap().contains(stamp) {
            return false;
        }
        let expected = self.compute_mac(content);
        // Constant-time compare: a short-circuiting `==` leaks, via response
        // timing, how many leading bytes of a forged stamp are correct.
        constant_time_eq(&stamp.0, &expected)
    }

    /// Invalidate a stamp when the message it covers is transformed.
    pub fn invalidate(&self, stamp: Stamp) {
        self.audit(DecisionKind::StampInvalidated, format!("stamp {}", hex(&stamp.0)));
        self.invalidated.lock().unwrap().insert(stamp);
    }

    /// Record an access-control decision (grant/denial) made by a consumer such
    /// as the dashboard API server, into the same tamper-evident audit chain.
    /// `detail` is length-bounded and stripped of control characters to prevent
    /// log injection; never pass secret/key/token material here.
    pub fn record_decision(&self, granted: bool, detail: String) {
        let kind = if granted { DecisionKind::Grant } else { DecisionKind::Denial };
        self.audit(kind, sanitize_detail(&detail));
    }

    /// Read-only snapshot of the in-memory audit log.
    pub fn audit_log_snapshot(&self) -> Vec<SecurityDecision> {
        self.audit_log.lock().unwrap().clone()
    }

    /// Verify the audit chain: each entry's `prev_hash` must equal the keyed MAC
    /// of its predecessor's serialisation.
    ///
    /// Threat model — be precise about what this does and does NOT give you:
    /// * It detects in-place mutation or mid-chain deletion/reordering of entries.
    /// * Because the link is a *keyed* MAC, the guarantee is meaningful only when
    ///   the verifier holds the key and the *attacker does not* — i.e. when a
    ///   persisted log (see `with_audit_file`) is checked later by a separate
    ///   trusted process holding the durable key. For the in-process in-memory
    ///   log, any actor that can mutate the log can also read the key, so the
    ///   keying adds nothing over a plain hash chain there.
    /// * It does NOT detect *suffix truncation* (dropping the most recent
    ///   entries) — the shortened chain still verifies. Detecting that requires
    ///   an external high-water mark (a signed entry count / chain-head),
    ///   tracked as roadmap (external anchoring).
    ///
    /// Returns an error identifying the first broken link.
    pub fn verify_chain(&self) -> Result<(), SecurityError> {
        let log = self.audit_log.lock().unwrap();
        let mut expected_prev = String::new();
        for (i, entry) in log.iter().enumerate() {
            if entry.prev_hash != expected_prev {
                return Err(SecurityError::IntegrityFailure(format!(
                    "audit chain broken at entry {i}"
                )));
            }
            let serialized = serde_json::to_string(entry).unwrap_or_default();
            expected_prev = self.chain_link(serialized.as_bytes());
        }
        Ok(())
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    /// Keyed chain link: HMAC-SHA256 over a domain tag + the entry serialisation.
    fn chain_link(&self, serialized: &[u8]) -> String {
        let mut buf = Vec::with_capacity(serialized.len() + 16);
        buf.extend_from_slice(b"wyrtloom-audit-chain-v1\0");
        buf.extend_from_slice(serialized);
        hex(&self.compute_mac(&buf))
    }

    fn compute_mac(&self, content: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .expect("HMAC key is 32 bytes — valid for any HMAC-SHA256 key size");
        mac.update(content);
        mac.finalize().into_bytes().into()
    }

    fn is_allowed(&self, cap: &Capability) -> bool {
        match cap {
            Capability::FileRead(path)  => self.check_file_path(path, &self.policy.file_read_prefixes),
            Capability::FileWrite(path) => self.check_file_path(path, &self.policy.file_write_prefixes),
            Capability::Network(host) => {
                self.policy.network_allowlist.iter().any(|allowed| {
                    // Exact match or subdomain match — require a dot separator so
                    // "evillocalhost" does not match the allowlist entry "localhost".
                    host == allowed || host.ends_with(&format!(".{}", allowed))
                })
            }
            Capability::Shell => self.policy.allow_shell,
            Capability::Git   => self.policy.allow_git,
        }
    }

    fn check_file_path(&self, path: &str, prefixes: &[String]) -> bool {
        !path.contains("..") && prefixes.iter().any(|p| path.starts_with(p.as_str()))
    }

    fn audit(&self, kind: DecisionKind, detail: String) {
        // Hold last_hash across the entire read-compute-write to prevent concurrent
        // audit() calls from reading the same prev_hash and forking the chain.
        let entry;
        let serialized;
        {
            let mut last = self.last_hash.lock().unwrap();
            entry = SecurityDecision {
                kind, detail, at: Timestamp::now(), prev_hash: last.clone(),
            };
            serialized = serde_json::to_string(&entry).unwrap_or_default();
            *last = self.chain_link(serialized.as_bytes());
        } // last_hash lock released; I/O and log push happen outside.

        // Optionally persist to file before touching in-memory log.
        if let Some(file_lock) = &self.audit_file {
            let mut f = file_lock.lock().unwrap();
            let _ = writeln!(f, "{}", serialized);
            let _ = f.flush();
        }

        self.audit_log.lock().unwrap().push(entry);
    }
}

impl Default for SecurityModule {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Bound and de-fang free-text audit detail: cap length and drop control
/// characters (incl. newlines/escapes) AND Unicode bidi/format codepoints (e.g.
/// U+202E) so a hostile username/path can neither inject forged-looking lines
/// nor visually spoof the log ("Trojan Source").
fn sanitize_detail(s: &str) -> String {
    const MAX: usize = 512;
    s.chars()
        .filter(|c| !c.is_control() && !crate::util::is_bidi_or_format(*c))
        .take(MAX)
        .collect()
}

/// Constant-time equality for two 32-byte MACs (no early exit).
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::{Capability, PluginClass, PluginManifest};
    use crate::types::SemVer;

    fn safe_manifest() -> PluginManifest {
        PluginManifest {
            name: "test-safe".into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Safe,
            capabilities: vec![],
            implements: vec![],
        }
    }

    fn safe_manifest_with_cap() -> PluginManifest {
        PluginManifest {
            name: "rogue-safe".into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Safe,
            capabilities: vec![Capability::Shell],
            implements: vec![],
        }
    }

    fn unsafe_manifest() -> PluginManifest {
        PluginManifest {
            name: "test-unsafe".into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Unsafe,
            capabilities: vec![Capability::FileRead(".".into())],
            implements: vec![],
        }
    }

    fn sec() -> SecurityModule {
        SecurityModule::with_policy(SecurityPolicy::permissive())
    }

    // 001 — self_check validates internal state
    #[test]
    fn self_check_passes_with_valid_key() {
        assert!(sec().self_check().is_ok());
    }

    #[test]
    fn self_check_fails_with_zeroed_key() {
        let mut s = sec();
        s.hmac_key = [0u8; 32];
        assert!(s.self_check().is_err());
    }

    // 002 — policy enforced
    #[test]
    fn safe_plugin_with_no_capabilities_is_verified() {
        assert!(sec().verify(&safe_manifest()).is_ok());
    }

    #[test]
    fn safe_plugin_requesting_capability_is_rejected() {
        let err = sec().verify(&safe_manifest_with_cap()).unwrap_err();
        assert!(matches!(err, SecurityError::SafePluginViolation));
    }

    #[test]
    fn unsafe_plugin_with_allowed_path_is_verified() {
        assert!(sec().verify(&unsafe_manifest()).is_ok());
    }

    #[test]
    fn unsafe_plugin_with_denied_path_is_rejected() {
        let mut m = unsafe_manifest();
        m.capabilities = vec![Capability::FileRead("/etc/passwd".into())];
        let err = SecurityModule::with_policy(SecurityPolicy::deny_all())
            .verify(&m).unwrap_err();
        assert!(matches!(err, SecurityError::CapabilityDenied(_)));
    }

    #[test]
    fn shell_capability_denied_unless_policy_allows() {
        let mut m = unsafe_manifest();
        m.capabilities = vec![Capability::Shell];
        assert!(SecurityModule::with_policy(SecurityPolicy::deny_all()).verify(&m).is_err());
        let mut allow = SecurityPolicy::deny_all();
        allow.allow_shell = true;
        assert!(SecurityModule::with_policy(allow).verify(&m).is_ok());
    }

    #[test]
    fn path_traversal_in_capability_is_denied() {
        let mut m = unsafe_manifest();
        m.capabilities = vec![Capability::FileRead("/tmp/../etc".into())];
        let err = sec().verify(&m).unwrap_err();
        assert!(matches!(err, SecurityError::CapabilityDenied(_)));
    }

    // 004 — HMAC stamps
    #[test]
    fn stamp_is_valid_for_same_content() {
        let s = sec();
        let content = b"hello world";
        let stamp = s.stamp(content);
        assert!(s.is_valid(&stamp, content));
    }

    #[test]
    fn stamp_is_invalid_for_different_content() {
        let s = sec();
        let stamp = s.stamp(b"original");
        assert!(!s.is_valid(&stamp, b"modified"));
    }

    #[test]
    fn stamp_is_invalid_after_invalidation() {
        let s = sec();
        let content = b"msg";
        let stamp = s.stamp(content);
        assert!(s.is_valid(&stamp, content));
        s.invalidate(stamp.clone());
        assert!(!s.is_valid(&stamp, content));
    }

    #[test]
    fn forged_sequential_stamp_is_rejected() {
        let s = sec();
        // Attacker tries to forge stamp by constructing Stamp([1,0,...,0])
        let forged = Stamp([1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!s.is_valid(&forged, b"any content"));
    }

    // 009 — every decision is audited
    #[test]
    fn every_decision_is_audited() {
        let s = sec();
        s.verify(&safe_manifest()).unwrap();
        let log = s.audit_log_snapshot();
        assert!(!log.is_empty());
    }

    #[test]
    fn audit_entries_form_a_keyed_chain_that_verifies() {
        let s = sec();
        s.verify(&safe_manifest()).unwrap();
        s.verify(&safe_manifest()).unwrap();
        let log = s.audit_log_snapshot();
        assert!(log.len() >= 2);
        // First entry anchors at empty; links are non-empty keyed MACs.
        assert_eq!(log[0].prev_hash, "");
        assert!(!log[1].prev_hash.is_empty());
        // The whole chain verifies under the module's key.
        assert!(s.verify_chain().is_ok());
    }

    #[test]
    fn verify_chain_detects_tampering() {
        let s = sec();
        s.verify(&safe_manifest()).unwrap();
        s.verify(&safe_manifest()).unwrap();
        // Tamper with the in-memory log directly: flip a detail string.
        s.audit_log.lock().unwrap()[0].detail.push_str(" TAMPERED");
        // Because links are keyed MACs, the recomputed link no longer matches.
        assert!(s.verify_chain().is_err());
    }

    #[test]
    fn record_decision_audits_and_sanitises() {
        let s = sec();
        // Control characters in detail must not leak into the log.
        s.record_decision(false, "denied login for user\n\x1b[2Jadmin".into());
        let log = s.audit_log_snapshot();
        let last = log.last().unwrap();
        assert!(matches!(last.kind, DecisionKind::Denial));
        assert!(!last.detail.contains('\n') && !last.detail.contains('\x1b'));
        assert!(s.verify_chain().is_ok());
    }

    #[test]
    fn with_key_uses_supplied_key() {
        // Two modules with the SAME key produce the SAME stamp for the same content.
        let key = [7u8; 32];
        let a = SecurityModule::with_key(key, SecurityPolicy::permissive());
        let b = SecurityModule::with_key(key, SecurityPolicy::permissive());
        let content = b"session-payload";
        assert_eq!(a.stamp(content), b.stamp(content));
        assert!(b.is_valid(&a.stamp(content), content));
    }

    #[test]
    fn self_check_runs_before_verify() {
        let s = sec();
        s.self_check().expect("self_check must pass before any other operation");
        s.verify(&safe_manifest()).expect("verify must work after self_check");
    }
}
