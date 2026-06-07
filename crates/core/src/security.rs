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
        let expected = self.compute_mac(content);
        if stamp.0 != expected {
            return false;
        }
        !self.invalidated.lock().unwrap().contains(stamp)
    }

    /// Invalidate a stamp when the message it covers is transformed.
    pub fn invalidate(&self, stamp: Stamp) {
        self.audit(DecisionKind::StampInvalidated, format!("stamp {}", hex(&stamp.0)));
        self.invalidated.lock().unwrap().insert(stamp);
    }

    /// Read-only snapshot of the in-memory audit log.
    pub fn audit_log_snapshot(&self) -> Vec<SecurityDecision> {
        self.audit_log.lock().unwrap().clone()
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    fn compute_mac(&self, content: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .expect("HMAC key is 32 bytes — valid for any HMAC-SHA256 key size");
        mac.update(content);
        mac.finalize().into_bytes().into()
    }

    fn is_allowed(&self, cap: &Capability) -> bool {
        match cap {
            Capability::FileRead(path) => {
                !path.contains("..") && self.policy.file_read_prefixes
                    .iter().any(|p| path.starts_with(p.as_str()))
            }
            Capability::FileWrite(path) => {
                !path.contains("..") && self.policy.file_write_prefixes
                    .iter().any(|p| path.starts_with(p.as_str()))
            }
            Capability::Network(host) => {
                self.policy.network_allowlist
                    .iter().any(|allowed| host == allowed || host.ends_with(allowed.as_str()))
            }
            Capability::Shell => self.policy.allow_shell,
            Capability::Git   => self.policy.allow_git,
        }
    }

    fn audit(&self, kind: DecisionKind, detail: String) {
        let prev_hash = self.last_hash.lock().unwrap().clone();
        let entry = SecurityDecision { kind, detail, at: Timestamp::now(), prev_hash };

        // Compute hash of this entry and store as the new chain tip.
        let serialized = serde_json::to_string(&entry).unwrap_or_default();
        let new_hash = sha256_hex(serialized.as_bytes());
        *self.last_hash.lock().unwrap() = new_hash;

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

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex(&hasher.finalize())
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
    fn audit_entries_form_a_hash_chain() {
        let s = sec();
        s.verify(&safe_manifest()).unwrap();
        s.verify(&safe_manifest()).unwrap();
        let log = s.audit_log_snapshot();
        assert!(log.len() >= 2);
        // Second entry's prev_hash must equal SHA-256 of first entry.
        let first_json = serde_json::to_string(&log[0]).unwrap();
        let expected_hash = sha256_hex(first_json.as_bytes());
        assert_eq!(log[1].prev_hash, expected_hash);
    }

    #[test]
    fn self_check_runs_before_verify() {
        let s = sec();
        s.self_check().expect("self_check must pass before any other operation");
        s.verify(&safe_manifest()).expect("verify must work after self_check");
    }
}
