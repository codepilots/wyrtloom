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
///   029 – Optional external high-water-mark anchor (signed entry count +
///         chain head, stored outside the log) detects suffix truncation.
use crate::audit_anchor::{AuditAnchorRecord, AuditAnchorStore};
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

/// Upper bound on the on-disk audit file accepted by [`SecurityModule::with_audit_file`].
/// A larger file is refused rather than read into memory (OOM guard against an
/// attacker-written audit file).
const MAX_AUDIT_FILE_BYTES: u64 = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Stamp — HMAC-SHA256 bound to message content
// ---------------------------------------------------------------------------

/// Opaque stamp issued after a message form passes the security gate.
/// Internally stores the 32-byte HMAC so `is_valid()` can verify it
/// without a separate lookup table for the issued set.
/// A stamp is invalidated when the message it was issued for is transformed.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Stamp(pub [u8; 32]);

// Custom Debug that redacts the MAC bytes: the MAC is the secret half of the
// dashboard session token, so it must never reach a Debug/log sink.
impl std::fmt::Debug for Stamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Stamp(<redacted ref={}>)", stamp_ref(&self.0))
    }
}

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

/// What to do when an anchor store holds no record yet (see
/// [`SecurityModule::with_audit_anchor`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorEnrollment {
    /// A missing anchor is accepted only for an EMPTY audit log (a fresh
    /// install). A non-empty log with no anchor is rejected, because that is
    /// exactly what an attacker who deleted the anchor would present.
    Strict,
    /// Accept a missing anchor for a non-empty log and anchor it as it stands.
    /// For the one-time adoption of anchoring on an existing log only — switch
    /// back to `Strict` afterwards.
    EnrollExisting,
}

/// Running head of the audit chain. Kept under one lock so the entry count and
/// the head link always describe the same entry.
#[derive(Default)]
struct ChainHead {
    /// Keyed link over the last entry (hex); empty when the chain is empty.
    hash: String,
    /// Number of entries in the chain.
    count: u64,
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
    /// Root key as supplied/seeded. Retained only so `self_check` can reject an
    /// all-zero root; all cryptographic use goes through the derived sub-keys.
    hmac_key: [u8; 32],
    /// Domain-separated sub-key for stamp/session MACs (finding 027).
    k_session: [u8; 32],
    /// Domain-separated sub-key for the audit hash-chain (finding 027).
    k_audit: [u8; 32],
    /// Domain-separated sub-key for signing the external audit anchor.
    k_anchor: [u8; 32],
    invalidated: Arc<Mutex<HashSet<Stamp>>>,
    policy: SecurityPolicy,
    /// If Some, every audit entry is appended to this JSONL file.
    audit_file: Option<Mutex<File>>,
    /// Head of the audit chain (last link + entry count), for hash-chaining.
    /// Held across the whole of `audit()` so entries reach the file, the
    /// in-memory log and the anchor in chain order.
    chain: Mutex<ChainHead>,
    /// If Some, the signed high-water mark is kept here (outside the log).
    anchor: Option<Arc<dyn AuditAnchorStore>>,
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
        // Finding 027: derive two domain-separated sub-keys from the root so the
        // same secret is never used for two purposes. A single HMAC-extract per
        // label is a sound KDF here (the root is a uniformly random 32-byte key).
        let k_session = derive_subkey(&key, b"wyrtloom-session-v1");
        let k_audit = derive_subkey(&key, b"wyrtloom-audit-v1");
        let k_anchor = derive_subkey(&key, b"wyrtloom-audit-anchor-v1");
        Self {
            audit_log: Arc::new(Mutex::new(Vec::new())),
            hmac_key: key,
            k_session,
            k_audit,
            k_anchor,
            invalidated: Arc::new(Mutex::new(HashSet::new())),
            policy,
            audit_file: None,
            chain: Mutex::new(ChainHead::default()),
            anchor: None,
        }
    }

    /// Enable persistent audit logging to a JSONL file.
    ///
    /// Finding 028:
    /// (a) The file is opened/created with mode 0600 (owner read/write only) so
    ///     the tamper-evident log is not world-readable; permissions are applied
    ///     via `fchmod` on the open fd (no path-based TOCTOU window).
    /// (b) If the file already has content, the chain is re-anchored from its
    ///     LAST line so new entries link onto the old ones across a restart,
    ///     rather than resetting `prev_hash` to "" and forking the chain.
    /// (c) The load reads through the same open fd (bounded to [`MAX_AUDIT_FILE_BYTES`]),
    ///     so an attacker-written file cannot OOM us and a swapped symlink cannot
    ///     feed a different inode than the one we chmodded.
    /// (d) After loading, the re-anchored chain is **verified**; a tampered file
    ///     is rejected (`IntegrityFailure`) at open rather than blindly trusted.
    pub fn with_audit_file(mut self, path: &str) -> Result<Self, SecurityError> {
        use std::io::{Read, Seek, SeekFrom};
        use std::os::unix::fs::OpenOptionsExt;

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| SecurityError::IntegrityFailure(format!("audit file: {}", e)))?;

        // Defensively tighten permissions via fchmod on the OPEN fd, so a
        // pre-existing file is locked down with no path-based TOCTOU window
        // (a path-based set_permissions could be redirected by a swapped symlink
        // between open and chmod).
        fchmod_0600(&f)
            .map_err(|e| SecurityError::IntegrityFailure(format!("audit file perms: {}", e)))?;

        // Load the existing persisted entries by reading the SAME open fd `f`
        // that was opened, stat'd, and chmodded — never re-opening by path — so
        // a swapped symlink cannot feed us a different inode than the one we
        // locked down. The read is hard-bounded to MAX_AUDIT_FILE_BYTES + 1 via
        // `take`: an attacker-written (or concurrently-growing) file cannot OOM
        // us, and exceeding the cap is rejected. (`append` mode leaves the read
        // cursor at 0, but seek to start explicitly to be robust.)
        f.seek(SeekFrom::Start(0))
            .map_err(|e| SecurityError::IntegrityFailure(format!("audit file seek: {}", e)))?;
        let mut bytes = Vec::new();
        let mut limited = (&f).take(MAX_AUDIT_FILE_BYTES + 1);
        limited
            .read_to_end(&mut bytes)
            .map_err(|e| SecurityError::IntegrityFailure(format!("audit file read: {}", e)))?;
        if bytes.len() as u64 > MAX_AUDIT_FILE_BYTES {
            return Err(SecurityError::IntegrityFailure(format!(
                "audit file too large: exceeds {} byte cap",
                MAX_AUDIT_FILE_BYTES
            )));
        }
        let existing = String::from_utf8(bytes)
            .map_err(|_| SecurityError::IntegrityFailure("audit file is not valid UTF-8".into()))?;
        {
            let mut log = self.audit_log.lock().unwrap();
            let mut chain = self.chain.lock().unwrap();
            for line in existing.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let entry: SecurityDecision = serde_json::from_str(line).map_err(|e| {
                    SecurityError::IntegrityFailure(format!("audit file parse: {}", e))
                })?;
                // Recompute the chain head from the canonical serialisation of
                // the just-loaded entry (matching how `audit()` advances it).
                let serialized = serde_json::to_string(&entry).unwrap_or_default();
                chain.hash = self.chain_link(serialized.as_bytes());
                chain.count += 1;
                log.push(entry);
            }
        }

        // Fail closed: a tampered file must be rejected at open, not trusted.
        // `verify_chain` recomputes the keyed links over the loaded entries and
        // errors on the first broken link (in-place mutation / reorder / deletion).
        self.verify_chain()?;

        self.audit_file = Some(Mutex::new(f));
        Ok(self)
    }

    /// Anchor the persisted audit chain to an external high-water mark, so that
    /// **suffix truncation** of the audit file is detected (finding 029).
    ///
    /// The anchor is a signed `(entry count, chain head)` record kept in `store`,
    /// outside the log. This call:
    /// (a) requires [`with_audit_file`](Self::with_audit_file) to have been called
    ///     first — an anchor over an in-memory log would report every restart as
    ///     a truncation;
    /// (b) loads the record and fails closed (`IntegrityFailure`) if the store
    ///     errors, the record's MAC does not verify under this module's key, the
    ///     log holds FEWER entries than the record says (truncation), or the log
    ///     does not pass through the anchored head (a different chain);
    /// (c) handles a missing record per `enrollment`;
    /// (d) writes a fresh record for the log as loaded, then keeps it current
    ///     after every audit entry.
    ///
    /// A log that is AHEAD of its anchor is accepted: the entry is written to the
    /// file before the anchor advances, so a crash between the two leaves the
    /// anchor one step behind. The same window means entries written after the
    /// last successful anchor update are not yet protected.
    ///
    /// Limits: the store can replay an older genuine record, and deleting both
    /// the log and the anchor looks like a fresh install — see
    /// [`crate::audit_anchor`]. Use a durable key ([`with_key`](Self::with_key));
    /// with an ephemeral key the record cannot be verified after a restart.
    pub fn with_audit_anchor(
        mut self,
        store: Arc<dyn AuditAnchorStore>,
        enrollment: AnchorEnrollment,
    ) -> Result<Self, SecurityError> {
        if self.audit_file.is_none() {
            return Err(SecurityError::IntegrityFailure(
                "audit anchor requires a persisted audit log: call with_audit_file first".into(),
            ));
        }
        {
            let chain = self.chain.lock().unwrap();
            let log = self.audit_log.lock().unwrap();
            let record = store
                .load()
                .map_err(|e| SecurityError::IntegrityFailure(e.to_string()))?;
            match record {
                None => {
                    if chain.count > 0 && enrollment == AnchorEnrollment::Strict {
                        return Err(SecurityError::IntegrityFailure(
                            "audit anchor missing for a non-empty audit log".into(),
                        ));
                    }
                }
                Some(rec) => {
                    if !self.anchor_mac_is_valid(&rec) {
                        return Err(SecurityError::IntegrityFailure(
                            "audit anchor signature invalid".into(),
                        ));
                    }
                    if rec.count > chain.count {
                        return Err(SecurityError::IntegrityFailure(format!(
                            "audit log truncated: anchor records {} entries, log has {}",
                            rec.count, chain.count
                        )));
                    }
                    let head_at_anchor = match rec.count {
                        0 => String::new(),
                        n => {
                            let entry = &log[(n - 1) as usize];
                            let serialized = serde_json::to_string(entry).unwrap_or_default();
                            self.chain_link(serialized.as_bytes())
                        }
                    };
                    if !constant_time_eq_bytes(head_at_anchor.as_bytes(), rec.head.as_bytes()) {
                        return Err(SecurityError::IntegrityFailure(
                            "audit log does not match its anchor (chain head differs)".into(),
                        ));
                    }
                }
            }
            // Bring the anchor up to the log as loaded (first enrolment, or a log
            // that was ahead after a crash). Failing here is fatal: we would
            // otherwise run believing the log is anchored when it is not.
            store
                .store(&self.sign_anchor(chain.count, &chain.hash))
                .map_err(|e| SecurityError::IntegrityFailure(e.to_string()))?;
        }
        self.anchor = Some(store);
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
        // Never log the raw MAC: the dashboard session token's MAC half IS this
        // stamp, so it would leak into the 0600 audit file and GET /api/audit.
        // Log a non-reversible reference (truncated SHA-256 of the MAC) instead —
        // enough to correlate issue/invalidate without disclosing the secret.
        self.audit(DecisionKind::StampIssued, format!("stamp issued ref={}", stamp_ref(&mac)));
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
        // Same as `stamp()`: log a non-reversible reference, not the raw MAC.
        self.audit(DecisionKind::StampInvalidated, format!("stamp invalidated ref={}", stamp_ref(&stamp.0)));
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
    /// * On its own it does NOT detect *suffix truncation* (dropping the most
    ///   recent entries) — the shortened chain still verifies. That is covered by
    ///   the external high-water mark: see `with_audit_anchor` / `verify_anchor`.
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

    /// Whether an external audit anchor is configured.
    pub fn audit_anchor_configured(&self) -> bool {
        self.anchor.is_some()
    }

    /// Check that the external anchor is present, genuinely signed, and exactly
    /// matches the current chain (entry count and head).
    ///
    /// Use it alongside [`verify_chain`](Self::verify_chain) in a health check.
    /// It fails when no anchor is configured, when the store errors or has lost
    /// its record, when the record is forged, and when the anchor is stale or
    /// ahead — a stale anchor means a `store` failed during `audit()`, which
    /// leaves the newest entries unprotected until the next successful update.
    pub fn verify_anchor(&self) -> Result<(), SecurityError> {
        let store = self.anchor.as_ref().ok_or_else(|| {
            SecurityError::IntegrityFailure("no audit anchor configured".into())
        })?;
        // Hold the chain lock so an in-flight `audit()` cannot be observed
        // between writing its entry and advancing the anchor.
        let chain = self.chain.lock().unwrap();
        let rec = store
            .load()
            .map_err(|e| SecurityError::IntegrityFailure(e.to_string()))?
            .ok_or_else(|| SecurityError::IntegrityFailure("audit anchor missing".into()))?;
        if !self.anchor_mac_is_valid(&rec) {
            return Err(SecurityError::IntegrityFailure(
                "audit anchor signature invalid".into(),
            ));
        }
        if rec.count != chain.count
            || !constant_time_eq_bytes(rec.head.as_bytes(), chain.hash.as_bytes())
        {
            return Err(SecurityError::IntegrityFailure(format!(
                "audit anchor out of step: anchor records {} entries, chain has {}",
                rec.count, chain.count
            )));
        }
        Ok(())
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    /// MAC binding an anchor's entry count to its chain head, under the anchor
    /// sub-key: HMAC-SHA256(domain tag || count (u64 BE) || head).
    fn anchor_mac(&self, count: u64, head: &str) -> [u8; 32] {
        let mut buf = Vec::with_capacity(head.len() + 40);
        buf.extend_from_slice(b"wyrtloom-audit-anchor-v1\0");
        buf.extend_from_slice(&count.to_be_bytes());
        buf.extend_from_slice(head.as_bytes());
        mac_with(&self.k_anchor, &buf)
    }

    fn sign_anchor(&self, count: u64, head: &str) -> AuditAnchorRecord {
        AuditAnchorRecord {
            count,
            head: head.to_string(),
            mac: hex(&self.anchor_mac(count, head)),
        }
    }

    fn anchor_mac_is_valid(&self, rec: &AuditAnchorRecord) -> bool {
        let expected = hex(&self.anchor_mac(rec.count, &rec.head));
        constant_time_eq_bytes(expected.as_bytes(), rec.mac.as_bytes())
    }

    /// Keyed chain link: HMAC-SHA256 (under the audit sub-key) over a domain tag
    /// + the entry serialisation.
    fn chain_link(&self, serialized: &[u8]) -> String {
        let mut buf = Vec::with_capacity(serialized.len() + 16);
        buf.extend_from_slice(b"wyrtloom-audit-chain-v1\0");
        buf.extend_from_slice(serialized);
        hex(&mac_with(&self.k_audit, &buf))
    }

    /// Stamp/session MAC under the session sub-key (finding 027).
    fn compute_mac(&self, content: &[u8]) -> [u8; 32] {
        mac_with(&self.k_session, content)
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
        if path.contains("..") {
            return false;
        }
        prefixes.iter().any(|p| {
            // Component-boundary match: a raw `starts_with` lets the prefix
            // "/etc" grant "/etc-evil/secret". Require either an exact match or a
            // match up to and including a path separator, mirroring the network
            // allowlist's dot-separator check.
            let p = p.trim_end_matches('/');
            path == p || path.starts_with(&format!("{}/", p))
        })
    }

    fn audit(&self, kind: DecisionKind, detail: String) {
        // Hold the chain lock across the whole read-compute-write. That stops
        // concurrent audit() calls reading the same prev_hash and forking the
        // chain, and it keeps the file, the in-memory log and the anchor in
        // chain order (releasing it before the I/O let two threads write their
        // lines to the file in the opposite order to their links).
        let mut chain = self.chain.lock().unwrap();
        let entry = SecurityDecision {
            kind, detail, at: Timestamp::now(), prev_hash: chain.hash.clone(),
        };
        let serialized = serde_json::to_string(&entry).unwrap_or_default();
        chain.hash = self.chain_link(serialized.as_bytes());
        chain.count += 1;

        // Optionally persist to file before touching in-memory log.
        let mut persisted = true;
        if let Some(file_lock) = &self.audit_file {
            let mut f = file_lock.lock().unwrap();
            persisted = writeln!(f, "{}", serialized).is_ok() && f.flush().is_ok();
        }

        self.audit_log.lock().unwrap().push(entry);

        // Advance the external anchor only AFTER the entry is on disk: a crash
        // in between leaves the log ahead of the anchor (benign), never behind
        // it (a false truncation alarm). Best-effort, like the file write — a
        // failure leaves the anchor stale, which `verify_anchor` reports.
        if persisted {
            if let Some(anchor) = &self.anchor {
                let _ = anchor.store(&self.sign_anchor(chain.count, &chain.hash));
            }
        }
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

/// Non-reversible audit reference for a stamp/session MAC: the first 8 bytes of
/// SHA-256(mac), hex-encoded. Logging this instead of the raw MAC lets an
/// operator correlate a stamp's issue and invalidation without disclosing the
/// MAC itself (which doubles as the dashboard session token's secret half).
fn stamp_ref(mac: &[u8; 32]) -> String {
    use sha2::Digest;
    let digest = Sha256::digest(mac);
    hex(&digest[..8])
}

/// Set mode 0600 on an already-open file. `File::set_permissions` operates on the
/// open fd (it is `fchmod` under the hood), so it closes the TOCTOU window a
/// path-based `set_permissions` leaves open between open and chmod — a swapped
/// symlink can't redirect it.
fn fchmod_0600(f: &File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
}

/// HMAC-SHA256 of `content` under `key`.
fn mac_with(key: &[u8; 32], content: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC key is 32 bytes — valid for any HMAC-SHA256 key size");
    mac.update(content);
    mac.finalize().into_bytes().into()
}

/// Derive a 32-byte domain-separated sub-key from a root key and a label.
/// This is an HKDF-Extract-style step: `HMAC(root, label)`. Because the root is
/// a uniformly random 32-byte secret, a single extract per distinct label gives
/// independent sub-keys suitable for our two domains (session, audit).
fn derive_subkey(root: &[u8; 32], label: &[u8]) -> [u8; 32] {
    mac_with(root, label)
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

/// Constant-time equality for two byte strings of public length (no early exit
/// on content; a length mismatch returns immediately, which leaks nothing here
/// because the expected length is fixed and public).
fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
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
    use uuid::Uuid;

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

    // 026 — prefix match must be at a component boundary: "/etc" must NOT
    // grant a sibling directory "/etc-evil/…", but MUST grant "/etc/passwd".
    #[test]
    fn file_prefix_does_not_grant_sibling_directory() {
        let mut policy = SecurityPolicy::deny_all();
        policy.file_read_prefixes = vec!["/etc".into()];
        let s = SecurityModule::with_policy(policy);

        let mut sibling = unsafe_manifest();
        sibling.capabilities = vec![Capability::FileRead("/etc-evil/secret".into())];
        assert!(s.verify(&sibling).is_err(), "sibling dir must be denied");

        let mut inside = unsafe_manifest();
        inside.capabilities = vec![Capability::FileRead("/etc/passwd".into())];
        assert!(s.verify(&inside).is_ok(), "child path must be granted");

        let mut exact = unsafe_manifest();
        exact.capabilities = vec![Capability::FileRead("/etc".into())];
        assert!(s.verify(&exact).is_ok(), "exact prefix must be granted");
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

    // 028 — reopening an audit file re-anchors the chain: new entries link onto
    // the old ones and verify_chain passes across the restart boundary.
    #[test]
    fn audit_file_chains_across_restart() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("wyrtloom-audit-{}.jsonl", Uuid::new_v4()));
        let path_str = path.to_str().unwrap();
        let key = [9u8; 32];

        // First session: write a couple of entries, then drop.
        {
            let s = SecurityModule::with_key(key, SecurityPolicy::permissive())
                .with_audit_file(path_str)
                .unwrap();
            s.verify(&safe_manifest()).unwrap();
            s.verify(&safe_manifest()).unwrap();
            assert!(s.verify_chain().is_ok());

            // File must be 0600.
            let mode = std::fs::metadata(path_str).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "audit file must be owner-only");
        }

        // Second session: reopen with the SAME key, append more entries.
        {
            let s = SecurityModule::with_key(key, SecurityPolicy::permissive())
                .with_audit_file(path_str)
                .unwrap();
            // Loaded the prior entries into memory.
            let before = s.audit_log_snapshot();
            assert_eq!(before.len(), 2);
            assert_eq!(before[0].prev_hash, "");
            assert!(!before[1].prev_hash.is_empty());

            // New entries chain onto the old ones.
            s.verify(&safe_manifest()).unwrap();
            let after = s.audit_log_snapshot();
            assert_eq!(after.len(), 3);
            assert!(!after[2].prev_hash.is_empty());

            // The whole chain — across the restart boundary — verifies.
            assert!(s.verify_chain().is_ok());
        }

        let _ = std::fs::remove_file(path_str);
    }

    // Round-2: the stamp/invalidate audit detail must NOT contain the raw MAC.
    #[test]
    fn stamp_audit_detail_does_not_leak_mac() {
        let s = sec();
        let content = b"session-payload";
        let stamp = s.stamp(content);
        s.invalidate(stamp.clone());
        let raw_mac_hex = hex(&stamp.0);
        for entry in s.audit_log_snapshot() {
            assert!(
                !entry.detail.contains(&raw_mac_hex),
                "raw MAC leaked into audit detail: {}",
                entry.detail
            );
            // The attestation marker and a non-reversible ref are preserved.
            if matches!(entry.kind, DecisionKind::StampIssued) {
                assert!(entry.detail.starts_with("stamp issued ref="));
            }
            if matches!(entry.kind, DecisionKind::StampInvalidated) {
                assert!(entry.detail.starts_with("stamp invalidated ref="));
            }
        }
        // The ref is the truncated SHA-256 of the MAC (16 hex chars), not the MAC.
        assert_eq!(stamp_ref(&stamp.0).len(), 16);
        assert_ne!(stamp_ref(&stamp.0), raw_mac_hex);
    }

    // Round-2: the custom Debug impl for Stamp must redact the MAC bytes.
    #[test]
    fn stamp_debug_redacts_mac() {
        let s = sec();
        let stamp = s.stamp(b"secret");
        let dbg = format!("{:?}", stamp);
        assert!(dbg.contains("redacted"), "Debug must mark redaction: {dbg}");
        assert!(!dbg.contains(&hex(&stamp.0)), "Debug must not print raw MAC: {dbg}");
    }

    // Round-2: a tampered middle line makes with_audit_file fail closed.
    #[test]
    fn tampered_audit_file_is_rejected_on_open() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("wyrtloom-audit-tamper-{}.jsonl", Uuid::new_v4()));
        let path_str = path.to_str().unwrap();
        let key = [11u8; 32];

        // Write three entries, then drop.
        {
            let s = SecurityModule::with_key(key, SecurityPolicy::permissive())
                .with_audit_file(path_str)
                .unwrap();
            s.verify(&safe_manifest()).unwrap();
            s.verify(&safe_manifest()).unwrap();
            s.verify(&safe_manifest()).unwrap();
        }

        // Tamper with the MIDDLE line's detail in-place.
        let contents = std::fs::read_to_string(path_str).unwrap();
        let mut lines: Vec<String> = contents.lines().map(|l| l.to_string()).collect();
        assert!(lines.len() >= 3);
        let mut mid: SecurityDecision = serde_json::from_str(&lines[1]).unwrap();
        mid.detail.push_str(" TAMPERED");
        lines[1] = serde_json::to_string(&mid).unwrap();
        std::fs::write(path_str, lines.join("\n") + "\n").unwrap();

        // Reopening with the same key must fail closed (chain no longer verifies).
        let result = SecurityModule::with_key(key, SecurityPolicy::permissive())
            .with_audit_file(path_str);
        match result {
            Err(SecurityError::IntegrityFailure(_)) => {}
            Err(other) => panic!("expected IntegrityFailure, got {other:?}"),
            Ok(_) => panic!("tampered audit file must be rejected on open"),
        }

        let _ = std::fs::remove_file(path_str);
    }

    // Round-2: an audit file above the byte cap is refused at open (OOM guard),
    // and the load reads through the open fd, not a re-opened path.
    #[test]
    fn oversized_audit_file_is_rejected_on_open() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("wyrtloom-audit-big-{}.jsonl", Uuid::new_v4()));
        let path_str = path.to_str().unwrap();

        // Write a file just over the cap of newline bytes (cheap; no parsing
        // needed because the cap trips before any line is parsed).
        let oversized = vec![b'\n'; (MAX_AUDIT_FILE_BYTES + 1) as usize];
        std::fs::write(path_str, &oversized).unwrap();

        let result = SecurityModule::with_key([5u8; 32], SecurityPolicy::permissive())
            .with_audit_file(path_str);
        match result {
            Err(SecurityError::IntegrityFailure(msg)) => {
                assert!(msg.contains("too large"), "got {msg}");
            }
            Err(other) => panic!("expected too-large IntegrityFailure, got {other:?}"),
            Ok(_) => panic!("oversized audit file must be rejected"),
        }

        let _ = std::fs::remove_file(path_str);
    }

    // ── 029 — external high-water-mark anchoring ────────────────────────────

    use crate::audit_anchor::{AnchorStoreError, AuditAnchorRecord, AuditAnchorStore};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// In-memory anchor store standing in for "somewhere outside the log".
    #[derive(Default)]
    struct MemAnchor {
        rec: Mutex<Option<AuditAnchorRecord>>,
        fail_store: AtomicBool,
        fail_load: AtomicBool,
    }

    impl AuditAnchorStore for MemAnchor {
        fn load(&self) -> Result<Option<AuditAnchorRecord>, AnchorStoreError> {
            if self.fail_load.load(Ordering::SeqCst) {
                return Err(AnchorStoreError("down".into()));
            }
            Ok(self.rec.lock().unwrap().clone())
        }
        fn store(&self, record: &AuditAnchorRecord) -> Result<(), AnchorStoreError> {
            if self.fail_store.load(Ordering::SeqCst) {
                return Err(AnchorStoreError("down".into()));
            }
            *self.rec.lock().unwrap() = Some(record.clone());
            Ok(())
        }
    }

    struct TempAudit(std::path::PathBuf);
    impl TempAudit {
        fn new(tag: &str) -> Self {
            Self(std::env::temp_dir().join(format!("wyrtloom-anchor-{tag}-{}.jsonl", Uuid::new_v4())))
        }
        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
        /// Keep only the first `n` lines of the audit file.
        fn truncate_to(&self, n: usize) {
            let contents = std::fs::read_to_string(&self.0).unwrap();
            let kept: Vec<&str> = contents.lines().take(n).collect();
            let mut out = kept.join("\n");
            if n > 0 {
                out.push('\n');
            }
            std::fs::write(&self.0, out).unwrap();
        }
    }
    impl Drop for TempAudit {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    const ANCHOR_KEY: [u8; 32] = [13u8; 32];

    fn open_anchored(
        file: &TempAudit,
        anchor: &Arc<MemAnchor>,
        enrollment: AnchorEnrollment,
    ) -> Result<SecurityModule, SecurityError> {
        SecurityModule::with_key(ANCHOR_KEY, SecurityPolicy::permissive())
            .with_audit_file(file.path())?
            .with_audit_anchor(anchor.clone(), enrollment)
    }

    /// Write `n` entries through an anchored module, then drop it.
    fn write_entries(file: &TempAudit, anchor: &Arc<MemAnchor>, n: usize) {
        let s = open_anchored(file, anchor, AnchorEnrollment::Strict).unwrap();
        for _ in 0..n {
            s.verify(&safe_manifest()).unwrap();
        }
    }

    fn expect_integrity_failure(r: Result<SecurityModule, SecurityError>, needle: &str) {
        match r {
            Err(SecurityError::IntegrityFailure(msg)) => {
                assert!(msg.contains(needle), "expected {needle:?} in {msg:?}")
            }
            Err(other) => panic!("expected IntegrityFailure, got {other:?}"),
            Ok(_) => panic!("expected IntegrityFailure containing {needle:?}, got Ok"),
        }
    }

    #[test]
    fn anchor_tracks_every_audit_entry() {
        let file = TempAudit::new("track");
        let anchor = Arc::new(MemAnchor::default());
        let s = open_anchored(&file, &anchor, AnchorEnrollment::Strict).unwrap();
        // A fresh install is anchored at zero straight away.
        assert_eq!(anchor.rec.lock().unwrap().as_ref().unwrap().count, 0);
        assert!(s.verify_anchor().is_ok());

        s.verify(&safe_manifest()).unwrap();
        s.verify(&safe_manifest()).unwrap();
        let rec = anchor.rec.lock().unwrap().clone().unwrap();
        assert_eq!(rec.count, 2);
        assert!(!rec.head.is_empty());
        assert!(s.verify_anchor().is_ok());
        assert!(s.audit_anchor_configured());
    }

    #[test]
    fn anchored_log_reopens_cleanly() {
        let file = TempAudit::new("reopen");
        let anchor = Arc::new(MemAnchor::default());
        write_entries(&file, &anchor, 3);
        let s = open_anchored(&file, &anchor, AnchorEnrollment::Strict).unwrap();
        assert_eq!(s.audit_log_snapshot().len(), 3);
        s.verify(&safe_manifest()).unwrap();
        assert_eq!(anchor.rec.lock().unwrap().as_ref().unwrap().count, 4);
        assert!(s.verify_chain().is_ok());
        assert!(s.verify_anchor().is_ok());
    }

    // The headline: dropping the newest entries leaves a chain that still
    // verifies on its own, and the anchor is what catches it.
    #[test]
    fn suffix_truncation_is_detected_on_open() {
        let file = TempAudit::new("trunc");
        let anchor = Arc::new(MemAnchor::default());
        write_entries(&file, &anchor, 3);
        file.truncate_to(2);

        // Without the anchor the shortened log is accepted...
        let unanchored = SecurityModule::with_key(ANCHOR_KEY, SecurityPolicy::permissive())
            .with_audit_file(file.path())
            .unwrap();
        assert!(unanchored.verify_chain().is_ok());
        drop(unanchored);

        // ...with it, the open fails closed.
        expect_integrity_failure(
            open_anchored(&file, &anchor, AnchorEnrollment::Strict),
            "truncated",
        );
        // Enrolment mode must not be a way round an EXISTING anchor.
        expect_integrity_failure(
            open_anchored(&file, &anchor, AnchorEnrollment::EnrollExisting),
            "truncated",
        );
        // A rejected open must not have moved the anchor.
        assert_eq!(anchor.rec.lock().unwrap().as_ref().unwrap().count, 3);
    }

    #[test]
    fn truncation_to_empty_is_detected() {
        let file = TempAudit::new("empty");
        let anchor = Arc::new(MemAnchor::default());
        write_entries(&file, &anchor, 2);
        file.truncate_to(0);
        expect_integrity_failure(
            open_anchored(&file, &anchor, AnchorEnrollment::Strict),
            "truncated",
        );
    }

    #[test]
    fn log_ahead_of_anchor_is_accepted_and_anchor_catches_up() {
        let file = TempAudit::new("ahead");
        let anchor = Arc::new(MemAnchor::default());
        write_entries(&file, &anchor, 2);
        let behind = anchor.rec.lock().unwrap().clone();
        write_entries(&file, &anchor, 1);
        // Simulate a crash after the log line was written but before the anchor
        // advanced: the anchor is one entry behind.
        *anchor.rec.lock().unwrap() = behind;

        let s = open_anchored(&file, &anchor, AnchorEnrollment::Strict).unwrap();
        assert_eq!(anchor.rec.lock().unwrap().as_ref().unwrap().count, 3);
        assert!(s.verify_anchor().is_ok());
    }

    #[test]
    fn forged_anchor_is_rejected() {
        let file = TempAudit::new("forged");
        let anchor = Arc::new(MemAnchor::default());
        write_entries(&file, &anchor, 3);
        file.truncate_to(1);
        // Attacker lowers the count to match the truncated log but cannot re-sign.
        anchor.rec.lock().unwrap().as_mut().unwrap().count = 1;
        expect_integrity_failure(
            open_anchored(&file, &anchor, AnchorEnrollment::Strict),
            "signature",
        );
    }

    #[test]
    fn anchor_signed_under_another_key_is_rejected() {
        let file = TempAudit::new("otherkey");
        let anchor = Arc::new(MemAnchor::default());
        write_entries(&file, &anchor, 1);
        // A record genuinely signed, but by a module holding a different key.
        let other = SecurityModule::with_key([99u8; 32], SecurityPolicy::permissive());
        let rec = anchor.rec.lock().unwrap().clone().unwrap();
        *anchor.rec.lock().unwrap() = Some(other.sign_anchor(rec.count, &rec.head));
        expect_integrity_failure(
            open_anchored(&file, &anchor, AnchorEnrollment::Strict),
            "signature",
        );
    }

    #[test]
    fn anchor_for_a_different_chain_is_rejected() {
        let file = TempAudit::new("otherchain");
        let anchor = Arc::new(MemAnchor::default());
        write_entries(&file, &anchor, 2);
        // A correctly signed record whose head is not this log's head at count 2.
        let s = SecurityModule::with_key(ANCHOR_KEY, SecurityPolicy::permissive());
        *anchor.rec.lock().unwrap() = Some(s.sign_anchor(2, &"0".repeat(64)));
        expect_integrity_failure(
            open_anchored(&file, &anchor, AnchorEnrollment::Strict),
            "chain head differs",
        );
    }

    #[test]
    fn missing_anchor_for_existing_log_needs_explicit_enrolment() {
        let file = TempAudit::new("enrol");
        // An existing, un-anchored log.
        {
            let s = SecurityModule::with_key(ANCHOR_KEY, SecurityPolicy::permissive())
                .with_audit_file(file.path())
                .unwrap();
            s.verify(&safe_manifest()).unwrap();
            s.verify(&safe_manifest()).unwrap();
        }
        let anchor = Arc::new(MemAnchor::default());
        // Strict: a non-empty log with no anchor looks like a deleted anchor.
        expect_integrity_failure(
            open_anchored(&file, &anchor, AnchorEnrollment::Strict),
            "anchor missing",
        );
        assert!(anchor.rec.lock().unwrap().is_none());
        // Explicit one-time adoption anchors the log as it stands.
        let s = open_anchored(&file, &anchor, AnchorEnrollment::EnrollExisting).unwrap();
        assert_eq!(anchor.rec.lock().unwrap().as_ref().unwrap().count, 2);
        drop(s);
        // From then on Strict works.
        assert!(open_anchored(&file, &anchor, AnchorEnrollment::Strict).is_ok());
    }

    #[test]
    fn anchor_requires_a_persisted_audit_file() {
        let anchor = Arc::new(MemAnchor::default());
        let r = SecurityModule::with_key(ANCHOR_KEY, SecurityPolicy::permissive())
            .with_audit_anchor(anchor, AnchorEnrollment::Strict);
        expect_integrity_failure(r, "with_audit_file first");
    }

    #[test]
    fn anchor_store_failure_at_open_fails_closed() {
        let file = TempAudit::new("storefail");
        let anchor = Arc::new(MemAnchor::default());
        anchor.fail_load.store(true, Ordering::SeqCst);
        expect_integrity_failure(
            open_anchored(&file, &anchor, AnchorEnrollment::Strict),
            "anchor store failure",
        );
        anchor.fail_load.store(false, Ordering::SeqCst);
        anchor.fail_store.store(true, Ordering::SeqCst);
        expect_integrity_failure(
            open_anchored(&file, &anchor, AnchorEnrollment::Strict),
            "anchor store failure",
        );
    }

    #[test]
    fn verify_anchor_reports_stale_missing_and_unconfigured() {
        // Unconfigured.
        assert!(sec().verify_anchor().is_err());
        assert!(!sec().audit_anchor_configured());

        let file = TempAudit::new("stale");
        let anchor = Arc::new(MemAnchor::default());
        let s = open_anchored(&file, &anchor, AnchorEnrollment::Strict).unwrap();
        s.verify(&safe_manifest()).unwrap();
        assert!(s.verify_anchor().is_ok());

        // The store goes down: auditing carries on, but the anchor is now stale.
        anchor.fail_store.store(true, Ordering::SeqCst);
        s.verify(&safe_manifest()).unwrap();
        assert_eq!(s.audit_log_snapshot().len(), 2);
        assert!(s.verify_anchor().is_err());

        // It recovers on the next successful update.
        anchor.fail_store.store(false, Ordering::SeqCst);
        s.verify(&safe_manifest()).unwrap();
        assert!(s.verify_anchor().is_ok());

        // The record vanishing from the store is reported too.
        *anchor.rec.lock().unwrap() = None;
        assert!(s.verify_anchor().is_err());
    }

    // Entries must reach the file in chain order even under contention, or the
    // persisted chain (and so the anchor) would not verify on the next open.
    #[test]
    fn concurrent_audits_keep_file_and_anchor_in_chain_order() {
        let file = TempAudit::new("concurrent");
        let anchor = Arc::new(MemAnchor::default());
        let s = Arc::new(open_anchored(&file, &anchor, AnchorEnrollment::Strict).unwrap());
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let s = s.clone();
                std::thread::spawn(move || {
                    for i in 0..50 {
                        s.record_decision(true, format!("thread {t} entry {i}"));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(s.verify_chain().is_ok());
        assert!(s.verify_anchor().is_ok());
        assert_eq!(anchor.rec.lock().unwrap().as_ref().unwrap().count, 400);
        drop(s);
        let reopened = open_anchored(&file, &anchor, AnchorEnrollment::Strict).unwrap();
        assert_eq!(reopened.audit_log_snapshot().len(), 400);
    }

    #[test]
    fn self_check_runs_before_verify() {
        let s = sec();
        s.self_check().expect("self_check must pass before any other operation");
        s.verify(&safe_manifest()).expect("verify must work after self_check");
    }
}
