use crate::plugin::{Capability, PluginClass, PluginManifest};
use crate::types::Timestamp;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("integrity check failed: {0}")]
    IntegrityFailure(String),
    #[error("capability denied: {0:?}")]
    CapabilityDenied(Capability),
    #[error("safe plugin declared system capability")]
    SafePluginViolation,
}

/// Opaque stamp issued after a message form passes the security gate.
/// If the message is transformed the stamp must be invalidated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Stamp(pub u64);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDecision {
    pub kind: DecisionKind,
    pub detail: String,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecisionKind {
    Grant,
    Denial,
    StampIssued,
    StampInvalidated,
}

/// Root of trust — initialises first, verifies everything.
/// This is a concrete type in core; it is never a plugin.
pub struct SecurityModule {
    audit_log: Arc<Mutex<Vec<SecurityDecision>>>,
    next_stamp: Arc<Mutex<u64>>,
    invalidated: Arc<Mutex<std::collections::HashSet<Stamp>>>,
}

impl SecurityModule {
    pub fn new() -> Self {
        Self {
            audit_log: Arc::new(Mutex::new(Vec::new())),
            next_stamp: Arc::new(Mutex::new(1)),
            invalidated: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }

    /// Runs before any other component. Returns Err if self-check fails.
    pub fn self_check(&self) -> Result<(), SecurityError> {
        // In v0.1 this is a no-op integrity check; the seam is here for later
        // cryptographic verification of the binary.
        Ok(())
    }

    /// Called by the plugin loader before instantiating any plugin.
    pub fn verify(&self, manifest: &PluginManifest) -> Result<(), SecurityError> {
        // SAFE plugins must declare no capabilities.
        if manifest.class == PluginClass::Safe && !manifest.capabilities.is_empty() {
            self.audit(SecurityDecision {
                kind: DecisionKind::Denial,
                detail: format!("safe plugin '{}' declared capabilities", manifest.name),
                at: Timestamp::now(),
            });
            return Err(SecurityError::SafePluginViolation);
        }

        // Validate each declared capability against the allow-list.
        for cap in &manifest.capabilities {
            if !self.is_allowed(cap) {
                self.audit(SecurityDecision {
                    kind: DecisionKind::Denial,
                    detail: format!(
                        "plugin '{}' requested denied capability {:?}",
                        manifest.name, cap
                    ),
                    at: Timestamp::now(),
                });
                return Err(SecurityError::CapabilityDenied(cap.clone()));
            }
        }

        self.audit(SecurityDecision {
            kind: DecisionKind::Grant,
            detail: format!("plugin '{}' v{} verified", manifest.name, manifest.version),
            at: Timestamp::now(),
        });
        Ok(())
    }

    /// Issue a stamp for a message in its current form.
    pub fn stamp(&self) -> Stamp {
        let mut n = self.next_stamp.lock().unwrap();
        let s = Stamp(*n);
        *n += 1;
        self.audit(SecurityDecision {
            kind: DecisionKind::StampIssued,
            detail: format!("stamp {}", s.0),
            at: Timestamp::now(),
        });
        s
    }

    /// Invalidate a stamp when the message it was issued for is transformed.
    pub fn invalidate(&self, stamp: Stamp) {
        self.audit(SecurityDecision {
            kind: DecisionKind::StampInvalidated,
            detail: format!("stamp {}", stamp.0),
            at: Timestamp::now(),
        });
        self.invalidated.lock().unwrap().insert(stamp);
    }

    /// Returns true if the stamp has not been invalidated.
    pub fn is_valid(&self, stamp: &Stamp) -> bool {
        !self.invalidated.lock().unwrap().contains(stamp)
    }

    /// Append-only audit record.
    pub fn audit(&self, decision: SecurityDecision) {
        self.audit_log.lock().unwrap().push(decision);
    }

    /// Returns a snapshot of the audit log.
    pub fn audit_log_snapshot(&self) -> Vec<SecurityDecision> {
        self.audit_log.lock().unwrap().clone()
    }

    fn is_allowed(&self, cap: &Capability) -> bool {
        // In v0.1 all declared capabilities from UNSAFE plugins are allowed;
        // a richer policy engine (Phase 3) narrows this.
        matches!(
            cap,
            Capability::FileRead(_)
                | Capability::FileWrite(_)
                | Capability::Network(_)
                | Capability::Shell
                | Capability::Git
        )
    }
}

impl Default for SecurityModule {
    fn default() -> Self { Self::new() }
}

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
            capabilities: vec![Capability::FileRead("/tmp".into())],
            implements: vec![],
        }
    }

    #[test]
    fn self_check_passes() {
        let sec = SecurityModule::new();
        assert!(sec.self_check().is_ok());
    }

    #[test]
    fn safe_plugin_with_no_capabilities_is_verified() {
        let sec = SecurityModule::new();
        assert!(sec.verify(&safe_manifest()).is_ok());
    }

    #[test]
    fn safe_plugin_requesting_capability_is_rejected() {
        let sec = SecurityModule::new();
        let err = sec.verify(&safe_manifest_with_cap()).unwrap_err();
        assert!(matches!(err, SecurityError::SafePluginViolation));
    }

    #[test]
    fn unsafe_plugin_with_declared_capability_is_verified() {
        let sec = SecurityModule::new();
        assert!(sec.verify(&unsafe_manifest()).is_ok());
    }

    #[test]
    fn every_decision_is_audited() {
        let sec = SecurityModule::new();
        sec.verify(&safe_manifest()).unwrap();
        let log = sec.audit_log_snapshot();
        assert!(!log.is_empty());
    }

    #[test]
    fn stamp_is_valid_until_invalidated() {
        let sec = SecurityModule::new();
        let s = sec.stamp();
        assert!(sec.is_valid(&s));
        sec.invalidate(s.clone());
        assert!(!sec.is_valid(&s));
    }

    #[test]
    fn invalidation_is_audited() {
        let sec = SecurityModule::new();
        let s = sec.stamp();
        sec.invalidate(s);
        let log = sec.audit_log_snapshot();
        assert!(log
            .iter()
            .any(|d| matches!(d.kind, DecisionKind::StampInvalidated)));
    }

    #[test]
    fn self_check_runs_before_verify() {
        // Contract: self_check must not fail for the base security module.
        let sec = SecurityModule::new();
        sec.self_check().expect("self_check must pass before any other operation");
        sec.verify(&safe_manifest()).expect("verify must work after self_check");
    }
}
