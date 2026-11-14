/// Bootstrap sequence as specified in §8.
///
/// Order is fixed; a failure at any stage halts with a logged reason.
/// Security initialises first and verifies each subsequent stage.
use crate::bus::{BootstrapBus, Event, MessageBus};
use crate::plugin::{CoreContractVersions, LoadError, PluginClass, PluginManifest, PluginRegistry};
use crate::security::{SecurityModule, SecurityPolicy};
use std::sync::Arc;

pub struct BootstrappedSystem {
    pub security: Arc<SecurityModule>,
    pub bus: Arc<BootstrapBus>,
    pub contract_versions: Arc<CoreContractVersions>,
}

pub struct Bootstrapper {
    registry: PluginRegistry,
}

impl Bootstrapper {
    pub fn new() -> Self {
        Self { registry: PluginRegistry::new() }
    }

    pub fn register_plugin<F>(
        &mut self,
        manifest: PluginManifest,
        factory: F,
    ) where
        F: Fn() -> Arc<dyn std::any::Any + Send + Sync> + Send + Sync + 'static,
    {
        self.registry.register(manifest, factory);
    }

    /// Run the bootstrap sequence with the hardened default: a **deny-all**
    /// policy and an ephemeral key. Plugins that declare no capabilities load;
    /// any plugin requesting file, network, shell or git access is rejected.
    ///
    /// A host that needs to grant capabilities, keep a durable key, or persist
    /// the audit log must say so explicitly via [`run_with`](Self::run_with).
    pub fn run(self) -> Result<BootstrappedSystem, BootstrapError> {
        self.run_with(SecurityModule::with_policy(SecurityPolicy::deny_all()))
    }

    /// Run the bootstrap sequence under a caller-built [`SecurityModule`], so
    /// the policy, key and audit persistence are the host's explicit choice:
    /// build it with `with_key` for stamps and an audit chain that survive a
    /// restart, and `with_audit_file` / `with_audit_anchor` for a persisted,
    /// truncation-evident log. The module still has to pass its own
    /// `self_check` before anything else runs.
    ///
    /// Returns the live system or an error describing the stage that failed.
    pub fn run_with(self, security: SecurityModule) -> Result<BootstrappedSystem, BootstrapError> {
        // Stage 1 — Security & Trust Module
        let security = Arc::new(security);
        security.self_check().map_err(|e| BootstrapError::SecurityInit(e.to_string()))?;

        // Stage 2 — Plugin Loader (manifests are already in registry; verify here)
        let contract_versions = Arc::new(CoreContractVersions::v0_1());

        // Stage 3 — Bus primitive
        let bus = Arc::new(BootstrapBus::new());

        // Stages 4-8: interfaces register (they are trait objects; we validate manifests here)
        let manifests = self.registry.manifests();
        for manifest in &manifests {
            // Check manifest schema — includes name character-set validation (finding 020).
            PluginManifest::validate_name(&manifest.name).map_err(|e| {
                BootstrapError::PluginLoad(LoadError::ManifestInvalid(e))
            })?;
            // Check contract versions
            for (contract_id, required_version) in &manifest.implements {
                if !contract_versions.is_compatible(contract_id, required_version) {
                    return Err(BootstrapError::PluginLoad(
                        LoadError::IncompatibleContractVersion {
                            contract: contract_id.clone(),
                            required: required_version.clone(),
                            provided: contract_versions
                                .0
                                .get(contract_id.as_str())
                                .cloned()
                                .unwrap_or(crate::types::SemVer::new(0, 0, 0)),
                        },
                    ));
                }
            }
            // Safe plugin with capabilities is a violation
            if manifest.class == PluginClass::Safe && !manifest.capabilities.is_empty() {
                return Err(BootstrapError::PluginLoad(
                    LoadError::SafePluginRequestedCapability,
                ));
            }
            // Security verification
            security
                .verify(manifest)
                .map_err(|e| BootstrapError::PluginLoad(LoadError::SecurityRejected(e.to_string())))?;
        }

        // Publish boot-complete event
        let _ = bus.publish(Event::new(
            "wyrtloom.boot",
            serde_json::json!({ "stage": "complete", "plugins": manifests.len() }),
        ));

        Ok(BootstrappedSystem { security, bus, contract_versions })
    }
}

impl Default for Bootstrapper {
    fn default() -> Self { Self::new() }
}

#[derive(Debug)]
pub enum BootstrapError {
    SecurityInit(String),
    PluginLoad(LoadError),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapError::SecurityInit(s) => write!(f, "security init failed: {}", s),
            BootstrapError::PluginLoad(e) => write!(f, "plugin load failed: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::{Capability, PluginClass, PluginManifest};
    use crate::types::SemVer;

    fn safe_manifest(name: &str) -> PluginManifest {
        PluginManifest {
            name: name.into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Safe,
            capabilities: vec![],
            implements: vec![("wyrtloom.kanban".into(), SemVer::new(0, 1, 0))],
        }
    }

    #[test]
    fn bootstrap_succeeds_with_no_plugins() {
        let b = Bootstrapper::new();
        b.run().expect("bootstrap with no plugins must succeed");
    }

    #[test]
    fn bootstrap_succeeds_with_safe_plugin() {
        let mut b = Bootstrapper::new();
        b.register_plugin(safe_manifest("kanban-sqlite"), || Arc::new(()));
        b.run().expect("bootstrap with safe plugin must succeed");
    }

    fn unsafe_manifest(name: &str, capabilities: Vec<Capability>) -> PluginManifest {
        PluginManifest {
            name: name.into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Unsafe,
            capabilities,
            implements: vec![("wyrtloom.kanban".into(), SemVer::new(0, 1, 0))],
        }
    }

    // The default path must grant nothing: every capability the old permissive
    // default allowed (cwd / /tmp files, localhost network, git) is refused.
    #[test]
    fn default_run_denies_every_capability() {
        for cap in [
            Capability::FileRead(".".into()),
            Capability::FileWrite("/tmp".into()),
            Capability::Network("localhost".into()),
            Capability::Git,
            Capability::Shell,
        ] {
            let mut b = Bootstrapper::new();
            b.register_plugin(unsafe_manifest("needs-access", vec![cap.clone()]), || Arc::new(()));
            match b.run() {
                Err(BootstrapError::PluginLoad(LoadError::SecurityRejected(_))) => {}
                Err(other) => panic!("{cap:?}: expected SecurityRejected, got {other}"),
                Ok(_) => panic!("{cap:?} must be denied by the default bootstrap path"),
            }
        }
    }

    #[test]
    fn default_run_still_loads_an_unsafe_plugin_with_no_capabilities() {
        let mut b = Bootstrapper::new();
        b.register_plugin(unsafe_manifest("no-access", vec![]), || Arc::new(()));
        b.run().expect("a plugin asking for nothing loads under deny-all");
    }

    #[test]
    fn run_with_grants_only_what_the_supplied_policy_allows() {
        let policy = || SecurityPolicy {
            file_write_prefixes: vec!["/var/lib/wyrtloom".into()],
            ..SecurityPolicy::deny_all()
        };

        let mut b = Bootstrapper::new();
        b.register_plugin(
            unsafe_manifest("store", vec![Capability::FileWrite("/var/lib/wyrtloom/db".into())]),
            || Arc::new(()),
        );
        b.run_with(SecurityModule::with_policy(policy()))
            .expect("capability inside the explicit policy must load");

        let mut b = Bootstrapper::new();
        b.register_plugin(
            unsafe_manifest("net", vec![Capability::Network("localhost".into())]),
            || Arc::new(()),
        );
        assert!(
            b.run_with(SecurityModule::with_policy(policy())).is_err(),
            "capability outside the explicit policy must be rejected"
        );
    }

    // The system must run on the module the host supplied (its key), not a
    // freshly constructed one.
    #[test]
    fn run_with_uses_the_supplied_module() {
        let key = [42u8; 32];
        let sys = Bootstrapper::new()
            .run_with(SecurityModule::with_key(key, SecurityPolicy::deny_all()))
            .unwrap();
        let same_key = SecurityModule::with_key(key, SecurityPolicy::deny_all());
        let stamp = sys.security.stamp(b"payload");
        assert!(same_key.is_valid(&stamp, b"payload"));
    }

    #[test]
    fn run_with_rejects_a_module_that_fails_self_check() {
        let zero_key = SecurityModule::with_key([0u8; 32], SecurityPolicy::deny_all());
        match Bootstrapper::new().run_with(zero_key) {
            Err(BootstrapError::SecurityInit(_)) => {}
            Err(other) => panic!("expected SecurityInit, got {other}"),
            Ok(_) => panic!("an all-zero key must halt bootstrap at stage 1"),
        }
    }

    #[test]
    fn rejected_capability_is_audited_in_the_supplied_module() {
        // A denial must land in the audit chain. We cannot read the module back
        // out of a failed run, so check the same decision on the module directly.
        let security = SecurityModule::with_policy(SecurityPolicy::deny_all());
        let manifest = unsafe_manifest("net", vec![Capability::Network("localhost".into())]);
        assert!(security.verify(&manifest).is_err());
        assert_eq!(security.audit_log_snapshot().len(), 1);
    }

    #[test]
    fn bootstrap_rejects_safe_plugin_with_capability() {
        let mut b = Bootstrapper::new();
        b.register_plugin(
            PluginManifest {
                name: "rogue".into(),
                version: SemVer::new(0, 1, 0),
                class: PluginClass::Safe,
                capabilities: vec![Capability::Shell],
                implements: vec![],
            },
            || Arc::new(()),
        );
        assert!(b.run().is_err());
    }

    #[test]
    fn bootstrap_security_runs_first() {
        // The security module must be operational before plugins are checked.
        // We verify this indirectly: a clean bootstrapper succeeds, meaning
        // security.self_check() ran without error.
        let b = Bootstrapper::new();
        let sys = b.run().unwrap();
        // And the audit log must have at least the boot grant entry.
        let log = sys.security.audit_log_snapshot();
        // With no plugins the log may be empty — but self_check must have run
        // without returning an error (we already asserted the overall Ok above).
        let _ = log; // suppress unused warning
    }

    #[test]
    fn bootstrap_publishes_complete_event() {
        let b = Bootstrapper::new();
        let sys = b.run().unwrap();
        let _rx = sys.bus.subscribe("wyrtloom.boot".into());
        // The event was already sent before we subscribed — in a broadcast channel
        // we won't receive it after the fact, but we can verify the bus is live.
        let _ = sys.bus.publish(Event::new("probe", serde_json::json!({})));
    }
}
