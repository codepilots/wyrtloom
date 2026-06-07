use crate::types::{ContractId, SemVer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginClass {
    Safe,
    Unsafe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    FileRead(String),
    FileWrite(String),
    Network(String),
    Shell,
    Git,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: SemVer,
    pub class: PluginClass,
    pub capabilities: Vec<Capability>,
    /// (ContractId, required core version)
    pub implements: Vec<(ContractId, SemVer)>,
}

#[derive(Error, Debug)]
pub enum LoadError {
    #[error("manifest is invalid: {0}")]
    ManifestInvalid(String),
    #[error("incompatible contract version for {contract}: plugin requires {required}, core provides {provided}")]
    IncompatibleContractVersion {
        contract: String,
        required: SemVer,
        provided: SemVer,
    },
    #[error("security rejected: {0}")]
    SecurityRejected(String),
    #[error("safe plugin requested a system capability")]
    SafePluginRequestedCapability,
}

pub type PluginFactory = Box<dyn Fn() -> Arc<dyn std::any::Any + Send + Sync> + Send + Sync>;

pub struct PluginRegistry {
    entries: Mutex<Vec<(PluginManifest, PluginFactory)>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self { entries: Mutex::new(Vec::new()) }
    }

    pub fn register<F>(&self, manifest: PluginManifest, factory: F)
    where
        F: Fn() -> Arc<dyn std::any::Any + Send + Sync> + Send + Sync + 'static,
    {
        self.entries.lock().unwrap().push((manifest, Box::new(factory)));
    }

    pub fn manifests(&self) -> Vec<PluginManifest> {
        self.entries.lock().unwrap().iter().map(|(m, _)| m.clone()).collect()
    }

    pub fn take_factories(&self) -> Vec<(PluginManifest, PluginFactory)> {
        std::mem::take(&mut *self.entries.lock().unwrap())
    }
}

impl Default for PluginRegistry {
    fn default() -> Self { Self::new() }
}

/// Core versions of each interface contract — plugins must be compatible.
pub struct CoreContractVersions(pub HashMap<ContractId, SemVer>);

impl CoreContractVersions {
    pub fn v0_1() -> Self {
        let mut m = HashMap::new();
        m.insert("wyrtloom.kanban".into(),     SemVer::new(0, 1, 0));
        m.insert("wyrtloom.provider".into(),   SemVer::new(0, 1, 0));
        m.insert("wyrtloom.sandbox".into(),    SemVer::new(0, 1, 0));
        m.insert("wyrtloom.logger".into(),     SemVer::new(0, 1, 0));
        m.insert("wyrtloom.escalation".into(), SemVer::new(0, 1, 0));
        m.insert("wyrtloom.bus".into(),        SemVer::new(0, 1, 0));
        Self(m)
    }

    pub fn is_compatible(&self, contract: &str, plugin_version: &SemVer) -> bool {
        match self.0.get(contract) {
            Some(core_ver) => plugin_version.is_compatible_with(core_ver),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_manifest(class: PluginClass, caps: Vec<Capability>) -> PluginManifest {
        PluginManifest {
            name: "test-plugin".into(),
            version: SemVer::new(0, 1, 0),
            class,
            capabilities: caps,
            implements: vec![("wyrtloom.kanban".into(), SemVer::new(0, 1, 0))],
        }
    }

    #[test]
    fn safe_manifest_has_no_capabilities() {
        let m = minimal_manifest(PluginClass::Safe, vec![]);
        assert!(m.capabilities.is_empty());
    }

    #[test]
    fn contract_version_compatibility_same_major_higher_minor() {
        let core = CoreContractVersions::v0_1();
        // Providing v0.2 should be compatible with a core that requires v0.1
        let newer = SemVer::new(0, 2, 0);
        assert!(newer.is_compatible_with(&SemVer::new(0, 1, 0)));
    }

    #[test]
    fn contract_version_incompatible_different_major() {
        let v1 = SemVer::new(1, 0, 0);
        assert!(!v1.is_compatible_with(&SemVer::new(0, 1, 0)));
    }

    #[test]
    fn core_contract_versions_exist_for_all_v01_interfaces() {
        let core = CoreContractVersions::v0_1();
        for name in &[
            "wyrtloom.kanban",
            "wyrtloom.provider",
            "wyrtloom.sandbox",
            "wyrtloom.logger",
            "wyrtloom.escalation",
            "wyrtloom.bus",
        ] {
            assert!(core.0.contains_key(*name), "missing contract: {}", name);
        }
    }

    #[test]
    fn registry_discover_returns_registered_manifests() {
        let registry = PluginRegistry::new();
        registry.register(
            minimal_manifest(PluginClass::Safe, vec![]),
            || Arc::new(()),
        );
        assert_eq!(registry.manifests().len(), 1);
    }
}
