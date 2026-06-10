/// Plugin manifest, capability model, and loader contract.
///
/// Security hardening (see CHANGELOG.md):
///   020 – Plugin names are validated against [a-z0-9_-]{1,64}.
use crate::types::{ContractId, SemVer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
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

impl PluginManifest {
    /// Validate that the manifest's name conforms to [a-z0-9_-]{1,64}.
    /// Returns an error message if invalid.
    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("plugin name must not be empty".into());
        }
        if name.len() > 64 {
            return Err(format!("plugin name exceeds 64 characters: {}", name.len()));
        }
        if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
            return Err(format!(
                "plugin name '{}' contains characters outside [a-z0-9_-]",
                name
            ));
        }
        Ok(())
    }
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

pub type PluginFactory = Box<dyn Fn() -> std::sync::Arc<dyn std::any::Any + Send + Sync> + Send + Sync>;

pub struct PluginRegistry {
    entries: Mutex<Vec<(PluginManifest, PluginFactory)>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self { entries: Mutex::new(Vec::new()) }
    }

    pub fn register<F>(&self, manifest: PluginManifest, factory: F)
    where
        F: Fn() -> std::sync::Arc<dyn std::any::Any + Send + Sync> + Send + Sync + 'static,
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
            || std::sync::Arc::new(()),
        );
        assert_eq!(registry.manifests().len(), 1);
    }

    // 020 — name validation
    #[test]
    fn valid_plugin_names_are_accepted() {
        for name in &["kanban-sqlite", "provider_ollama", "bus-tokio-v2", "a1b2"] {
            assert!(PluginManifest::validate_name(name).is_ok(), "should accept: {}", name);
        }
    }

    #[test]
    fn empty_name_is_rejected() {
        assert!(PluginManifest::validate_name("").is_err());
    }

    #[test]
    fn name_with_path_separator_is_rejected() {
        assert!(PluginManifest::validate_name("../evil").is_err());
        assert!(PluginManifest::validate_name("/etc/passwd").is_err());
    }

    #[test]
    fn name_with_uppercase_is_rejected() {
        assert!(PluginManifest::validate_name("MyPlugin").is_err());
    }

    #[test]
    fn name_with_escape_sequence_is_rejected() {
        assert!(PluginManifest::validate_name("plugin\x1b[2J").is_err());
    }

    #[test]
    fn name_exceeding_64_chars_is_rejected() {
        let long = "a".repeat(65);
        assert!(PluginManifest::validate_name(&long).is_err());
    }
}
