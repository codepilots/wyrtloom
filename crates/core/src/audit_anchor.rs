//! External high-water-mark anchoring for the audit chain.
//!
//! The keyed audit chain in [`crate::security::SecurityModule`] detects in-place
//! mutation, reordering and mid-chain deletion, but a log whose most recent
//! entries were dropped is still a valid, shorter chain. To detect that *suffix
//! truncation* the module keeps a signed high-water mark — the entry count and
//! the chain head — in a store **outside the log**. On start-up the log must be
//! at least as long as the anchor says, and must pass through the anchored head.
//!
//! This module holds the storage seam only: the record, the store trait, and an
//! adapter over the [`PersistenceProvider`] contract. Signing and verification
//! live in `security.rs`, because they need the module's anchor sub-key.
//!
//! Security notes for implementors and operators:
//! * The anchor only helps if it lives somewhere the log's attacker cannot also
//!   write. A store on the same disk as the audit file defends against someone
//!   with access to the log file alone; a remote or append-only store defends
//!   against more.
//! * The record is MAC'd, so a store cannot forge one, but it can **replay an
//!   older genuine record**. A store that can enforce monotonicity (refuse a
//!   `store` whose `count` is lower than the current one) should do so.
//! * Deleting both the log and the anchor is indistinguishable from a fresh
//!   install. Only a store the attacker cannot reach closes that.

use crate::persistence::{CollectionSpec, PersistenceProvider, Record, StoreError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

/// The signed high-water mark of the audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchorRecord {
    /// Number of audit entries the chain held when this record was signed.
    pub count: u64,
    /// Chain head after `count` entries: the keyed link over entry `count - 1`
    /// (hex), or the empty string when `count` is 0.
    pub head: String,
    /// HMAC-SHA256 (hex) over `count` and `head` under the module's anchor
    /// sub-key. Not a secret, but only the key holder can produce it.
    pub mac: String,
}

/// Opaque failure from an anchor store. The message must not carry secrets.
#[derive(Error, Debug)]
#[error("audit anchor store failure: {0}")]
pub struct AnchorStoreError(pub String);

/// Where the high-water mark is kept. Implementations hold exactly one record.
pub trait AuditAnchorStore: Send + Sync {
    /// The current record, or `None` if none has ever been stored. A record that
    /// exists but cannot be decoded MUST be an error, never `None` — reporting
    /// "absent" for a damaged anchor would let an attacker reset it.
    fn load(&self) -> Result<Option<AuditAnchorRecord>, AnchorStoreError>;
    /// Replace the current record.
    fn store(&self, record: &AuditAnchorRecord) -> Result<(), AnchorStoreError>;
}

/// Collection used by [`PersistenceAuditAnchor`].
pub const AUDIT_ANCHOR_COLLECTION: &str = "audit_anchor";

/// An [`AuditAnchorStore`] over any [`PersistenceProvider`], so the anchor can
/// live in whatever store the installation already uses (for example the
/// SQLite store, in a different file from the audit JSONL).
pub struct PersistenceAuditAnchor {
    store: Arc<dyn PersistenceProvider>,
    id: String,
}

impl PersistenceAuditAnchor {
    /// `id` names the anchor record, so several audit logs can share one store.
    pub fn new(store: Arc<dyn PersistenceProvider>, id: &str) -> Result<Self, AnchorStoreError> {
        if id.is_empty() || id.len() > 128 || id.chars().any(|c| c.is_control()) {
            return Err(AnchorStoreError("invalid anchor id".into()));
        }
        store
            .ensure_collection(&CollectionSpec {
                name: AUDIT_ANCHOR_COLLECTION.into(),
                indexed_fields: vec![],
            })
            .map_err(opaque)?;
        Ok(Self { store, id: id.to_string() })
    }
}

impl AuditAnchorStore for PersistenceAuditAnchor {
    fn load(&self) -> Result<Option<AuditAnchorRecord>, AnchorStoreError> {
        match self.store.get(AUDIT_ANCHOR_COLLECTION, &self.id) {
            Ok(record) => serde_json::from_value(record.doc)
                .map(Some)
                .map_err(|_| AnchorStoreError("integrity error: malformed anchor record".into())),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(opaque(e)),
        }
    }

    fn store(&self, record: &AuditAnchorRecord) -> Result<(), AnchorStoreError> {
        let doc = serde_json::to_value(record)
            .map_err(|_| AnchorStoreError("anchor record not serialisable".into()))?;
        self.store
            .put(AUDIT_ANCHOR_COLLECTION, Record { id: self.id.clone(), doc })
            .map_err(opaque)
    }
}

/// Map a store error to its variant name only: the payload may echo ids or
/// backend detail that should not travel into audit/error sinks.
fn opaque(e: StoreError) -> AnchorStoreError {
    let kind = match e {
        StoreError::CollectionNotFound(_) => "collection not found",
        StoreError::NotFound(_) => "record not found",
        StoreError::InvalidIdentifier(_) => "invalid identifier",
        StoreError::FieldNotIndexed(_) => "field not indexed",
        StoreError::Storage(_) => "storage failure",
    };
    AnchorStoreError(kind.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::Query;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Minimal in-memory `PersistenceProvider` for exercising the adapter.
    #[derive(Default)]
    struct MemStore {
        docs: Mutex<HashMap<(String, String), serde_json::Value>>,
        collections: Mutex<Vec<String>>,
    }

    impl PersistenceProvider for MemStore {
        fn ensure_collection(&self, spec: &CollectionSpec) -> Result<(), StoreError> {
            self.collections.lock().unwrap().push(spec.name.clone());
            Ok(())
        }
        fn put(&self, collection: &str, record: Record) -> Result<(), StoreError> {
            self.docs
                .lock()
                .unwrap()
                .insert((collection.into(), record.id), record.doc);
            Ok(())
        }
        fn get(&self, collection: &str, id: &str) -> Result<Record, StoreError> {
            self.docs
                .lock()
                .unwrap()
                .get(&(collection.to_string(), id.to_string()))
                .map(|doc| Record { id: id.into(), doc: doc.clone() })
                .ok_or_else(|| StoreError::NotFound(id.into()))
        }
        fn query(&self, _: &str, _: &Query) -> Result<Vec<Record>, StoreError> {
            Ok(vec![])
        }
        fn delete(&self, collection: &str, id: &str) -> Result<(), StoreError> {
            self.docs
                .lock()
                .unwrap()
                .remove(&(collection.to_string(), id.to_string()));
            Ok(())
        }
    }

    fn rec(count: u64) -> AuditAnchorRecord {
        AuditAnchorRecord { count, head: "ab".into(), mac: "cd".into() }
    }

    #[test]
    fn absent_anchor_loads_as_none() {
        let a = PersistenceAuditAnchor::new(Arc::new(MemStore::default()), "main").unwrap();
        assert_eq!(a.load().unwrap(), None);
    }

    #[test]
    fn store_then_load_round_trips_and_replaces() {
        let a = PersistenceAuditAnchor::new(Arc::new(MemStore::default()), "main").unwrap();
        a.store(&rec(3)).unwrap();
        assert_eq!(a.load().unwrap(), Some(rec(3)));
        a.store(&rec(4)).unwrap();
        assert_eq!(a.load().unwrap(), Some(rec(4)));
    }

    #[test]
    fn anchors_with_different_ids_are_independent() {
        let store: Arc<dyn PersistenceProvider> = Arc::new(MemStore::default());
        let a = PersistenceAuditAnchor::new(store.clone(), "a").unwrap();
        let b = PersistenceAuditAnchor::new(store, "b").unwrap();
        a.store(&rec(1)).unwrap();
        assert_eq!(b.load().unwrap(), None);
    }

    #[test]
    fn malformed_record_is_an_error_not_absent() {
        let store = Arc::new(MemStore::default());
        let a = PersistenceAuditAnchor::new(store.clone(), "main").unwrap();
        store
            .put(
                AUDIT_ANCHOR_COLLECTION,
                Record { id: "main".into(), doc: serde_json::json!({"count": "nope"}) },
            )
            .unwrap();
        assert!(a.load().is_err());
    }

    #[test]
    fn invalid_ids_rejected() {
        let store: Arc<dyn PersistenceProvider> = Arc::new(MemStore::default());
        assert!(PersistenceAuditAnchor::new(store.clone(), "").is_err());
        assert!(PersistenceAuditAnchor::new(store.clone(), "a\nb").is_err());
        assert!(PersistenceAuditAnchor::new(store, &"x".repeat(129)).is_err());
    }
}
