//! Persistence contract — a storage-agnostic document/collection store.
//!
//! Plugins that need to persist state (user directories, client-auth schemes,
//! …) depend on this contract rather than embedding a concrete database, so the
//! backing store (SQLite now, anything later) is swappable. The contract is a
//! minimal document store: named collections of JSON documents keyed by a string
//! id, with a small declared-index query surface.
//!
//! Security note for implementors: collection names and indexed-field names are
//! storage *identifiers* (often un-parameterizable in SQL). Implementations MUST
//! validate them against [`is_valid_identifier`] and MUST allow-list a
//! `Query::ByField` field against the collection's declared `indexed_fields`.
//! Document *values* must always be bound, never interpolated.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Declares a collection and the fields that may be queried via [`Query::ByField`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionSpec {
    pub name: String,
    /// Top-level document keys that get a secondary index; only these are
    /// permitted as `Query::ByField` fields.
    pub indexed_fields: Vec<String>,
}

/// A stored document: an opaque JSON value addressed by a string id.
#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub doc: serde_json::Value,
}

// Custom Debug that omits `doc`: a document may hold password hashes, keys, or
// other secret-bearing fields, so it must not be dumped to a Debug/log sink.
// Only the id is printed, with a `<redacted>` marker for the document.
impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("id", &self.id)
            .field("doc", &"<redacted>")
            .finish()
    }
}

/// Read query over a collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Query {
    /// All records in the collection.
    All,
    /// The single record with this id (empty result if absent).
    ById(String),
    /// Records whose indexed `field` equals `value`. `field` MUST be one of the
    /// collection's declared `indexed_fields`.
    ByField { field: String, value: serde_json::Value },
}

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("collection not found: {0}")]
    CollectionNotFound(String),
    #[error("record not found: {0}")]
    NotFound(String),
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("field is not indexed for this collection: {0}")]
    FieldNotIndexed(String),
    #[error("storage failure: {0}")]
    Storage(String),
}

/// Storage-agnostic document store. Implementations live in separate plugin repos
/// (e.g. `wyrtloom-store-sqlite`).
pub trait PersistenceProvider: Send + Sync {
    /// Idempotently create a collection and its declared indexes.
    fn ensure_collection(&self, spec: &CollectionSpec) -> Result<(), StoreError>;
    /// Insert or replace a record by its id.
    fn put(&self, collection: &str, record: Record) -> Result<(), StoreError>;
    /// Fetch a single record by id.
    fn get(&self, collection: &str, id: &str) -> Result<Record, StoreError>;
    /// Run a query, returning matching records.
    fn query(&self, collection: &str, query: &Query) -> Result<Vec<Record>, StoreError>;
    /// Delete a record by id (no-op if absent).
    fn delete(&self, collection: &str, id: &str) -> Result<(), StoreError>;

    /// Atomically insert only if `record.id` is absent. Returns Ok(true) if
    /// inserted, Ok(false) if it already existed. Implementations MUST make this
    /// atomic — it backs single-use tokens. The default is a NON-atomic
    /// get-then-put fallback (NOT safe for cross-process single-use); real stores
    /// override it.
    fn put_if_absent(&self, collection: &str, record: Record) -> Result<bool, StoreError> {
        match self.get(collection, &record.id) {
            Ok(_) => Ok(false),
            Err(StoreError::NotFound(_)) => {
                self.put(collection, record)?;
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }
}

/// Validate a storage identifier (collection or indexed-field name): a lowercase
/// `[a-z][a-z0-9_]{0,63}` token (must start with a letter), 1..=64 chars. This
/// exists so implementations can build dynamic SQL safely — identifiers cannot be
/// bound as parameters, so they must be whitelisted.
///
/// Note: this is intentionally STRICTER than the plugin-name rule
/// (`crate::plugin::PluginManifest::validate_name`, which also permits `-`):
/// a `-` is fine in a plugin/path name but is not a safe bare SQL identifier, and
/// requiring a leading letter avoids all-numeric identifiers that some backends
/// reject. The two rules are deliberately different.
pub fn is_valid_identifier(name: &str) -> bool {
    let len = name.len();
    if len == 0 || len > 64 {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_identifiers_accepted() {
        for n in &["users", "clients", "user_1", "a", "audit_chain"] {
            assert!(is_valid_identifier(n), "should accept {n}");
        }
    }

    #[test]
    fn injection_identifiers_rejected() {
        for n in &[
            "",
            "Users",                 // uppercase
            "users; DROP TABLE x",   // sql
            "u\"; --",
            "x) UNION SELECT 1 --",
            "_leading",              // must start alnum
            "a.b",                   // dot
            " space name",
            &"a".repeat(65),         // too long
        ] {
            assert!(!is_valid_identifier(n), "should reject {n:?}");
        }
    }

    // Round-2: Record's Debug must not dump the document (it may hold secrets).
    #[test]
    fn record_debug_redacts_doc() {
        let r = Record {
            id: "u1".into(),
            doc: serde_json::json!({ "password_hash": "argon2-very-secret" }),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("u1"), "id should be shown: {dbg}");
        assert!(dbg.contains("<redacted>"), "doc must be redacted: {dbg}");
        assert!(!dbg.contains("argon2-very-secret"), "secret leaked: {dbg}");
    }

    // Round-2: contract test for the default (non-atomic) put_if_absent fallback.
    #[test]
    fn put_if_absent_default_inserts_then_refuses_duplicate() {
        use std::collections::HashMap;
        use std::sync::Mutex;

        // Minimal in-memory store that does NOT override put_if_absent, so the
        // trait default is exercised.
        #[derive(Default)]
        struct MemStore {
            data: Mutex<HashMap<String, Record>>,
        }
        impl PersistenceProvider for MemStore {
            fn ensure_collection(&self, _spec: &CollectionSpec) -> Result<(), StoreError> {
                Ok(())
            }
            fn put(&self, _collection: &str, record: Record) -> Result<(), StoreError> {
                self.data.lock().unwrap().insert(record.id.clone(), record);
                Ok(())
            }
            fn get(&self, _collection: &str, id: &str) -> Result<Record, StoreError> {
                self.data
                    .lock()
                    .unwrap()
                    .get(id)
                    .cloned()
                    .ok_or_else(|| StoreError::NotFound(id.to_string()))
            }
            fn query(&self, _collection: &str, _query: &Query) -> Result<Vec<Record>, StoreError> {
                Ok(self.data.lock().unwrap().values().cloned().collect())
            }
            fn delete(&self, _collection: &str, id: &str) -> Result<(), StoreError> {
                self.data.lock().unwrap().remove(id);
                Ok(())
            }
        }

        let store = MemStore::default();
        let rec = Record { id: "tok-1".into(), doc: serde_json::json!({}) };

        // First insert succeeds.
        assert!(store.put_if_absent("tokens", rec.clone()).unwrap());
        // Second insert of the same id is refused (single-use semantics).
        assert!(!store.put_if_absent("tokens", rec).unwrap());
    }

    #[test]
    fn query_default_shapes_roundtrip_serde() {
        let q = Query::ByField { field: "username".into(), value: serde_json::json!("alice") };
        let s = serde_json::to_string(&q).unwrap();
        let back: Query = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Query::ByField { .. }));
    }
}
