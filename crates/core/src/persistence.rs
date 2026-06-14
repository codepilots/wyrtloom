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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub doc: serde_json::Value,
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
}

/// Validate a storage identifier (collection or indexed-field name): a lowercase
/// `[a-z0-9_]` token starting with a letter/digit, 1..=64 chars. This mirrors the
/// plugin-name rule and exists so implementations can build dynamic SQL safely —
/// identifiers cannot be bound as parameters, so they must be whitelisted.
pub fn is_valid_identifier(name: &str) -> bool {
    let len = name.len();
    if len == 0 || len > 64 {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
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

    #[test]
    fn query_default_shapes_roundtrip_serde() {
        let q = Query::ByField { field: "username".into(), value: serde_json::json!("alice") };
        let s = serde_json::to_string(&q).unwrap();
        let back: Query = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Query::ByField { .. }));
    }
}
