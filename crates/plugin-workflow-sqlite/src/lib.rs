/// SQLite persistence for the comprehension-first workflow state: coverage
/// map, calibration ledgers, regression suite, and rationale ledger.
///
/// This IS the storage layer the governance requirements point at:
///   CG-22 – retention limits are enforced here on every save and load;
///           ledgers are stored and retrieved one owner at a time, so no
///           cross-person scan or ranking query exists in the API.
///   CG-21 – what comes back out is the same governed `CalibrationLedger`
///           type, so per-event access stays owner-only after a reload.
///
/// Follows the established SQLite plugin conventions:
///   - paths are validated against traversal (finding 010);
///   - raw rusqlite error strings are mapped to opaque categories before
///     leaving the crate (finding 022).
use plugin_workflow_conversation::calibration::CalibrationLedger;
use plugin_workflow_conversation::coverage::CoverageMap;
use plugin_workflow_conversation::hunt::RegressionSuite;
use plugin_workflow_conversation::rationale::RationaleLedger;
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;
use thiserror::Error;
use wyrtloom_core::storage::validate_db_path;
use wyrtloom_core::types::{ActorId, Timestamp};

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("invalid database path: {0}")]
    InvalidPath(String),
    #[error("database operation failed: {0}")]
    Storage(&'static str),
    #[error("state could not be (de)serialised: {0}")]
    Serde(String),
}

/// Map raw rusqlite errors to opaque categories (finding 022).
fn opaque(e: rusqlite::Error) -> StoreError {
    let category = match e {
        rusqlite::Error::SqliteFailure(_, _) => "engine failure",
        rusqlite::Error::InvalidPath(_) => "invalid path",
        rusqlite::Error::QueryReturnedNoRows => "no rows",
        _ => "internal error",
    };
    StoreError::Storage(category)
}

const KIND_COVERAGE: &str = "coverage";
const KIND_CALIBRATION: &str = "calibration";
const KIND_REGRESSION: &str = "regression";
const KIND_RATIONALE: &str = "rationale";

pub struct SqliteWorkflowStore {
    conn: Mutex<Connection>,
}

impl SqliteWorkflowStore {
    /// Open or create a store at `path`. No traversal is permitted.
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory().map_err(opaque)?
        } else {
            validate_db_path(path).map_err(StoreError::InvalidPath)?;
            Connection::open(path).map_err(opaque)?
        };
        let store = Self { conn: Mutex::new(conn) };
        store.init_schema()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self, StoreError> {
        Self::open(":memory:")
    }

    fn init_schema(&self) -> Result<(), StoreError> {
        self.conn
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS workflow_state (
                    kind  TEXT NOT NULL,
                    key   TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (kind, key)
                );",
            )
            .map_err(opaque)
    }

    fn put(&self, kind: &str, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO workflow_state (kind, key, value) VALUES (?1, ?2, ?3)
                 ON CONFLICT (kind, key) DO UPDATE SET value = excluded.value",
                params![kind, key, value],
            )
            .map_err(opaque)?;
        Ok(())
    }

    fn get(&self, kind: &str, key: &str) -> Result<Option<String>, StoreError> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM workflow_state WHERE kind = ?1 AND key = ?2",
                params![kind, key],
                |row| row.get(0),
            )
            .optional()
            .map_err(opaque)
    }

    // ── Coverage map ─────────────────────────────────────────────────────

    pub fn save_coverage(&self, key: &str, map: &CoverageMap) -> Result<(), StoreError> {
        let json = serde_json::to_string(map).map_err(|e| StoreError::Serde(e.to_string()))?;
        self.put(KIND_COVERAGE, key, &json)
    }

    pub fn load_coverage(&self, key: &str) -> Result<Option<CoverageMap>, StoreError> {
        self.get(KIND_COVERAGE, key)?
            .map(|json| serde_json::from_str(&json).map_err(|e| StoreError::Serde(e.to_string())))
            .transpose()
    }

    // ── Calibration ledgers (governed, per owner) ────────────────────────

    /// Persist one owner's ledger, keyed by the owner. The retention limit
    /// is applied before the bytes hit disk (CG-22).
    pub fn save_ledger(&self, ledger: &mut CalibrationLedger) -> Result<(), StoreError> {
        ledger.enforce_retention(&Timestamp::now());
        let key = ledger.owner().clone();
        let json =
            serde_json::to_string(ledger).map_err(|e| StoreError::Serde(e.to_string()))?;
        self.put(KIND_CALIBRATION, &key, &json)
    }

    /// Load one owner's ledger. Retention is enforced again on the way out,
    /// so events that aged past the limit while stored never surface.
    pub fn load_ledger(&self, owner: &ActorId) -> Result<Option<CalibrationLedger>, StoreError> {
        let Some(json) = self.get(KIND_CALIBRATION, owner)? else {
            return Ok(None);
        };
        let mut ledger: CalibrationLedger =
            serde_json::from_str(&json).map_err(|e| StoreError::Serde(e.to_string()))?;
        ledger.enforce_retention(&Timestamp::now());
        Ok(Some(ledger))
    }

    /// CG-22: owner-initiated delete reaches the stored bytes too.
    pub fn delete_ledger(&self, owner: &ActorId) -> Result<(), StoreError> {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM workflow_state WHERE kind = ?1 AND key = ?2",
                params![KIND_CALIBRATION, owner],
            )
            .map_err(opaque)?;
        Ok(())
    }

    // ── Regression suite ─────────────────────────────────────────────────

    pub fn save_suite(&self, key: &str, suite: &RegressionSuite) -> Result<(), StoreError> {
        let json = serde_json::to_string(suite).map_err(|e| StoreError::Serde(e.to_string()))?;
        self.put(KIND_REGRESSION, key, &json)
    }

    pub fn load_suite(&self, key: &str) -> Result<Option<RegressionSuite>, StoreError> {
        self.get(KIND_REGRESSION, key)?
            .map(|json| serde_json::from_str(&json).map_err(|e| StoreError::Serde(e.to_string())))
            .transpose()
    }

    // ── Rationale ledger ─────────────────────────────────────────────────

    pub fn save_rationale(&self, key: &str, ledger: &RationaleLedger) -> Result<(), StoreError> {
        let json =
            serde_json::to_string(ledger).map_err(|e| StoreError::Serde(e.to_string()))?;
        self.put(KIND_RATIONALE, key, &json)
    }

    pub fn load_rationale(&self, key: &str) -> Result<Option<RationaleLedger>, StoreError> {
        self.get(KIND_RATIONALE, key)?
            .map(|json| serde_json::from_str(&json).map_err(|e| StoreError::Serde(e.to_string())))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_workflow_conversation::calibration::{PracticeEvent, PracticeKind};
    use plugin_workflow_conversation::coverage::{Concept, CreditSource};
    use plugin_workflow_conversation::policy::LedgerGovernance;
    use plugin_workflow_conversation::rationale::AdrRecord;
    use uuid::Uuid;

    fn store() -> SqliteWorkflowStore {
        SqliteWorkflowStore::in_memory().unwrap()
    }

    #[test]
    fn coverage_round_trips_with_credits() {
        let store = store();
        let mut map = CoverageMap::new();
        map.add_concept(Concept {
            id: "tokeniser".into(),
            component: "parser".into(),
            summary: "splits raw input into tokens".into(),
        });
        map.add_concept(Concept {
            id: "limits".into(),
            component: "sandbox".into(),
            summary: "resource ceilings".into(),
        });
        map.credit_from_trace(
            &"human:alice".to_string(),
            &["tokeniser".into()],
            CreditSource::Hunt(Uuid::new_v4()),
            Timestamp::now(),
        );

        store.save_coverage("project", &map).unwrap();
        let loaded = store.load_coverage("project").unwrap().unwrap();
        assert!(!loaded.is_dark("tokeniser"));
        assert!(loaded.is_dark("limits"));
        assert_eq!(loaded.redundancy("tokeniser"), 1);
    }

    #[test]
    fn cg21_loaded_ledger_keeps_owner_only_access() {
        let store = store();
        let mut ledger =
            CalibrationLedger::new("human:alice".into(), LedgerGovernance::new(365));
        ledger.record_practice(PracticeEvent {
            concept: "tokeniser".into(),
            confidence: 0.8,
            success: true,
            kind: PracticeKind::Hunt,
            at: Timestamp::now(),
        });
        store.save_ledger(&mut ledger).unwrap();

        let loaded = store.load_ledger(&"human:alice".to_string()).unwrap().unwrap();
        assert_eq!(loaded.events(&"human:alice".to_string()).unwrap().len(), 1);
        assert!(loaded.events(&"human:manager".to_string()).is_err());
    }

    #[test]
    fn cg22_retention_is_enforced_at_the_storage_layer() {
        let store = store();
        let mut ledger =
            CalibrationLedger::new("human:alice".into(), LedgerGovernance::new(30));
        let mut stale = PracticeEvent {
            concept: "tokeniser".into(),
            confidence: 0.8,
            success: true,
            kind: PracticeKind::Probe,
            at: Timestamp(Timestamp::now().0 - chrono::Duration::days(60)),
        };
        ledger.record_practice(stale.clone());
        stale.at = Timestamp::now();
        ledger.record_practice(stale);

        store.save_ledger(&mut ledger).unwrap();
        let loaded = store.load_ledger(&"human:alice".to_string()).unwrap().unwrap();
        assert_eq!(
            loaded.events(&"human:alice".to_string()).unwrap().len(),
            1,
            "the 60-day-old event must not survive a 30-day retention limit"
        );
    }

    #[test]
    fn cg22_delete_removes_the_stored_ledger() {
        let store = store();
        let mut ledger =
            CalibrationLedger::new("human:alice".into(), LedgerGovernance::new(365));
        store.save_ledger(&mut ledger).unwrap();
        store.delete_ledger(&"human:alice".to_string()).unwrap();
        assert!(store.load_ledger(&"human:alice".to_string()).unwrap().is_none());
    }

    #[test]
    fn suite_and_rationale_round_trip() {
        let store = store();

        let mut suite = RegressionSuite::default();
        let test_id = Uuid::new_v4();
        suite.crystallise(test_id);
        store.save_suite("project", &suite).unwrap();
        let loaded = store.load_suite("project").unwrap().unwrap();
        assert_eq!(loaded.crystallised_tests, vec![test_id]);

        let mut rationale = RationaleLedger::new();
        let adr = rationale.append(AdrRecord::new(
            "Persist workflow state in SQLite",
            "In-memory state dies with the process",
            "Snapshot the governed types as JSON rows",
            "Governance stays in the types; storage stays simple",
            "agent:wyrt".into(),
        ));
        store.save_rationale("project", &rationale).unwrap();
        let loaded = store.load_rationale("project").unwrap().unwrap();
        assert!(loaded.find(adr).is_some());
    }

    #[test]
    fn missing_keys_load_as_none() {
        let store = store();
        assert!(store.load_coverage("nope").unwrap().is_none());
        assert!(store.load_suite("nope").unwrap().is_none());
        assert!(store.load_rationale("nope").unwrap().is_none());
        assert!(store.load_ledger(&"human:nobody".to_string()).unwrap().is_none());
    }

    #[test]
    fn save_overwrites_under_the_same_key() {
        let store = store();
        let mut suite = RegressionSuite::default();
        suite.crystallise(Uuid::new_v4());
        store.save_suite("project", &suite).unwrap();
        suite.crystallise(Uuid::new_v4());
        store.save_suite("project", &suite).unwrap();
        let loaded = store.load_suite("project").unwrap().unwrap();
        assert_eq!(loaded.crystallised_tests.len(), 2);
    }

    #[test]
    fn traversal_paths_are_rejected() {
        assert!(matches!(
            SqliteWorkflowStore::open("../evil.db"),
            Err(StoreError::InvalidPath(_))
        ));
    }
}
