//! W13 — Rationale ledger (SQLite).
//!
//! SQLite-backed, ADR-shaped decision ledger. Each record captures the
//! **context**, **decision**, and **consequences** of an architectural choice
//! (ADR shape), is **agent-authored** (`ActorId`), **timestamped**
//! (`Timestamp`), and **linkable to a task** (`TaskId`).
//!
//! This is one of the four durable artifact streams written by the agent as a
//! by-product of the conversation (SoftDevSpec §1.4 item 2; F11). It implements
//! spec §2.2 row W13 ("ADR-shaped decision records, agent-authored") and feeds
//! the CG-28 audit requirement (all gate/hunt/probe/withdrawal/rotation events
//! logged for audit under CG-21/22 access rules).
//!
//! ## Append-only / immutability invariant
//!
//! The ledger is **append-only**: once written, a record is immutable. There is
//! deliberately **no in-place mutation API** (no update, no delete). A
//! "correction" is modelled as a *new* record that **supersedes** an earlier one
//! via `supersedes: Option<RationaleId>`, forming an auditable supersede chain.
//! This preserves the full decision history required for CG-28 audit — the
//! original rationale is never lost, only annotated as superseded.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;
use wyrtloom_core::storage::validate_db_path;
use wyrtloom_core::types::{ActorId, TaskId, Timestamp};

/// Stable identity of a single rationale (ADR) record.
pub type RationaleId = Uuid;

/// Errors surfaced by the rationale ledger.
///
/// SQLite-internal errors are mapped to opaque [`LedgerError::Storage`]
/// messages rather than leaking driver internals, matching the SQLite plugin
/// pattern used elsewhere in Wyrtloom.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("storage error: {0}")]
    Storage(String),
    /// A referenced record (e.g. a `supersedes` target) was not found.
    #[error("rationale not found: {0}")]
    NotFound(RationaleId),
}

/// A new, not-yet-persisted rationale record (the agent's authored input).
///
/// The persisted [`RationaleRecord`] additionally carries the assigned
/// [`RationaleId`] and the write [`Timestamp`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewRationale {
    /// Task this decision belongs to (CG-28 linkability).
    pub task: TaskId,
    /// Agent that authored the record (§2.2 W13: agent-authored).
    pub author: ActorId,
    /// Short human-readable title of the decision.
    pub title: String,
    /// ADR "Context": the forces and situation prompting the decision.
    pub context: String,
    /// ADR "Decision": what was decided.
    pub decision: String,
    /// ADR "Consequences": resulting trade-offs and follow-on effects.
    pub consequences: String,
    /// If this record corrects/replaces an earlier one, the superseded id.
    /// `None` for an original record.
    pub supersedes: Option<RationaleId>,
}

/// A persisted, immutable ADR-shaped rationale record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RationaleRecord {
    pub id: RationaleId,
    pub task: TaskId,
    pub author: ActorId,
    pub title: String,
    pub context: String,
    pub decision: String,
    pub consequences: String,
    /// The record this one supersedes, if any.
    pub supersedes: Option<RationaleId>,
    /// When the record was appended (immutable).
    pub recorded_at: Timestamp,
}

/// SQLite-backed, append-only rationale ledger.
pub struct SqliteRationaleLedger {
    conn: Mutex<Connection>,
}

impl SqliteRationaleLedger {
    /// Open (or create) a ledger at `path`. Use `":memory:"` for an in-memory
    /// database. Non-memory paths are validated against directory traversal.
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            validate_db_path(path)
                .map_err(|e| rusqlite::Error::InvalidPath(std::path::PathBuf::from(e)))?;
            Connection::open(path)?
        };
        let ledger = Self { conn: Mutex::new(conn) };
        ledger.init_schema()?;
        Ok(ledger)
    }

    /// Open an in-memory ledger (used for the round-trip integration test).
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        self.conn.lock().unwrap().execute_batch(
            "CREATE TABLE IF NOT EXISTS rationale_records (
                id           TEXT PRIMARY KEY NOT NULL,
                task_id      TEXT NOT NULL,
                author       TEXT NOT NULL,
                title        TEXT NOT NULL,
                context      TEXT NOT NULL,
                decision     TEXT NOT NULL,
                consequences TEXT NOT NULL,
                supersedes   TEXT,
                recorded_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rationale_task
                ON rationale_records (task_id);
            CREATE INDEX IF NOT EXISTS idx_rationale_supersedes
                ON rationale_records (supersedes);",
        )
    }

    /// Append a new immutable record, returning its assigned id and stored form.
    ///
    /// This is the **only** write path. There is no update or delete; the
    /// append-only invariant (§1.4) is enforced structurally by the absence of
    /// any mutation API. If `supersedes` is set, the target must already exist.
    pub fn append(&self, new: NewRationale) -> Result<RationaleRecord, LedgerError> {
        let record = RationaleRecord {
            id: Uuid::new_v4(),
            task: new.task,
            author: new.author,
            title: new.title,
            context: new.context,
            decision: new.decision,
            consequences: new.consequences,
            supersedes: new.supersedes,
            recorded_at: Timestamp::now(),
        };

        let conn = self.conn.lock().unwrap();

        // A supersede target must exist AND belong to the same task — a
        // correction supersedes a decision within its own task, never another
        // task's. This guards against dangling chains and cross-task supersedes
        // that would corrupt the per-task "current" view and the audit trail.
        if let Some(target) = record.supersedes {
            let target_task: Option<String> = conn
                .query_row(
                    "SELECT task_id FROM rationale_records WHERE id = ?1",
                    params![target.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
                .map_err(|_| LedgerError::Storage("supersede lookup failed".into()))?;
            match target_task {
                None => return Err(LedgerError::NotFound(target)),
                Some(t) if t != record.task.to_string() => {
                    return Err(LedgerError::Storage(format!(
                        "supersede target {} belongs to a different task",
                        target
                    )))
                }
                Some(_) => {}
            }
        }

        conn.execute(
            "INSERT INTO rationale_records
             (id, task_id, author, title, context, decision,
              consequences, supersedes, recorded_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                record.id.to_string(),
                record.task.to_string(),
                record.author,
                record.title,
                record.context,
                record.decision,
                record.consequences,
                record.supersedes.map(|s| s.to_string()),
                record.recorded_at.0.to_rfc3339(),
            ],
        )
        .map_err(|_| LedgerError::Storage("insert failed".into()))?;

        Ok(record)
    }

    /// Fetch a single record by id.
    pub fn get(&self, id: RationaleId) -> Result<RationaleRecord, LedgerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, task_id, author, title, context, decision,
                        consequences, supersedes, recorded_at
                 FROM rationale_records WHERE id = ?1",
            )
            .map_err(|_| LedgerError::Storage("prepare failed".into()))?;
        let mut rows = stmt
            .query(params![id.to_string()])
            .map_err(|_| LedgerError::Storage("query failed".into()))?;
        match rows
            .next()
            .map_err(|_| LedgerError::Storage("row read failed".into()))?
        {
            Some(row) => row_to_record(row),
            None => Err(LedgerError::NotFound(id)),
        }
    }

    /// All records authored against a given task, oldest first.
    pub fn for_task(&self, task: TaskId) -> Result<Vec<RationaleRecord>, LedgerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, task_id, author, title, context, decision,
                        consequences, supersedes, recorded_at
                 FROM rationale_records WHERE task_id = ?1
                 ORDER BY recorded_at, id",
            )
            .map_err(|_| LedgerError::Storage("prepare failed".into()))?;
        let rows = stmt
            .query_map(params![task.to_string()], record_columns)
            .map_err(|_| LedgerError::Storage("query failed".into()))?;
        collect_records(rows)
    }

    /// Every record, oldest first — the full append-only stream for audit.
    pub fn all(&self) -> Result<Vec<RationaleRecord>, LedgerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, task_id, author, title, context, decision,
                        consequences, supersedes, recorded_at
                 FROM rationale_records ORDER BY recorded_at, id",
            )
            .map_err(|_| LedgerError::Storage("prepare failed".into()))?;
        let rows = stmt
            .query_map([], record_columns)
            .map_err(|_| LedgerError::Storage("query failed".into()))?;
        collect_records(rows)
    }

    /// Records that have *not* been superseded by any later record, oldest
    /// first — the currently-effective view of decisions for a task.
    pub fn current_for_task(&self, task: TaskId) -> Result<Vec<RationaleRecord>, LedgerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, task_id, author, title, context, decision,
                        consequences, supersedes, recorded_at
                 FROM rationale_records r
                 WHERE r.task_id = ?1
                   AND NOT EXISTS (
                       SELECT 1 FROM rationale_records s
                       WHERE s.supersedes = r.id
                         AND s.task_id = r.task_id)
                 ORDER BY recorded_at, id",
            )
            .map_err(|_| LedgerError::Storage("prepare failed".into()))?;
        let rows = stmt
            .query_map(params![task.to_string()], record_columns)
            .map_err(|_| LedgerError::Storage("query failed".into()))?;
        collect_records(rows)
    }
}

/// Raw column tuple as read out of SQLite (before integrity validation).
type RawRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
);

/// Read a row's columns as a raw tuple, propagating (not panicking on) any
/// type/NULL mismatch as a `rusqlite::Error`. This preserves the "integrity
/// errors, not panics" intent: a corrupted NOT NULL column surfaces as a
/// `LedgerError::Storage` via `collect_records` rather than poisoning the
/// connection mutex (mirrors the logger plugin's `row.get::<_, T>(N)?` style).
fn record_columns(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

/// Validate a raw row and build a [`RationaleRecord`]. Malformed ids or
/// timestamps are integrity errors rather than silent coercions.
fn raw_to_record(raw: RawRow) -> Result<RationaleRecord, LedgerError> {
    let (id_s, task_s, author, title, context, decision, consequences, supersedes_s, at_s) = raw;

    let id = id_s
        .parse::<RationaleId>()
        .map_err(|_| LedgerError::Storage("integrity error: malformed id".into()))?;
    let task = task_s
        .parse::<TaskId>()
        .map_err(|_| LedgerError::Storage("integrity error: malformed task_id".into()))?;
    let supersedes = match supersedes_s {
        Some(s) => Some(
            s.parse::<RationaleId>()
                .map_err(|_| LedgerError::Storage("integrity error: malformed supersedes".into()))?,
        ),
        None => None,
    };
    let recorded_at = chrono::DateTime::parse_from_rfc3339(&at_s)
        .map(|dt| Timestamp(dt.with_timezone(&chrono::Utc)))
        .map_err(|_| LedgerError::Storage("integrity error: malformed timestamp".into()))?;

    Ok(RationaleRecord {
        id,
        task,
        author,
        title,
        context,
        decision,
        consequences,
        supersedes,
        recorded_at,
    })
}

fn row_to_record(row: &rusqlite::Row<'_>) -> Result<RationaleRecord, LedgerError> {
    let raw = record_columns(row).map_err(|_| LedgerError::Storage("row read failed".into()))?;
    raw_to_record(raw)
}

fn collect_records<I>(rows: I) -> Result<Vec<RationaleRecord>, LedgerError>
where
    I: Iterator<Item = rusqlite::Result<RawRow>>,
{
    let mut out = Vec::new();
    for row in rows {
        let raw = row.map_err(|_| LedgerError::Storage("row read failed".into()))?;
        out.push(raw_to_record(raw)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger() -> SqliteRationaleLedger {
        SqliteRationaleLedger::in_memory().unwrap()
    }

    fn sample(task: TaskId) -> NewRationale {
        NewRationale {
            task,
            author: "agent://planner".into(),
            title: "Use SQLite for the rationale ledger".into(),
            context: "Need a durable, queryable, append-only store.".into(),
            decision: "Adopt rusqlite with a single immutable table.".into(),
            consequences: "Simple ops; corrections modelled as supersede records.".into(),
            supersedes: None,
        }
    }

    // ---- CORE INTEGRATION TEST -------------------------------------------
    // Append + query ADR records keyed by real TaskId/Timestamp, round-trip
    // via in_memory(), and assert append-only / immutability.
    #[test]
    fn append_query_roundtrip_and_append_only() {
        let l = ledger();
        let task: TaskId = Uuid::new_v4();

        // Append an original record.
        let original = l.append(sample(task)).unwrap();

        // Round-trip: stored form matches what we read back by id.
        let fetched = l.get(original.id).unwrap();
        assert_eq!(fetched, original);
        assert_eq!(fetched.task, task);
        assert!(fetched.supersedes.is_none());
        // Real Timestamp is preserved through serialization (rfc3339).
        assert_eq!(fetched.recorded_at, original.recorded_at);

        // Append-only / immutable: there is NO update/delete API. A correction
        // is a brand-new superseding record; the original is untouched.
        let mut correction = sample(task);
        correction.title = "Correction: add supersede chain".into();
        correction.decision = "Keep SQLite; document supersede semantics.".into();
        correction.supersedes = Some(original.id);
        let superseding = l.append(correction).unwrap();

        // Distinct identity — the original was not mutated in place.
        assert_ne!(superseding.id, original.id);
        assert_eq!(superseding.supersedes, Some(original.id));

        // The original is still byte-for-byte what we wrote.
        let original_again = l.get(original.id).unwrap();
        assert_eq!(original_again, original);

        // Full audit stream contains BOTH records.
        let all = l.for_task(task).unwrap();
        assert_eq!(all.len(), 2);

        // Current view excludes the superseded original.
        let current = l.current_for_task(task).unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].id, superseding.id);
    }

    #[test]
    fn adr_fields_are_persisted() {
        let l = ledger();
        let task = Uuid::new_v4();
        let rec = l.append(sample(task)).unwrap();
        let got = l.get(rec.id).unwrap();
        assert_eq!(got.context, "Need a durable, queryable, append-only store.");
        assert_eq!(got.decision, "Adopt rusqlite with a single immutable table.");
        assert_eq!(
            got.consequences,
            "Simple ops; corrections modelled as supersede records."
        );
        assert_eq!(got.author, "agent://planner");
    }

    #[test]
    fn for_task_isolates_by_task() {
        let l = ledger();
        let task_a = Uuid::new_v4();
        let task_b = Uuid::new_v4();
        l.append(sample(task_a)).unwrap();
        l.append(sample(task_a)).unwrap();
        l.append(sample(task_b)).unwrap();
        assert_eq!(l.for_task(task_a).unwrap().len(), 2);
        assert_eq!(l.for_task(task_b).unwrap().len(), 1);
        assert_eq!(l.all().unwrap().len(), 3);
    }

    #[test]
    fn supersede_target_must_exist() {
        let l = ledger();
        let task = Uuid::new_v4();
        let mut bad = sample(task);
        let phantom = Uuid::new_v4();
        bad.supersedes = Some(phantom);
        let err = l.append(bad).unwrap_err();
        assert!(matches!(err, LedgerError::NotFound(id) if id == phantom));
    }

    #[test]
    fn chained_supersedes_keep_only_tip_current() {
        let l = ledger();
        let task = Uuid::new_v4();
        let v1 = l.append(sample(task)).unwrap();

        let mut r2 = sample(task);
        r2.supersedes = Some(v1.id);
        let v2 = l.append(r2).unwrap();

        let mut r3 = sample(task);
        r3.supersedes = Some(v2.id);
        let v3 = l.append(r3).unwrap();

        let current = l.current_for_task(task).unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].id, v3.id);
        // Full chain preserved for audit (CG-28).
        assert_eq!(l.for_task(task).unwrap().len(), 3);
    }

    #[test]
    fn get_unknown_id_is_not_found() {
        let l = ledger();
        let missing = Uuid::new_v4();
        assert!(matches!(l.get(missing), Err(LedgerError::NotFound(id)) if id == missing));
    }

    #[test]
    fn malformed_timestamp_row_is_integrity_error() {
        let l = ledger();
        let task = Uuid::new_v4();
        let rec = l.append(sample(task)).unwrap();
        // Corrupt the stored timestamp directly to simulate DB tampering.
        {
            let conn = l.conn.lock().unwrap();
            conn.execute(
                "UPDATE rationale_records SET recorded_at = 'not-a-date' WHERE id = ?1",
                params![rec.id.to_string()],
            )
            .unwrap();
        }
        let err = l.get(rec.id).unwrap_err();
        assert!(matches!(err, LedgerError::Storage(m) if m.contains("integrity error")));
    }

    #[test]
    fn wrong_typed_column_is_integrity_error_not_panic() {
        // A TEXT column corrupted to a non-text value (SQLite type affinity
        // permits this) must surface as a Storage error from the row reader,
        // not a panic that unwinds the query_map closure and poisons the mutex.
        let l = ledger();
        let task = Uuid::new_v4();
        let rec = l.append(sample(task)).unwrap();
        {
            let conn = l.conn.lock().unwrap();
            conn.execute(
                "UPDATE rationale_records SET title = X'00FF' WHERE id = ?1",
                params![rec.id.to_string()],
            )
            .unwrap();
        }
        // Must return an error rather than unwinding through the closure.
        assert!(l.all().is_err());
        assert!(l.get(rec.id).is_err());
        // And the mutex is not poisoned: a subsequent call still works.
        let task2 = Uuid::new_v4();
        assert!(l.append(sample(task2)).is_ok());
    }

    #[test]
    fn cross_task_supersede_is_rejected() {
        let l = ledger();
        let task_a = Uuid::new_v4();
        let task_b = Uuid::new_v4();
        let a1 = l.append(sample(task_a)).unwrap();
        // A record under task B may not supersede a record under task A.
        let mut b = sample(task_b);
        b.supersedes = Some(a1.id);
        let err = l.append(b).unwrap_err();
        assert!(matches!(err, LedgerError::Storage(m) if m.contains("different task")));
        // task A's current view is unaffected.
        let current_a = l.current_for_task(task_a).unwrap();
        assert_eq!(current_a.len(), 1);
        assert_eq!(current_a[0].id, a1.id);
    }

    // Path traversal is rejected (mirrors the logger plugin's hardening).
    #[test]
    fn path_with_parent_traversal_is_rejected() {
        assert!(SqliteRationaleLedger::open("../etc/ledger.db").is_err());
    }
}
