//! W9 — Insight Artifact (SQLite-backed).
//!
//! A first-class, typed home for human abstraction and *novel explanation*,
//! beside code, tests, and documentation (SoftDevSpec §1.4, D14.2, §2.5).
//! This is where the human's distinctive contribution stops being ephemeral.
//!
//! Implements SoftDevSpec §2.2 row W9 + §2.5; satisfies CG-27:
//!
//! > CG-27. Insight Artifacts SHALL be typed, linkable from coverage-map
//! > concepts, rationale entries, and code; authorship is human; capture
//! > labor is agent's.
//!
//! Authorship is therefore *human* (`author: ActorId`); the *capture* labor —
//! persisting, linking, superseding — is the agent's (this plugin).
//!
//! ## Storage pattern
//! Follows the standard Wyrtloom SQLite-plugin shape (cf.
//! `plugin-logger-sqlite`): a `Mutex<Connection>`, `open`/`in_memory`/
//! `init_schema`, `validate_db_path` for traversal defence, opaque SQLite
//! error mapping, and integrity errors on malformed rows. List/enum fields
//! (`concepts`, `links`, `born_of`, `status`) are stored as JSON via
//! `serde_json`.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;
use wyrtloom_core::storage::validate_db_path;
use wyrtloom_core::types::{ActorId, TaskId, Timestamp};

/// Identifier for a coverage-map concept (W6) an artifact illuminates.
///
/// A local newtype — the coverage map (W6) owns the canonical concept
/// inventory; here we only need a typed, linkable reference (CG-27).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConceptId(pub String);

impl ConceptId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// What occasioned the abstraction — the workflow event it was *born of*
/// (SoftDevSpec §2.5: `hunt_id | build_id | route_id | gate_id |
/// solo_flight_id`).
///
/// Each variant carries the originating `TaskId`, tying the insight back to
/// the concrete piece of work that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BornOf {
    /// Born of a hunt (W4) — a human-authored breaking test.
    Hunt(TaskId),
    /// Born of a reserved Build & Own task.
    Build(TaskId),
    /// Born of an interest-routed problem (W10).
    Route(TaskId),
    /// Born of resolving a gate (W2).
    Gate(TaskId),
    /// Born of a scheduled solo flight (W11).
    SoloFlight(TaskId),
}

/// A typed link from the artifact to another first-class element
/// (SoftDevSpec §2.5: `code_ref | rationale_ref | test_ref | contract_ref`).
///
/// CG-27 requires artifacts be linkable from coverage-map concepts, rationale
/// entries, and code; these refs realise that linkability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Link {
    /// A reference into source code (e.g. `path/to/file.rs:42`).
    Code(String),
    /// A reference to a rationale-ledger entry (W13).
    Rationale(String),
    /// A reference to a test.
    Test(String),
    /// A reference to a typed contract.
    Contract(String),
}

/// Living vs. superseded status (SoftDevSpec §2.5: `living | superseded(by)`).
///
/// Insights are never deleted; a newer explanation *supersedes* an older one,
/// preserving the chain of understanding. `Superseded` carries the id of the
/// artifact that replaced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    /// The current, in-force explanation.
    Living,
    /// Replaced by the artifact with this id.
    Superseded { by: Uuid },
}

/// A first-class Insight Artifact (SoftDevSpec §2.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsightArtifact {
    pub id: Uuid,
    /// The human author — authorship is HUMAN (CG-27).
    pub author: ActorId,
    pub created_at: Timestamp,
    /// The novel explanation itself.
    pub abstraction: String,
    /// The workflow event that occasioned this insight.
    pub born_of: BornOf,
    /// Coverage-map concepts this insight illuminates.
    pub concepts: Vec<ConceptId>,
    /// Typed links to code, rationale, tests, contracts.
    pub links: Vec<Link>,
    pub status: Status,
}

impl InsightArtifact {
    /// Construct a new *living* artifact with a fresh id and `created_at = now`.
    ///
    /// Authorship is human: `author` is a real `ActorId` (CG-27).
    pub fn new(
        author: ActorId,
        abstraction: impl Into<String>,
        born_of: BornOf,
        concepts: Vec<ConceptId>,
        links: Vec<Link>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            author,
            created_at: Timestamp::now(),
            abstraction: abstraction.into(),
            born_of,
            concepts,
            links,
            status: Status::Living,
        }
    }
}

/// Errors surfaced by the artifact store.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// An opaque storage failure (SQLite). The underlying error text is *not*
    /// propagated, matching the other SQLite plugins' opacity policy.
    #[error("storage error: {0}")]
    Storage(String),
    /// A referenced artifact id does not exist in the store.
    #[error("artifact not found: {0}")]
    NotFound(Uuid),
    /// An artifact cannot supersede itself (`old == new.id`).
    #[error("artifact cannot supersede itself: {0}")]
    SelfSupersede(Uuid),
}

/// SQLite-backed Insight Artifact store.
///
/// The agent does the *capture* labor (CG-27): persisting, linking, and
/// superseding the human-authored insights.
pub struct SqliteInsightStore {
    conn: Mutex<Connection>,
}

impl SqliteInsightStore {
    /// Open (or create) a store at `path`. Rejects path-traversal (`..`)
    /// via `validate_db_path`.
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            validate_db_path(path)
                .map_err(|e| rusqlite::Error::InvalidPath(std::path::PathBuf::from(e)))?;
            Connection::open(path)?
        };
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// In-memory store (tests / ephemeral use).
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        self.conn.lock().unwrap().execute_batch(
            "CREATE TABLE IF NOT EXISTS insight_artifacts (
                id          TEXT PRIMARY KEY,
                author      TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                abstraction TEXT NOT NULL,
                born_of     TEXT NOT NULL,   -- JSON BornOf
                concepts    TEXT NOT NULL,   -- JSON Vec<ConceptId>
                links       TEXT NOT NULL,   -- JSON Vec<Link>
                status      TEXT NOT NULL    -- JSON Status
            );",
        )
    }

    /// Persist a new artifact (capture labor; CG-27).
    pub fn store(&self, artifact: &InsightArtifact) -> Result<(), ArtifactError> {
        let born_of = serde_json::to_string(&artifact.born_of)
            .map_err(|_| ArtifactError::Storage("serialize born_of failed".into()))?;
        let concepts = serde_json::to_string(&artifact.concepts)
            .map_err(|_| ArtifactError::Storage("serialize concepts failed".into()))?;
        let links = serde_json::to_string(&artifact.links)
            .map_err(|_| ArtifactError::Storage("serialize links failed".into()))?;
        let status = serde_json::to_string(&artifact.status)
            .map_err(|_| ArtifactError::Storage("serialize status failed".into()))?;

        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO insight_artifacts
                 (id, author, created_at, abstraction, born_of, concepts, links, status)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    artifact.id.to_string(),
                    artifact.author,
                    artifact.created_at.0.to_rfc3339(),
                    artifact.abstraction,
                    born_of,
                    concepts,
                    links,
                    status,
                ],
            )
            .map_err(|_| ArtifactError::Storage("insert failed".into()))?;
        Ok(())
    }

    /// Fetch a single artifact by id, or `Ok(None)` if absent.
    pub fn get(&self, id: Uuid) -> Result<Option<InsightArtifact>, ArtifactError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, author, created_at, abstraction, born_of, concepts, links, status
                 FROM insight_artifacts WHERE id = ?1",
            )
            .map_err(|_| ArtifactError::Storage("prepare failed".into()))?;

        let mut rows = stmt
            .query(params![id.to_string()])
            .map_err(|_| ArtifactError::Storage("query failed".into()))?;

        match rows
            .next()
            .map_err(|_| ArtifactError::Storage("row read failed".into()))?
        {
            Some(row) => Ok(Some(row_to_artifact(row).map_err(map_row_err)?)),
            None => Ok(None),
        }
    }

    /// Return all artifacts, ordered by creation time then id.
    pub fn all(&self) -> Result<Vec<InsightArtifact>, ArtifactError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, author, created_at, abstraction, born_of, concepts, links, status
                 FROM insight_artifacts ORDER BY created_at, id",
            )
            .map_err(|_| ArtifactError::Storage("prepare failed".into()))?;

        let mapped = stmt
            .query_map([], row_to_artifact)
            .map_err(|_| ArtifactError::Storage("query failed".into()))?;

        let mut out = Vec::new();
        for r in mapped {
            out.push(r.map_err(map_row_err)?);
        }
        Ok(out)
    }

    /// Mark `old` as superseded by `new`, persisting `new` if it is not already
    /// stored.
    ///
    /// Sets `old.status = Superseded { by: new.id }`. The superseded artifact is
    /// retained (insights are never deleted), preserving the chain of
    /// understanding (§2.5). Errors with `NotFound` if `old` is absent.
    pub fn supersede(&self, old: Uuid, new: &InsightArtifact) -> Result<(), ArtifactError> {
        // An artifact cannot supersede itself: that would mark the living
        // current explanation as superseded by itself, a self-referential dead
        // state that breaks the supersede chain (§2.5).
        if old == new.id {
            return Err(ArtifactError::SelfSupersede(old));
        }

        // Ensure the superseding artifact is the living current explanation.
        if self.get(new.id)?.is_none() {
            self.store(new)?;
        }

        let new_status = Status::Superseded { by: new.id };
        let status_json = serde_json::to_string(&new_status)
            .map_err(|_| ArtifactError::Storage("serialize status failed".into()))?;

        let affected = self
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE insight_artifacts SET status = ?1 WHERE id = ?2",
                params![status_json, old.to_string()],
            )
            .map_err(|_| ArtifactError::Storage("update failed".into()))?;

        if affected == 0 {
            return Err(ArtifactError::NotFound(old));
        }
        Ok(())
    }
}

fn map_row_err(_: rusqlite::Error) -> ArtifactError {
    ArtifactError::Storage("row read failed".into())
}

/// Reconstruct an artifact from a row, treating any malformed field as an
/// integrity error (mirrors `plugin-logger-sqlite`'s policy).
fn row_to_artifact(row: &rusqlite::Row) -> Result<InsightArtifact, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let author: ActorId = row.get(1)?;
    let created_at_str: String = row.get(2)?;
    let abstraction: String = row.get(3)?;
    let born_of_str: String = row.get(4)?;
    let concepts_str: String = row.get(5)?;
    let links_str: String = row.get(6)?;
    let status_str: String = row.get(7)?;

    // Integrity errors map to an opaque SQLite error so the public API never
    // leaks raw parse details (cf. logger plugin findings 010/011).
    let integrity = |what: &str| {
        rusqlite::Error::InvalidColumnType(
            0,
            format!("integrity error: malformed {}", what),
            rusqlite::types::Type::Text,
        )
    };

    let id = Uuid::parse_str(&id_str).map_err(|_| integrity("id"))?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| Timestamp(dt.with_timezone(&chrono::Utc)))
        .map_err(|_| integrity("created_at"))?;
    let born_of: BornOf =
        serde_json::from_str(&born_of_str).map_err(|_| integrity("born_of"))?;
    let concepts: Vec<ConceptId> =
        serde_json::from_str(&concepts_str).map_err(|_| integrity("concepts"))?;
    let links: Vec<Link> =
        serde_json::from_str(&links_str).map_err(|_| integrity("links"))?;
    let status: Status =
        serde_json::from_str(&status_str).map_err(|_| integrity("status"))?;

    Ok(InsightArtifact {
        id,
        author,
        created_at,
        abstraction,
        born_of,
        concepts,
        links,
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SqliteInsightStore {
        SqliteInsightStore::in_memory().unwrap()
    }

    fn sample(author: &str) -> InsightArtifact {
        InsightArtifact::new(
            author.to_string(),
            "Malformed unicode at the parser boundary is really a framing bug.",
            BornOf::Hunt(Uuid::new_v4()),
            vec![ConceptId::new("coverage:unicode-framing")],
            vec![Link::Code("crates/parser/src/lib.rs:88".into())],
        )
    }

    // ---- contract tests (authored before implementation) ----

    #[test]
    fn new_artifact_is_living_with_human_author() {
        let a = sample("alice");
        assert_eq!(a.status, Status::Living);
        assert_eq!(a.author, "alice"); // authorship is HUMAN — CG-27
        assert!(!a.id.is_nil());
    }

    #[test]
    fn store_and_get_round_trips_all_fields() {
        let s = store();
        let a = sample("alice");
        s.store(&a).unwrap();
        let got = s.get(a.id).unwrap().expect("artifact present");
        assert_eq!(got, a);
    }

    #[test]
    fn get_missing_returns_none() {
        let s = store();
        assert!(s.get(Uuid::new_v4()).unwrap().is_none());
    }

    #[test]
    fn all_lists_stored_artifacts() {
        let s = store();
        s.store(&sample("alice")).unwrap();
        s.store(&sample("bob")).unwrap();
        assert_eq!(s.all().unwrap().len(), 2);
    }

    #[test]
    fn supersede_sets_status_superseded_by() {
        let s = store();
        let old = sample("alice");
        s.store(&old).unwrap();
        let new = sample("alice");
        s.supersede(old.id, &new).unwrap();

        let old_after = s.get(old.id).unwrap().unwrap();
        assert_eq!(old_after.status, Status::Superseded { by: new.id });
        // Superseding artifact is persisted and living.
        let new_after = s.get(new.id).unwrap().unwrap();
        assert_eq!(new_after.status, Status::Living);
    }

    #[test]
    fn supersede_missing_old_is_not_found() {
        let s = store();
        let new = sample("alice");
        let missing = Uuid::new_v4();
        let err = s.supersede(missing, &new).unwrap_err();
        assert!(matches!(err, ArtifactError::NotFound(id) if id == missing));
    }

    #[test]
    fn supersede_self_is_rejected() {
        let s = store();
        let a = sample("alice");
        s.store(&a).unwrap();
        let err = s.supersede(a.id, &a).unwrap_err();
        assert!(matches!(err, ArtifactError::SelfSupersede(id) if id == a.id));
        // The artifact stays living — its status was not mutated.
        assert_eq!(s.get(a.id).unwrap().unwrap().status, Status::Living);
    }

    #[test]
    fn born_of_variants_round_trip() {
        let s = store();
        let task = Uuid::new_v4();
        for born in [
            BornOf::Hunt(task),
            BornOf::Build(task),
            BornOf::Route(task),
            BornOf::Gate(task),
            BornOf::SoloFlight(task),
        ] {
            let a = InsightArtifact::new(
                "alice".into(),
                "x",
                born.clone(),
                vec![],
                vec![],
            );
            s.store(&a).unwrap();
            assert_eq!(s.get(a.id).unwrap().unwrap().born_of, born);
        }
    }

    #[test]
    fn link_variants_round_trip() {
        let s = store();
        let a = InsightArtifact::new(
            "alice".into(),
            "x",
            BornOf::Gate(Uuid::new_v4()),
            vec![],
            vec![
                Link::Code("a.rs:1".into()),
                Link::Rationale("ADR-7".into()),
                Link::Test("t::case".into()),
                Link::Contract("C-3".into()),
            ],
        );
        s.store(&a).unwrap();
        assert_eq!(s.get(a.id).unwrap().unwrap().links.len(), 4);
    }

    #[test]
    fn path_traversal_is_rejected() {
        assert!(SqliteInsightStore::open("../etc/insight.db").is_err());
    }

    #[test]
    fn malformed_row_is_integrity_error() {
        let s = store();
        // Corrupt a row's JSON directly.
        let a = sample("alice");
        s.store(&a).unwrap();
        s.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE insight_artifacts SET born_of = ?1 WHERE id = ?2",
                params!["{not valid", a.id.to_string()],
            )
            .unwrap();
        assert!(s.get(a.id).is_err());
    }

    /// CORE INTEGRATION TEST (required by the W9 brief).
    ///
    /// Store an artifact linked to a coverage concept and a real `TaskId`;
    /// round-trip via `in_memory()`; assert that superseding sets
    /// `status = superseded(by)` and that the author is a real `ActorId`.
    #[test]
    fn core_integration_store_link_and_supersede() {
        let s = SqliteInsightStore::in_memory().unwrap();

        let task: TaskId = Uuid::new_v4();
        let author: ActorId = "alice".to_string();
        let concept = ConceptId::new("coverage:unicode-framing");

        let original = InsightArtifact::new(
            author.clone(),
            "The malformed-unicode defect is a framing-boundary instance.",
            BornOf::Hunt(task),
            vec![concept.clone()],
            vec![Link::Test("hunt::malformed_unicode".into())],
        );
        s.store(&original).unwrap();

        // Round-trip.
        let got = s.get(original.id).unwrap().expect("stored");
        assert_eq!(got, original);
        assert_eq!(got.concepts, vec![concept]); // linked to coverage concept
        assert_eq!(got.born_of, BornOf::Hunt(task)); // real TaskId preserved
        assert_eq!(got.author, author); // author is a real ActorId (human)
        assert_eq!(got.status, Status::Living);

        // A deeper explanation supersedes the first.
        let revised = InsightArtifact::new(
            author.clone(),
            "More precisely: the framing bug is a length-prefix sign error.",
            BornOf::Hunt(task),
            vec![ConceptId::new("coverage:unicode-framing")],
            vec![],
        );
        s.supersede(original.id, &revised).unwrap();

        let superseded = s.get(original.id).unwrap().unwrap();
        assert_eq!(superseded.status, Status::Superseded { by: revised.id });
        assert_eq!(superseded.author, author); // authorship unchanged, human

        let current = s.get(revised.id).unwrap().unwrap();
        assert_eq!(current.status, Status::Living);
    }
}
