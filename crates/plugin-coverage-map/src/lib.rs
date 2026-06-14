//! W6 — Coverage map (SQLite).
//!
//! Implements spec §2.2 row W6: a concept inventory per component, with links
//! concept ↔ artifact ↔ human ([`ActorId`]). This is the substrate that the
//! Hunt/probe components (W4/W5) credit into.
//!
//! Supported requirements:
//!   * CG-6  — Coverage credit is computed deterministically from the concepts a
//!             hunt-test exercises (instrumented execution trace ∩ coverage map).
//!             This crate is the persisted coverage map that side of the
//!             intersection reads from.
//!   * CG-19 — Probes trigger only for coverage-map areas *dark* after
//!             hunt/build/solo credit. A "dark" concept is one with no living
//!             human ([`ActorId`]) link; [`CoverageMap::dark_concepts`] is the
//!             deterministic query that surfaces them.
//!
//! Follows the SQLite plugin pattern of `plugin-logger-sqlite`:
//!   * `pub struct CoverageMap { conn: Mutex<Connection> }`
//!   * constructors `open(path)` and `in_memory()` (delegates to `open(":memory:")`)
//!   * private `init_schema()`
//!   * malformed rows (bad uuid/timestamp) → [`CoverageError::Storage`]
//!     ("integrity error: …"), never a silent substitution; raw SQLite errors
//!     are mapped to opaque strings.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use wyrtloom_core::storage::validate_db_path;
use wyrtloom_core::types::{ActorId, Timestamp};

/// Stable identifier for a coverage-map concept.
///
/// A *concept* is a named unit of comprehension territory within a component
/// (e.g. "malformed-unicode handling" inside a parser). Concepts are the grain
/// at which coverage is credited (CG-6) and at which darkness is detected
/// (CG-19).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConceptId(pub String);

impl ConceptId {
    pub fn new(s: impl Into<String>) -> Self {
        ConceptId(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ConceptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A coverage-map concept: a unit of comprehension territory owned by a component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Concept {
    pub id: ConceptId,
    /// Component this concept inventories (spec §2.2 "concept inventory per component").
    pub component: String,
    /// Human-readable label.
    pub label: String,
    pub created_at: Timestamp,
}

/// Errors surfaced by the coverage map. Raw SQLite errors are deliberately
/// flattened into opaque strings so the storage layer does not leak internals.
#[derive(Debug, thiserror::Error)]
pub enum CoverageError {
    #[error("storage error: {0}")]
    Storage(String),
}

pub struct CoverageMap {
    conn: Mutex<Connection>,
}

impl CoverageMap {
    /// Open (or create) a coverage map at `path`. Real paths are validated
    /// against directory traversal via [`validate_db_path`].
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            validate_db_path(path)
                .map_err(|e| rusqlite::Error::InvalidPath(std::path::PathBuf::from(e)))?;
            Connection::open(path)?
        };
        // Enforce the declared FOREIGN KEY constraints. rusqlite leaves
        // foreign-key enforcement OFF by default, which would make the
        // `REFERENCES concepts(id)` clauses inert and allow orphan links;
        // `ensure_concept_exists` is then the *only* integrity guard. Turning
        // the pragma on makes the schema itself the backstop.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let map = Self {
            conn: Mutex::new(conn),
        };
        map.init_schema()?;
        Ok(map)
    }

    /// In-memory coverage map for tests and ephemeral use.
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        self.conn.lock().unwrap().execute_batch(
            "CREATE TABLE IF NOT EXISTS concepts (
                id          TEXT PRIMARY KEY,
                component   TEXT NOT NULL,
                label       TEXT NOT NULL,
                created_at  TEXT NOT NULL
            );

            -- concept ↔ artifact links (artifact identified by an opaque string ref).
            CREATE TABLE IF NOT EXISTS concept_artifacts (
                concept_id   TEXT NOT NULL,
                artifact_ref TEXT NOT NULL,
                linked_at    TEXT NOT NULL,
                PRIMARY KEY (concept_id, artifact_ref),
                FOREIGN KEY (concept_id) REFERENCES concepts(id)
            );

            -- concept ↔ human links. A *living* link (living = 1) means a human
            -- holds comprehension of this concept; CG-19 darkness is the absence
            -- of any living link.
            CREATE TABLE IF NOT EXISTS concept_actors (
                concept_id  TEXT NOT NULL,
                actor_id    TEXT NOT NULL,
                living      INTEGER NOT NULL DEFAULT 1,
                linked_at   TEXT NOT NULL,
                PRIMARY KEY (concept_id, actor_id),
                FOREIGN KEY (concept_id) REFERENCES concepts(id)
            );",
        )
    }

    /// Register a concept in the inventory. Idempotent on `id`: re-registration
    /// refreshes `component`/`label` but preserves the original `created_at`
    /// (creation time is immutable provenance, not refreshed on each re-add).
    pub fn add_concept(&self, concept: &Concept) -> Result<(), CoverageError> {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO concepts (id, component, label, created_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                     component  = excluded.component,
                     label      = excluded.label",
                params![
                    concept.id.0,
                    concept.component,
                    concept.label,
                    concept.created_at.0.to_rfc3339(),
                ],
            )
            .map_err(|_| CoverageError::Storage("insert concept failed".into()))?;
        Ok(())
    }

    /// Link a concept to an artifact (e.g. a source file, test, or digest ref).
    /// The concept must already exist. Idempotent on (concept, artifact).
    pub fn link_artifact(
        &self,
        concept: &ConceptId,
        artifact_ref: &str,
    ) -> Result<(), CoverageError> {
        self.ensure_concept_exists(concept)?;
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO concept_artifacts (concept_id, artifact_ref, linked_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(concept_id, artifact_ref) DO NOTHING",
                params![concept.0, artifact_ref, Timestamp::now().0.to_rfc3339()],
            )
            .map_err(|_| CoverageError::Storage("link artifact failed".into()))?;
        Ok(())
    }

    /// Link a concept to a human ([`ActorId`]) as a *living* comprehension link.
    /// The concept must already exist. Idempotent on (concept, actor); a
    /// re-link revives a previously-decayed link.
    pub fn link_actor(&self, concept: &ConceptId, actor: &ActorId) -> Result<(), CoverageError> {
        self.ensure_concept_exists(concept)?;
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO concept_actors (concept_id, actor_id, living, linked_at)
                 VALUES (?1, ?2, 1, ?3)
                 ON CONFLICT(concept_id, actor_id) DO UPDATE SET
                     living    = 1,
                     linked_at = excluded.linked_at",
                params![concept.0, actor, Timestamp::now().0.to_rfc3339()],
            )
            .map_err(|_| CoverageError::Storage("link actor failed".into()))?;
        Ok(())
    }

    /// Mark a concept↔actor link as no longer living (comprehension decayed /
    /// the human left). The concept becomes dark again if this was its last
    /// living human link. No-op if the link does not exist.
    pub fn decay_actor_link(
        &self,
        concept: &ConceptId,
        actor: &ActorId,
    ) -> Result<(), CoverageError> {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE concept_actors SET living = 0
                 WHERE concept_id = ?1 AND actor_id = ?2",
                params![concept.0, actor],
            )
            .map_err(|_| CoverageError::Storage("decay actor link failed".into()))?;
        Ok(())
    }

    /// Run a `SELECT id, component, label, created_at` query and map every row
    /// into a [`Concept`]. Shared by [`Self::all_concepts`] and
    /// [`Self::dark_concepts`] so the row shape lives in exactly one place — a
    /// new column added to [`Concept`] cannot desync the two readers.
    fn query_concepts(&self, sql: &str) -> Result<Vec<Concept>, CoverageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(sql)
            .map_err(|_| CoverageError::Storage("prepare failed".into()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|_| CoverageError::Storage("query failed".into()))?;

        let mut out = vec![];
        for row in rows {
            let (id, component, label, created_at_str) =
                row.map_err(|_| CoverageError::Storage("row read failed".into()))?;
            let created_at = parse_ts(&created_at_str)?;
            out.push(Concept {
                id: ConceptId(id),
                component,
                label,
                created_at,
            });
        }
        Ok(out)
    }

    /// All registered concepts, ordered by id.
    pub fn all_concepts(&self) -> Result<Vec<Concept>, CoverageError> {
        self.query_concepts("SELECT id, component, label, created_at FROM concepts ORDER BY id")
    }

    /// Artifact refs linked to a concept, ordered.
    pub fn artifacts_for(&self, concept: &ConceptId) -> Result<Vec<String>, CoverageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT artifact_ref FROM concept_artifacts
                 WHERE concept_id = ?1 ORDER BY artifact_ref",
            )
            .map_err(|_| CoverageError::Storage("prepare failed".into()))?;
        let rows = stmt
            .query_map(params![concept.0], |row| row.get::<_, String>(0))
            .map_err(|_| CoverageError::Storage("query failed".into()))?;
        let mut out = vec![];
        for row in rows {
            out.push(row.map_err(|_| CoverageError::Storage("row read failed".into()))?);
        }
        Ok(out)
    }

    /// Living human ([`ActorId`]) links for a concept, ordered.
    pub fn living_actors_for(&self, concept: &ConceptId) -> Result<Vec<ActorId>, CoverageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT actor_id FROM concept_actors
                 WHERE concept_id = ?1 AND living = 1 ORDER BY actor_id",
            )
            .map_err(|_| CoverageError::Storage("prepare failed".into()))?;
        let rows = stmt
            .query_map(params![concept.0], |row| row.get::<_, String>(0))
            .map_err(|_| CoverageError::Storage("query failed".into()))?;
        let mut out = vec![];
        for row in rows {
            out.push(row.map_err(|_| CoverageError::Storage("row read failed".into()))?);
        }
        Ok(out)
    }

    /// CG-19 — the *dark* concepts: those with no living human ([`ActorId`])
    /// link. Computed deterministically with a left-anti-join against living
    /// concept↔actor links. Ordered by concept id. A concept with only decayed
    /// (`living = 0`) human links is dark; artifact links do not lift darkness.
    pub fn dark_concepts(&self) -> Result<Vec<Concept>, CoverageError> {
        self.query_concepts(
            "SELECT c.id, c.component, c.label, c.created_at
             FROM concepts c
             WHERE NOT EXISTS (
                 SELECT 1 FROM concept_actors a
                 WHERE a.concept_id = c.id AND a.living = 1
             )
             ORDER BY c.id",
        )
    }

    fn ensure_concept_exists(&self, concept: &ConceptId) -> Result<(), CoverageError> {
        let conn = self.conn.lock().unwrap();
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM concepts WHERE id = ?1",
                params![concept.0],
                |_| Ok(true),
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                _ => Err(CoverageError::Storage("concept lookup failed".into())),
            })?;
        if exists {
            Ok(())
        } else {
            Err(CoverageError::Storage(format!(
                "unknown concept '{}'",
                concept.0
            )))
        }
    }
}

/// Parse an RFC-3339 timestamp from storage; a malformed value is an integrity
/// error, never a silent substitution.
fn parse_ts(s: &str) -> Result<Timestamp, CoverageError> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| Timestamp(dt.with_timezone(&chrono::Utc)))
        .map_err(|_| CoverageError::Storage("integrity error: malformed timestamp".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn concept(id: &str, component: &str) -> Concept {
        Concept {
            id: ConceptId::new(id),
            component: component.into(),
            label: format!("label for {id}"),
            created_at: Timestamp::now(),
        }
    }

    fn map() -> CoverageMap {
        CoverageMap::in_memory().unwrap()
    }

    // ----- contract tests (written before implementation) -----

    #[test]
    fn concept_round_trips() {
        let m = map();
        m.add_concept(&concept("parser.unicode", "parser")).unwrap();
        let all = m.all_concepts().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, ConceptId::new("parser.unicode"));
        assert_eq!(all[0].component, "parser");
    }

    #[test]
    fn linking_artifact_to_unknown_concept_errors() {
        let m = map();
        let err = m.link_artifact(&ConceptId::new("ghost"), "src/x.rs");
        assert!(matches!(err, Err(CoverageError::Storage(_))));
    }

    #[test]
    fn linking_actor_to_unknown_concept_errors() {
        let m = map();
        let err = m.link_actor(&ConceptId::new("ghost"), &"alice".to_string());
        assert!(matches!(err, Err(CoverageError::Storage(_))));
    }

    #[test]
    fn artifact_and_actor_links_round_trip() {
        let m = map();
        let c = ConceptId::new("parser.unicode");
        m.add_concept(&concept("parser.unicode", "parser")).unwrap();
        m.link_artifact(&c, "src/parser.rs").unwrap();
        m.link_artifact(&c, "tests/unicode.rs").unwrap();
        m.link_actor(&c, &"alice".to_string()).unwrap();

        assert_eq!(
            m.artifacts_for(&c).unwrap(),
            vec!["src/parser.rs".to_string(), "tests/unicode.rs".to_string()]
        );
        assert_eq!(m.living_actors_for(&c).unwrap(), vec!["alice".to_string()]);
    }

    #[test]
    fn links_are_idempotent() {
        let m = map();
        let c = ConceptId::new("c1");
        m.add_concept(&concept("c1", "comp")).unwrap();
        m.link_artifact(&c, "a").unwrap();
        m.link_artifact(&c, "a").unwrap();
        m.link_actor(&c, &"bob".to_string()).unwrap();
        m.link_actor(&c, &"bob".to_string()).unwrap();
        assert_eq!(m.artifacts_for(&c).unwrap().len(), 1);
        assert_eq!(m.living_actors_for(&c).unwrap().len(), 1);
    }

    /// CORE INTEGRATION TEST — CG-19 dark-concept detection.
    /// Persist concept↔artifact↔actor links, round-trip via in_memory(), and
    /// assert the dark-concept query returns *exactly* the concepts with no
    /// living human (ActorId) link.
    #[test]
    fn dark_query_returns_exactly_concepts_without_living_human_link() {
        let m = map();

        // lit: has a living human link.
        m.add_concept(&concept("lit", "parser")).unwrap();
        m.link_artifact(&ConceptId::new("lit"), "src/lit.rs").unwrap();
        m.link_actor(&ConceptId::new("lit"), &"alice".to_string())
            .unwrap();

        // dark_no_links: no links at all.
        m.add_concept(&concept("dark_no_links", "parser")).unwrap();

        // dark_artifact_only: has an artifact link but NO human link — still dark.
        m.add_concept(&concept("dark_artifact_only", "codec")).unwrap();
        m.link_artifact(&ConceptId::new("dark_artifact_only"), "src/codec.rs")
            .unwrap();

        // dark_decayed: had a human link that decayed — dark again.
        m.add_concept(&concept("dark_decayed", "net")).unwrap();
        m.link_actor(&ConceptId::new("dark_decayed"), &"carol".to_string())
            .unwrap();
        m.decay_actor_link(&ConceptId::new("dark_decayed"), &"carol".to_string())
            .unwrap();

        let dark: Vec<String> = m
            .dark_concepts()
            .unwrap()
            .into_iter()
            .map(|c| c.id.0)
            .collect();

        // Exactly the three concepts with no living human link, in id order.
        assert_eq!(
            dark,
            vec![
                "dark_artifact_only".to_string(),
                "dark_decayed".to_string(),
                "dark_no_links".to_string(),
            ]
        );
        // "lit" must NOT be dark.
        assert!(!dark.contains(&"lit".to_string()));
    }

    #[test]
    fn reviving_decayed_link_lifts_darkness() {
        let m = map();
        let c = ConceptId::new("c");
        m.add_concept(&concept("c", "comp")).unwrap();
        m.link_actor(&c, &"dave".to_string()).unwrap();
        m.decay_actor_link(&c, &"dave".to_string()).unwrap();
        assert_eq!(m.dark_concepts().unwrap().len(), 1);
        // Re-link revives.
        m.link_actor(&c, &"dave".to_string()).unwrap();
        assert!(m.dark_concepts().unwrap().is_empty());
        assert_eq!(m.living_actors_for(&c).unwrap(), vec!["dave".to_string()]);
    }

    #[test]
    fn re_adding_concept_preserves_created_at_but_refreshes_label() {
        let m = map();
        let mut c = concept("c", "comp");
        c.created_at = Timestamp(
            chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        m.add_concept(&c).unwrap();

        // Re-add with a different label and a later created_at.
        let mut c2 = c.clone();
        c2.label = "updated".into();
        c2.created_at = Timestamp::now();
        m.add_concept(&c2).unwrap();

        let stored = &m.all_concepts().unwrap()[0];
        assert_eq!(stored.label, "updated"); // label refreshed
        assert_eq!(stored.created_at, c.created_at); // created_at preserved
    }

    #[test]
    fn foreign_key_enforcement_rejects_orphan_link() {
        // FK pragma is on, so a direct insert of a link to a non-existent
        // concept must fail at the SQLite layer (not just via ensure_concept_exists).
        let m = map();
        let err = m.conn.lock().unwrap().execute(
            "INSERT INTO concept_actors (concept_id, actor_id, living, linked_at)
             VALUES ('ghost', 'alice', 1, '2020-01-01T00:00:00Z')",
            [],
        );
        assert!(err.is_err(), "orphan link should violate the foreign key");
    }

    #[test]
    fn malformed_timestamp_is_integrity_error() {
        let m = map();
        m.add_concept(&concept("c", "comp")).unwrap();
        // Corrupt the stored timestamp directly.
        m.conn
            .lock()
            .unwrap()
            .execute("UPDATE concepts SET created_at = 'not-a-date'", [])
            .unwrap();
        let err = m.all_concepts();
        assert!(
            matches!(&err, Err(CoverageError::Storage(s)) if s.contains("integrity error")),
            "expected integrity error, got {err:?}"
        );
    }

    #[test]
    fn path_with_parent_traversal_is_rejected() {
        let result = CoverageMap::open("../etc/coverage.db");
        assert!(result.is_err());
    }
}
