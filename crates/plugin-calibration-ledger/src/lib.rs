//! W7 — Calibration ledger (SoftDevSpec §2.2 row W7).
//!
//! A SQLite-backed, per-person confidence-vs-outcome record with a
//! deterministic BKT-style update rule. The ledger is **developmental, never
//! evaluative** (spec §1.6).
//!
//! Conformance:
//!   - CG-4  — the BKT update is pure deterministic arithmetic; no LLM grades.
//!   - CG-21 — ledgers are private-by-default to the individual; the only
//!             cross-person view is per-concept aggregate redundancy.
//!   - CG-22 — the storage layer enforces: no appraisal export, no per-person
//!             ranking queries, retention limits, user export and delete.
//!   - CG-23 — purpose is declared Developmental in the policy object;
//!             attaching performance targets is unsupported by API design.
//!
//! Governance is structural: there is deliberately **no method on this type**
//! that ranks or orders people. Per-actor reads (`mastery`, `export_actor`,
//! `delete_actor`) are private-by-default in the CG-21 sense — they require the
//! caller to name a specific actor (the intended use is the individual viewing
//! their own data) and never return a cross-person ordering. The only
//! cross-person method, `team_concept_redundancy`, returns counts grouped by
//! concept with actor ids dropped inside the computation, so a league table
//! cannot be read out of it. Binding a caller's identity to the actor they may
//! query is an access-control concern for the embedding deployment (D15.4);
//! this crate provides no ranking primitive for such a deployment to misuse.
//! See `DESIGN.md`.

use chrono::SecondsFormat;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use wyrtloom_core::storage::validate_db_path;
use wyrtloom_core::types::{ActorId, Timestamp};

/// Format a UTC timestamp as a fixed-width RFC3339 string
/// (`...T..:..:..xxx...Z`, always 9 fractional digits, `Z` suffix). Because
/// `Timestamp` wraps `DateTime<Utc>`, every stored value has the same width and
/// the same offset, so lexicographic string ordering matches chronological
/// ordering — which the `prune_older_than` `at < cutoff` comparison relies on.
fn rfc3339_fixed(ts: &Timestamp) -> String {
    ts.0.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

/// Newtype for a concept identifier. Defined here (not reused from core) per
/// the W7 brief.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConceptId(pub String);

impl ConceptId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl std::fmt::Display for ConceptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Errors surfaced by the ledger. SQLite errors are mapped to opaque
/// `Storage` strings so internal schema details never leak.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("storage error: {0}")]
    Storage(String),
}

/// A single graded probe event for one (actor, concept).
///
/// `predicted_correct` is the person's *stated confidence* (did they expect to
/// be right); `was_correct` is the deterministically graded outcome. The pair
/// is what "calibration" measures. Both are stored, but only `was_correct`
/// drives the BKT mastery update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeEvent {
    pub actor: ActorId,
    pub concept: ConceptId,
    pub predicted_correct: bool,
    pub was_correct: bool,
    pub at: Timestamp,
}

/// Aggregate, per-concept team view (CG-21). Carries **no** actor identity —
/// only how many distinct people are at-or-above the mastery threshold, which
/// is the bus-factor / redundancy signal the spec permits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConceptRedundancy {
    pub concept: ConceptId,
    /// Number of distinct actors whose mastery is >= the threshold.
    pub redundant_actors: u64,
}

/// Declared ledger purpose (CG-23). The enum has exactly one variant: the
/// ledger is developmental. There is intentionally no `Evaluative` /
/// `Appraisal` variant and no target field anywhere in the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Purpose {
    Developmental,
}

/// Policy object (CG-23). Read-only purpose declaration. Attaching a
/// performance target is *unsupported by API design* — there is no field or
/// method to do so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerPolicy {
    pub purpose: Purpose,
}

impl Default for LedgerPolicy {
    fn default() -> Self {
        Self { purpose: Purpose::Developmental }
    }
}

/// Fixed BKT parameters (CG-4). Constants, not learned weights — a Phase-4
/// tuner may replace these, but within a run they are fixed so replay is
/// deterministic.
#[derive(Debug, Clone, Copy)]
pub struct BktParams {
    /// Prior P(known) before any evidence.
    pub p_l0: f64,
    /// P(transit) — learning per opportunity.
    pub p_t: f64,
    /// P(slip) — known but answers wrong.
    pub p_s: f64,
    /// P(guess) — unknown but answers right.
    pub p_g: f64,
}

impl Default for BktParams {
    fn default() -> Self {
        Self { p_l0: 0.30, p_t: 0.10, p_s: 0.10, p_g: 0.20 }
    }
}

impl BktParams {
    /// Apply one observation to a prior mastery `p`, returning the updated
    /// mastery. Pure deterministic arithmetic — same inputs always give the
    /// same output (CG-4).
    ///
    /// ```text
    /// posterior =  if correct: p·(1−S) / ( p·(1−S) + (1−p)·G )
    ///              else:       p·S     / ( p·S     + (1−p)·(1−G) )
    /// p_next    =  posterior + (1 − posterior)·T
    /// ```
    pub fn update(&self, p: f64, correct: bool) -> f64 {
        let (num, den) = if correct {
            let n = p * (1.0 - self.p_s);
            (n, n + (1.0 - p) * self.p_g)
        } else {
            let n = p * self.p_s;
            (n, n + (1.0 - p) * (1.0 - self.p_g))
        };
        // Guard the degenerate den==0 case (only reachable with extreme params).
        let posterior = if den == 0.0 { p } else { num / den };
        posterior + (1.0 - posterior) * self.p_t
    }
}

/// Mastery threshold at/above which an actor counts toward concept redundancy.
const REDUNDANCY_THRESHOLD: f64 = 0.95;

/// The calibration ledger.
pub struct CalibrationLedger {
    conn: Mutex<Connection>,
    params: BktParams,
    policy: LedgerPolicy,
}

impl CalibrationLedger {
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            validate_db_path(path)
                .map_err(|e| rusqlite::Error::InvalidPath(std::path::PathBuf::from(e)))?;
            Connection::open(path)?
        };
        let ledger = Self {
            conn: Mutex::new(conn),
            params: BktParams::default(),
            policy: LedgerPolicy::default(),
        };
        ledger.init_schema()?;
        Ok(ledger)
    }

    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }

    fn init_schema(&self) -> Result<(), rusqlite::Error> {
        self.conn.lock().unwrap().execute_batch(
            "CREATE TABLE IF NOT EXISTS probe_events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                actor     TEXT NOT NULL,
                concept   TEXT NOT NULL,
                predicted INTEGER NOT NULL,
                correct   INTEGER NOT NULL,
                at        TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_probe_actor_concept
                ON probe_events (actor, concept, id);",
        )
    }

    /// The declared policy (CG-23). Purpose is always Developmental.
    pub fn policy(&self) -> LedgerPolicy {
        self.policy
    }

    /// The fixed BKT parameters in force.
    pub fn params(&self) -> BktParams {
        self.params
    }

    /// Record one graded probe event (CG-15: outcomes are practice events).
    pub fn record(&self, event: &ProbeEvent) -> Result<(), LedgerError> {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO probe_events (actor, concept, predicted, correct, at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    event.actor,
                    event.concept.0,
                    event.predicted_correct as i64,
                    event.was_correct as i64,
                    rfc3339_fixed(&event.at),
                ],
            )
            .map_err(|_| LedgerError::Storage("insert failed".into()))?;
        Ok(())
    }

    /// Read the ordered outcome sequence for one (actor, concept).
    /// Private-by-default (CG-21): the caller must name the actor.
    fn outcomes(&self, actor: &ActorId, concept: &ConceptId) -> Result<Vec<bool>, LedgerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT correct FROM probe_events
                 WHERE actor = ?1 AND concept = ?2 ORDER BY id",
            )
            .map_err(|_| LedgerError::Storage("prepare failed".into()))?;
        let rows = stmt
            .query_map(params![actor, concept.0], |row| row.get::<_, i64>(0))
            .map_err(|_| LedgerError::Storage("query failed".into()))?;

        let mut out = Vec::new();
        for r in rows {
            let v = r.map_err(|_| LedgerError::Storage("row read failed".into()))?;
            // Integrity: stored boolean must be 0 or 1.
            match v {
                0 => out.push(false),
                1 => out.push(true),
                other => {
                    return Err(LedgerError::Storage(format!(
                        "integrity error: malformed boolean '{}'",
                        other
                    )))
                }
            }
        }
        Ok(out)
    }

    /// Deterministic mastery estimate `p_known ∈ [0,1]` for one (actor,
    /// concept), computed by replaying the BKT update over the stored event
    /// sequence (CG-4). Private-by-default (CG-21).
    pub fn mastery(&self, actor: &ActorId, concept: &ConceptId) -> Result<f64, LedgerError> {
        let outcomes = self.outcomes(actor, concept)?;
        let mut p = self.params.p_l0;
        for correct in outcomes {
            p = self.params.update(p, correct);
        }
        Ok(p)
    }

    /// **The only cross-person query (CG-21).** Returns, per concept, the
    /// number of distinct actors at/above the mastery threshold — the
    /// bus-factor / redundancy signal. Actor identities are dropped inside the
    /// computation; no per-person row is ever returned, and there is no ordering
    /// of people. This is structurally aggregate-only.
    pub fn team_concept_redundancy(&self) -> Result<Vec<ConceptRedundancy>, LedgerError> {
        // Enumerate distinct (actor, concept) pairs, compute each mastery, then
        // collapse to per-concept counts. We never expose the per-pair masteries.
        let pairs = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn
                .prepare("SELECT DISTINCT actor, concept FROM probe_events ORDER BY concept, actor")
                .map_err(|_| LedgerError::Storage("prepare failed".into()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|_| LedgerError::Storage("query failed".into()))?;
            let mut v = Vec::new();
            for r in rows {
                v.push(r.map_err(|_| LedgerError::Storage("row read failed".into()))?);
            }
            v
        };

        // Per concept, count actors over threshold. BTreeMap keeps output
        // deterministic and ordered by concept.
        let mut counts: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
        for (actor, concept_str) in pairs {
            let concept = ConceptId(concept_str.clone());
            let m = self.mastery(&actor, &concept)?;
            // `or_insert(0)` ensures the concept appears even with zero
            // redundancy; only over-threshold actors increment the count.
            let entry = counts.entry(concept_str).or_insert(0);
            if m >= REDUNDANCY_THRESHOLD {
                *entry += 1;
            }
        }

        Ok(counts
            .into_iter()
            .map(|(concept, redundant_actors)| ConceptRedundancy {
                concept: ConceptId(concept),
                redundant_actors,
            })
            .collect())
    }

    /// Export every stored event for one actor (CG-22: user export). Returns
    /// the actor's own data only.
    pub fn export_actor(&self, actor: &ActorId) -> Result<Vec<ProbeEvent>, LedgerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT actor, concept, predicted, correct, at FROM probe_events
                 WHERE actor = ?1 ORDER BY id",
            )
            .map_err(|_| LedgerError::Storage("prepare failed".into()))?;
        let rows = stmt
            .query_map(params![actor], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|_| LedgerError::Storage("query failed".into()))?;

        let mut out = Vec::new();
        for r in rows {
            let (actor, concept, predicted, correct, at_str) =
                r.map_err(|_| LedgerError::Storage("row read failed".into()))?;
            let at = chrono::DateTime::parse_from_rfc3339(&at_str)
                .map(|dt| Timestamp(dt.with_timezone(&chrono::Utc)))
                .map_err(|_| LedgerError::Storage("integrity error: malformed timestamp".into()))?;
            out.push(ProbeEvent {
                actor,
                concept: ConceptId(concept),
                predicted_correct: to_bool(predicted)?,
                was_correct: to_bool(correct)?,
                at,
            });
        }
        Ok(out)
    }

    /// Delete every stored event for one actor (CG-22: user delete / erase).
    /// Returns the number of rows removed.
    pub fn delete_actor(&self, actor: &ActorId) -> Result<u64, LedgerError> {
        let n = self
            .conn
            .lock()
            .unwrap()
            .execute("DELETE FROM probe_events WHERE actor = ?1", params![actor])
            .map_err(|_| LedgerError::Storage("delete failed".into()))?;
        Ok(n as u64)
    }

    /// Retention limit (CG-22): prune events older than `days` days from `now`.
    /// Returns the number of rows removed.
    ///
    /// `days` must be non-negative; a negative window would put the cutoff in
    /// the future and silently delete the entire ledger, so it is rejected. An
    /// out-of-range `days` (overflowing chrono's date arithmetic) is likewise a
    /// `Storage` error rather than a panic — `prune` always honours its
    /// `Result` contract.
    pub fn prune_older_than(&self, days: i64, now: &Timestamp) -> Result<u64, LedgerError> {
        if days < 0 {
            return Err(LedgerError::Storage(
                "retention window must be non-negative".into(),
            ));
        }
        let cutoff = chrono::Duration::try_days(days)
            .and_then(|d| now.0.checked_sub_signed(d))
            .ok_or_else(|| LedgerError::Storage("retention window out of range".into()))?;
        let cutoff = Timestamp(cutoff);
        let n = self
            .conn
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM probe_events WHERE at < ?1",
                params![rfc3339_fixed(&cutoff)],
            )
            .map_err(|_| LedgerError::Storage("prune failed".into()))?;
        Ok(n as u64)
    }
}

fn to_bool(v: i64) -> Result<bool, LedgerError> {
    match v {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(LedgerError::Storage(format!(
            "integrity error: malformed boolean '{}'",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger() -> CalibrationLedger {
        CalibrationLedger::in_memory().unwrap()
    }

    fn event(actor: &str, concept: &str, predicted: bool, correct: bool) -> ProbeEvent {
        ProbeEvent {
            actor: actor.to_string(),
            concept: ConceptId::new(concept),
            predicted_correct: predicted,
            was_correct: correct,
            at: Timestamp::now(),
        }
    }

    // ---- BKT determinism (CG-4) ----

    #[test]
    fn bkt_update_is_pure_and_deterministic() {
        let p = BktParams::default();
        // Same inputs -> identical outputs, repeatedly.
        let a = p.update(0.3, true);
        let b = p.update(0.3, true);
        assert_eq!(a, b);
        let c = p.update(0.3, false);
        assert_eq!(c, p.update(0.3, false));
        // A correct answer raises mastery; a wrong one lowers it.
        assert!(a > 0.3);
        assert!(c < a);
    }

    #[test]
    fn mastery_replay_is_deterministic() {
        let l = ledger();
        for _ in 0..5 {
            l.record(&event("alice", "borrow-checker", true, true)).unwrap();
        }
        let m1 = l.mastery(&"alice".to_string(), &ConceptId::new("borrow-checker")).unwrap();

        // Replay the identical sequence into a fresh ledger -> same mastery.
        let l2 = ledger();
        for _ in 0..5 {
            l2.record(&event("alice", "borrow-checker", true, true)).unwrap();
        }
        let m2 = l2.mastery(&"alice".to_string(), &ConceptId::new("borrow-checker")).unwrap();
        assert_eq!(m1, m2);
    }

    #[test]
    fn no_events_gives_prior() {
        let l = ledger();
        let m = l.mastery(&"nobody".to_string(), &ConceptId::new("x")).unwrap();
        assert_eq!(m, BktParams::default().p_l0);
    }

    #[test]
    fn consistent_correct_answers_raise_mastery_above_threshold() {
        let l = ledger();
        for _ in 0..20 {
            l.record(&event("bob", "ownership", true, true)).unwrap();
        }
        let m = l.mastery(&"bob".to_string(), &ConceptId::new("ownership")).unwrap();
        assert!(m >= REDUNDANCY_THRESHOLD, "mastery was {m}");
    }

    // ---- CG-21: team view is aggregate-only, no per-person ----

    #[test]
    fn team_redundancy_counts_distinct_masters_only() {
        let l = ledger();
        for _ in 0..20 {
            l.record(&event("alice", "lifetimes", true, true)).unwrap();
            l.record(&event("bob", "lifetimes", true, true)).unwrap();
        }
        // carol never masters it
        l.record(&event("carol", "lifetimes", false, false)).unwrap();

        let red = l.team_concept_redundancy().unwrap();
        assert_eq!(red.len(), 1);
        assert_eq!(red[0].concept, ConceptId::new("lifetimes"));
        assert_eq!(red[0].redundant_actors, 2);

        // Structural: the redundancy struct carries no actor identity field.
        // (If a per-person field existed this would not compile.)
        let _ = ConceptRedundancy { concept: ConceptId::new("c"), redundant_actors: 0 };
    }

    #[test]
    fn team_view_returns_only_counts_no_actor_ids() {
        // This test documents CG-22's "no per-person ranking": the only
        // cross-person method returns ConceptRedundancy, whose public fields
        // are exactly {concept, redundant_actors}. Serialize and assert no
        // actor key leaks.
        let l = ledger();
        for _ in 0..20 {
            l.record(&event("alice", "traits", true, true)).unwrap();
        }
        let red = l.team_concept_redundancy().unwrap();
        let json = serde_json::to_string(&red).unwrap();
        // No actor *identity* leaks into the aggregate view.
        assert!(!json.contains("alice"));
        // The only fields are the concept and the redundancy count.
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        for row in &parsed {
            let keys: Vec<&str> = row.as_object().unwrap().keys().map(|k| k.as_str()).collect();
            assert_eq!(keys, vec!["concept", "redundant_actors"]);
        }
    }

    // ---- CG-23: developmental purpose, targets unsupported ----

    #[test]
    fn policy_purpose_is_developmental() {
        let l = ledger();
        assert_eq!(l.policy().purpose, Purpose::Developmental);
    }

    // ---- CG-22: export + delete + retention ----

    #[test]
    fn export_returns_only_the_named_actor() {
        let l = ledger();
        l.record(&event("alice", "c1", true, true)).unwrap();
        l.record(&event("alice", "c2", false, false)).unwrap();
        l.record(&event("bob", "c1", true, true)).unwrap();

        let exported = l.export_actor(&"alice".to_string()).unwrap();
        assert_eq!(exported.len(), 2);
        assert!(exported.iter().all(|e| e.actor == "alice"));
    }

    #[test]
    fn delete_removes_actor_data_and_returns_count() {
        let l = ledger();
        l.record(&event("alice", "c1", true, true)).unwrap();
        l.record(&event("alice", "c2", true, true)).unwrap();
        l.record(&event("bob", "c1", true, true)).unwrap();

        let removed = l.delete_actor(&"alice".to_string()).unwrap();
        assert_eq!(removed, 2);
        assert_eq!(l.export_actor(&"alice".to_string()).unwrap().len(), 0);
        // bob untouched
        assert_eq!(l.export_actor(&"bob".to_string()).unwrap().len(), 1);
    }

    #[test]
    fn prune_drops_old_events_only() {
        let l = ledger();
        let now = Timestamp::now();
        let old = Timestamp(now.0 - chrono::Duration::days(100));
        let recent = Timestamp(now.0 - chrono::Duration::days(1));

        let mut e_old = event("alice", "c1", true, true);
        e_old.at = old;
        let mut e_recent = event("alice", "c1", true, true);
        e_recent.at = recent;
        l.record(&e_old).unwrap();
        l.record(&e_recent).unwrap();

        let pruned = l.prune_older_than(30, &now).unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(l.export_actor(&"alice".to_string()).unwrap().len(), 1);
    }

    #[test]
    fn prune_rejects_negative_window_and_keeps_data() {
        let l = ledger();
        l.record(&event("alice", "c1", true, true)).unwrap();
        let now = Timestamp::now();
        let res = l.prune_older_than(-1, &now);
        assert!(matches!(res, Err(LedgerError::Storage(_))));
        // Data is untouched — a negative window must not wipe the ledger.
        assert_eq!(l.export_actor(&"alice".to_string()).unwrap().len(), 1);
    }

    #[test]
    fn prune_out_of_range_window_errors_not_panics() {
        let l = ledger();
        l.record(&event("alice", "c1", true, true)).unwrap();
        let now = Timestamp::now();
        let res = l.prune_older_than(i64::MAX, &now);
        assert!(matches!(res, Err(LedgerError::Storage(_))));
        assert_eq!(l.export_actor(&"alice".to_string()).unwrap().len(), 1);
    }

    // ---- storage robustness ----

    #[test]
    fn path_traversal_is_rejected() {
        assert!(CalibrationLedger::open("../etc/evil.db").is_err());
    }

    #[test]
    fn malformed_boolean_is_integrity_error() {
        let l = ledger();
        l.record(&event("alice", "c1", true, true)).unwrap();
        // Corrupt the stored boolean directly.
        l.conn
            .lock()
            .unwrap()
            .execute("UPDATE probe_events SET correct = 7", [])
            .unwrap();
        let res = l.mastery(&"alice".to_string(), &ConceptId::new("c1"));
        assert!(matches!(res, Err(LedgerError::Storage(_))));
    }

    // ---- CORE INTEGRATION TEST (required by W7 brief) ----
    //
    // Round-trips events keyed by a real ActorId, and asserts:
    //   * the BKT update is deterministic (replay -> identical mastery),
    //   * the API structurally offers only aggregate (not per-person ranking)
    //     team queries,
    //   * delete + export work.
    #[test]
    fn core_integration_round_trip() {
        let l = ledger();

        // Real ActorId values (core's ActorId is a String).
        let alice: ActorId = "actor:alice".to_string();
        let bob: ActorId = "actor:bob".to_string();
        let concept = ConceptId::new("rust::ownership");

        // Round-trip a sequence of graded events.
        for _ in 0..20 {
            l.record(&ProbeEvent {
                actor: alice.clone(),
                concept: concept.clone(),
                predicted_correct: true,
                was_correct: true,
                at: Timestamp::now(),
            })
            .unwrap();
            l.record(&ProbeEvent {
                actor: bob.clone(),
                concept: concept.clone(),
                predicted_correct: true,
                was_correct: true,
                at: Timestamp::now(),
            })
            .unwrap();
        }

        // 1. Determinism: recomputing mastery yields the same value.
        let m_first = l.mastery(&alice, &concept).unwrap();
        let m_again = l.mastery(&alice, &concept).unwrap();
        assert_eq!(m_first, m_again);

        // 2. Aggregate-only team view: per-concept redundancy count, no ranking.
        let redundancy = l.team_concept_redundancy().unwrap();
        assert_eq!(redundancy.len(), 1);
        assert_eq!(redundancy[0].redundant_actors, 2);
        // No serialized actor identity escapes the team view.
        let json = serde_json::to_string(&redundancy).unwrap();
        assert!(!json.contains("alice") && !json.contains("bob"));

        // 3. Export then delete round-trip.
        let exported = l.export_actor(&alice).unwrap();
        assert_eq!(exported.len(), 20);
        assert!(exported.iter().all(|e| e.actor == alice));
        let removed = l.delete_actor(&alice).unwrap();
        assert_eq!(removed, 20);
        assert_eq!(l.export_actor(&alice).unwrap().len(), 0);
        // bob's data survives.
        assert_eq!(l.export_actor(&bob).unwrap().len(), 20);

        // 4. Policy is developmental (CG-23).
        assert_eq!(l.policy().purpose, Purpose::Developmental);
    }
}
