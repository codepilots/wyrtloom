//! Hunt harness (Wyrtloom plugin-layer unit W4).
//!
//! Implements spec §2.2 row W4: sandboxed execution of human-authored breaking
//! tests against agent output, with deterministic coverage crediting and a
//! stake-escalation hook.
//!
//! Constraint coverage (SoftDevSpec.md §2.3 "The Hunt"):
//!   * CG-5 — the harness executes human-authored tests against agent output in
//!     the standard sandbox (`wyrtloom_core::sandbox::SandboxRuntime`). See
//!     [`HuntHarness::run`].
//!   * CG-6 — coverage credit is a deterministic function of the concepts a
//!     hunt-test exercises (its instrumented trace ∩ the coverage map),
//!     *regardless of whether the test passes or breaks the target*. There is
//!     no LLM grading. See [`credit_coverage`] and [`HuntHarness::run`].
//!   * CG-7 — a breaking test (i) opens a defect, (ii) credits coverage, and
//!     (iii) is flagged to crystallise into the regression suite on fix. See
//!     [`HuntOutcome`] and [`DefectRecord`].
//!   * CG-8 — on a surviving hunt the harness offers escalated-stakes variants
//!     ("break it again") pitched by the calibration ledger. See
//!     [`HuntHarness::escalate`].
//!   * CG-9 — NO points, scores, leaderboards, or rewards are attached to hunt
//!     statistics. This crate exposes none and the calibration score is used
//!     only to *pitch* difficulty, never as a reward (developmental, not
//!     evaluative — §1.6 / CG-9).
//!   * CG-4 — all crediting and pass/break decisions are deterministic; LLM
//!     output grades nothing here.

use std::collections::BTreeSet;
use thiserror::Error;
use wyrtloom_core::sandbox::{ResourceLimits, SafeModule, SandboxError, SandboxRuntime};
use wyrtloom_core::types::{Bytes, TaskId};

/// Identifier of a coverage-map concept.
///
/// Minimal local newtype — W4 deliberately does NOT depend on a sibling
/// coverage-map crate. Ordering is total so concept sets are deterministic
/// (`BTreeSet`), which CG-6 requires.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct ConceptId(pub String);

impl ConceptId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl From<&str> for ConceptId {
    fn from(s: &str) -> Self {
        ConceptId(s.to_string())
    }
}

/// A human-authored breaking test.
///
/// The `module` is a SAFE WASM module (the assertion harness) executed against
/// the agent's output in the standard sandbox (CG-5). `exercises` is the
/// instrumented trace: the coverage-map concepts this test touches. Crediting
/// derives from this set deterministically (CG-6), so it is declared as part of
/// the test rather than inferred by any model.
#[derive(Debug, Clone)]
pub struct HuntTest {
    /// Stable identity of this hunt-test (for defect/crystallisation linkage).
    pub id: String,
    /// The human who authored the hunt (for calibration-ledger linkage; never a
    /// leaderboard — CG-9).
    pub author: String,
    /// Task whose agent output is under hunt.
    pub task: TaskId,
    /// SAFE WASM assertion module. Must export `memory` and
    /// `run(i32,i32)->i64` per the sandbox contract.
    pub module_wasm: Bytes,
    /// Instrumented trace: coverage-map concepts this test exercises.
    pub exercises: BTreeSet<ConceptId>,
}

impl HuntTest {
    pub fn new(
        id: impl Into<String>,
        author: impl Into<String>,
        task: TaskId,
        module_wasm: Bytes,
        exercises: impl IntoIterator<Item = ConceptId>,
    ) -> Self {
        Self {
            id: id.into(),
            author: author.into(),
            task,
            module_wasm,
            exercises: exercises.into_iter().collect(),
        }
    }
}

/// The coverage map: the set of concepts the system tracks living human theories
/// for. Crediting intersects a hunt's exercised concepts with this set (CG-6).
#[derive(Debug, Clone, Default)]
pub struct CoverageMap {
    concepts: BTreeSet<ConceptId>,
}

impl CoverageMap {
    pub fn new(concepts: impl IntoIterator<Item = ConceptId>) -> Self {
        Self { concepts: concepts.into_iter().collect() }
    }

    pub fn contains(&self, c: &ConceptId) -> bool {
        self.concepts.contains(c)
    }

    pub fn len(&self) -> usize {
        self.concepts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.concepts.is_empty()
    }
}

/// Deterministic coverage crediting (CG-4, CG-6).
///
/// Credit = the instrumented trace ∩ the coverage map. This is a pure function
/// of its inputs: the same hunt-test against the same coverage map always
/// credits the same concepts, regardless of pass/break and with no model in the
/// loop. Output ordering is stable (`BTreeSet`).
pub fn credit_coverage(exercised: &BTreeSet<ConceptId>, map: &CoverageMap) -> BTreeSet<ConceptId> {
    exercised
        .iter()
        .filter(|c| map.contains(c))
        .cloned()
        .collect()
}

/// Whether the agent's work survived the hunt or was broken by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The agent output withstood the test (test asserted true / no trap).
    Survived,
    /// The test broke the target (assertion failed / trap).
    Broke,
}

/// A defect record opened when a hunt-test breaks the target (CG-7 i).
///
/// Carries the crystallisation flag (CG-7 iii): the breaking test is flagged to
/// crystallise into the regression suite once the defect is fixed. Blame stays
/// with the system — a defect is a system signal, not a marker against the
/// author (§1.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefectRecord {
    /// Hunt-test that opened this defect.
    pub hunt_test_id: String,
    /// Task under hunt.
    pub task: TaskId,
    /// Human author of the breaking hunt (linkage only — never a score, CG-9).
    pub author: String,
    /// Concepts credited at the moment the defect opened (CG-7 ii).
    pub credited: BTreeSet<ConceptId>,
    /// Human-readable account of how the target broke.
    pub detail: String,
    /// CG-7 iii — flag to crystallise this test into the regression suite on
    /// fix. Starts `true`; cleared once crystallised.
    pub crystallise_on_fix: bool,
}

/// Outcome of running a single hunt-test.
///
/// Coverage is ALWAYS credited (CG-6 — regardless of pass/break). A defect is
/// present only when the target broke (CG-7).
#[derive(Debug, Clone)]
pub struct HuntOutcome {
    pub verdict: Verdict,
    /// Coverage credited deterministically (CG-6).
    pub credited: BTreeSet<ConceptId>,
    /// Present iff `verdict == Broke` (CG-7).
    pub defect: Option<DefectRecord>,
}

/// Calibration ledger handle for pitching escalated stakes (CG-8).
///
/// Developmental, never evaluative (§1.6 / CG-9): the score pitches difficulty,
/// it is never a reward, target, or leaderboard entry. Private to the
/// individual.
pub trait CalibrationLedger {
    /// A per-(author, concept-area) confidence-vs-accuracy figure in `[0.0, 1.0]`.
    /// Higher = better-calibrated. Used only to pitch the next stake.
    fn calibration(&self, author: &str, concept: &ConceptId) -> f64;
}

/// A pitched "break it again" variant offered after a surviving hunt (CG-8).
#[derive(Debug, Clone, PartialEq)]
pub struct StakeEscalation {
    /// Depth of escalation, starting at 1 for the first "break it again".
    pub ladder_depth: u32,
    /// Human-facing pitch.
    pub pitch: String,
}

/// Errors surfaced by the harness.
#[derive(Error, Debug)]
pub enum HuntError {
    /// The hunt-test harness itself failed — the test could not be compiled,
    /// timed out, ran out of memory, or attempted host access. This is distinct
    /// from the agent's work breaking (a sandbox trap), and is NOT recorded as a
    /// defect, because such failures are environment-dependent and would
    /// otherwise violate CG-4 determinism.
    #[error("hunt-test could not be executed in the sandbox: {0}")]
    Harness(SandboxError),
}

/// The hunt harness (CG-5..9).
pub struct HuntHarness<'a> {
    sandbox: &'a dyn SandboxRuntime,
    map: CoverageMap,
    limits: ResourceLimits,
}

impl<'a> HuntHarness<'a> {
    pub fn new(sandbox: &'a dyn SandboxRuntime, map: CoverageMap) -> Self {
        Self { sandbox, map, limits: ResourceLimits::default() }
    }

    pub fn with_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Run a hunt-test against the agent's output (`agent_output`) in the
    /// standard sandbox (CG-5).
    ///
    /// The SAFE assertion module receives the agent output as its input. By the
    /// sandbox contract it returns a byte buffer; the harness interprets a
    /// non-empty buffer whose first byte is non-zero as "assertion held"
    /// (Survived) and anything else as "broke". A sandbox trap (e.g. the test
    /// hit `unreachable` on a failed assertion) is also a break. Any other
    /// sandbox error (compile failure, timeout, OOM, host-access attempt) is a
    /// failure of the *test harness* and surfaces as [`HuntError::Harness`] —
    /// never a defect against the target.
    ///
    /// Coverage is credited deterministically from the test's exercised concept
    /// set ∩ the coverage map (CG-6) **before** the verdict is consulted, so
    /// crediting is independent of pass/break. On a break a [`DefectRecord`] is
    /// opened, coverage credited, and the test flagged to crystallise on fix
    /// (CG-7).
    pub fn run(&self, test: &HuntTest, agent_output: Bytes) -> Result<HuntOutcome, HuntError> {
        // CG-6 / CG-4: deterministic crediting, computed independently of the
        // verdict and with no model in the loop.
        let credited = credit_coverage(&test.exercises, &self.map);

        // CG-5: execute the human-authored test in the standard sandbox.
        let module = SafeModule::new(test.module_wasm.clone());
        let verdict = match self.sandbox.execute(module, agent_output, self.limits.clone()) {
            Ok(out) => {
                if out.first().copied().unwrap_or(0) != 0 {
                    Verdict::Survived
                } else {
                    Verdict::Broke
                }
            }
            // A trap means the assertion harness aborted the target (e.g. a
            // failed `assert` lowered to `unreachable`) — that is a genuine
            // break of the agent's work.
            Err(SandboxError::Trap(_)) => Verdict::Broke,
            // Every other sandbox error is a failure of the hunt-test *harness*,
            // not the agent's work: a Compile error is a malformed test; a
            // Timeout / MemoryExceeded / HostAccessAttempted is the test itself
            // misbehaving or exceeding its budget. Crucially these are
            // environment-dependent (wall-clock, host load) and so must NOT be
            // recorded as a deterministic defect against the target — doing so
            // would violate CG-4 (determinism) and mis-blame the agent.
            Err(other) => return Err(HuntError::Harness(other)),
        };

        let defect = match verdict {
            Verdict::Broke => Some(DefectRecord {
                hunt_test_id: test.id.clone(),
                task: test.task,
                author: test.author.clone(),
                credited: credited.clone(),
                detail: format!("hunt-test '{}' broke the target", test.id),
                crystallise_on_fix: true, // CG-7 iii
            }),
            Verdict::Survived => None,
        };

        Ok(HuntOutcome { verdict, credited, defect })
    }

    /// Offer an escalated-stakes "break it again" variant after a surviving
    /// hunt (CG-8), pitched by the calibration ledger.
    ///
    /// Returns `None` when the verdict was a break (nothing survived to
    /// re-challenge), or when stake escalation is disabled / the ladder depth
    /// cap is reached. The calibration score only *pitches* difficulty — it is
    /// never a reward or leaderboard figure (CG-9).
    pub fn escalate(
        &self,
        test: &HuntTest,
        outcome: &HuntOutcome,
        ledger: &dyn CalibrationLedger,
        current_depth: u32,
        max_ladder_depth: u32,
    ) -> Option<StakeEscalation> {
        if outcome.verdict != Verdict::Survived {
            return None;
        }
        if current_depth >= max_ladder_depth {
            return None;
        }

        // Pitch difficulty from the *minimum* calibration across the concepts
        // this hunt touched: target the area where the author's confidence is
        // least supported by accuracy. Deterministic (CG-4).
        //
        // With no exercised concepts there is no calibration evidence at all, so
        // we must NOT default to the high-confidence pitch (an empty `min` fold
        // would return the identity 1.0 — the opposite of "no evidence"). Treat
        // the unknown case as low confidence and offer the gentler pitch.
        let calib = test
            .exercises
            .iter()
            .map(|c| ledger.calibration(&test.author, c))
            .reduce(f64::min);

        let next_depth = current_depth + 1;
        let pitch = if calib.is_some_and(|c| c >= 0.75) {
            format!(
                "This version survives your last test. You read this area well — \
                 try a sharper angle (depth {next_depth})."
            )
        } else {
            format!(
                "This version survives your last test. Break it again — a \
                 smaller, more concrete case may expose it (depth {next_depth})."
            )
        };

        Some(StakeEscalation { ladder_depth: next_depth, pitch })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn map() -> CoverageMap {
        CoverageMap::new([
            ConceptId::from("parser.unicode"),
            ConceptId::from("parser.bounds"),
        ])
    }

    #[test]
    fn crediting_is_deterministic_intersection() {
        let m = map();
        let exercised: BTreeSet<ConceptId> = [
            ConceptId::from("parser.unicode"),
            ConceptId::from("not.in.map"),
        ]
        .into_iter()
        .collect();

        let a = credit_coverage(&exercised, &m);
        let b = credit_coverage(&exercised, &m);
        assert_eq!(a, b, "crediting must be deterministic (CG-6)");
        assert_eq!(a, [ConceptId::from("parser.unicode")].into_iter().collect());
    }

    #[test]
    fn defect_record_flags_crystallisation() {
        // CG-7 iii — a fresh defect is flagged to crystallise on fix.
        let d = DefectRecord {
            hunt_test_id: "h1".into(),
            task: Uuid::new_v4(),
            author: "ana".into(),
            credited: BTreeSet::new(),
            detail: "broke".into(),
            crystallise_on_fix: true,
        };
        assert!(d.crystallise_on_fix);
    }

    struct FixedLedger(f64);
    impl CalibrationLedger for FixedLedger {
        fn calibration(&self, _author: &str, _concept: &ConceptId) -> f64 {
            self.0
        }
    }

    fn test_with(concepts: &[&str]) -> HuntTest {
        HuntTest::new(
            "h1",
            "ana",
            Uuid::new_v4(),
            vec![],
            concepts.iter().map(|c| ConceptId::from(*c)),
        )
    }

    #[test]
    fn no_escalation_when_target_broke() {
        // Nothing survived to re-challenge (CG-8 precondition).
        let test = test_with(&["parser.unicode"]);
        let outcome = HuntOutcome {
            verdict: Verdict::Broke,
            credited: BTreeSet::new(),
            defect: None,
        };
        // construct a harness without a sandbox call path
        let sb = NoopSandbox;
        let h = HuntHarness::new(&sb, map());
        let esc = h.escalate(&test, &outcome, &FixedLedger(0.9), 0, 3);
        assert!(esc.is_none());
    }

    #[test]
    fn escalation_respects_ladder_cap() {
        let test = test_with(&["parser.unicode"]);
        let outcome = HuntOutcome {
            verdict: Verdict::Survived,
            credited: BTreeSet::new(),
            defect: None,
        };
        let sb = NoopSandbox;
        let h = HuntHarness::new(&sb, map());
        // at cap → none
        assert!(h.escalate(&test, &outcome, &FixedLedger(0.9), 3, 3).is_none());
        // below cap → some, depth advances
        let esc = h.escalate(&test, &outcome, &FixedLedger(0.9), 1, 3).unwrap();
        assert_eq!(esc.ladder_depth, 2);
    }

    #[test]
    fn empty_exercises_does_not_pitch_high_confidence() {
        // No exercised concepts => no calibration evidence => the gentle
        // "break it again" pitch, NOT the high-confidence one (regression for
        // the empty-fold defaulting to 1.0).
        let test = test_with(&[]);
        let outcome = HuntOutcome {
            verdict: Verdict::Survived,
            credited: BTreeSet::new(),
            defect: None,
        };
        let sb = NoopSandbox;
        let h = HuntHarness::new(&sb, map());
        // A high-calibration ledger must be ignored when there are no concepts.
        let esc = h.escalate(&test, &outcome, &FixedLedger(0.9), 0, 3).unwrap();
        let low_ref = h
            .escalate(&test_with(&["x"]), &outcome, &FixedLedger(0.1), 0, 3)
            .unwrap();
        assert_eq!(esc.pitch, low_ref.pitch, "empty exercises => low-confidence pitch");
    }

    /// Sandbox stub that always returns a configured error.
    struct ErrSandbox(fn() -> SandboxError);
    impl SandboxRuntime for ErrSandbox {
        fn execute(
            &self,
            _module: SafeModule,
            _input: Bytes,
            _limits: ResourceLimits,
        ) -> Result<Bytes, SandboxError> {
            Err((self.0)())
        }
    }

    #[test]
    fn trap_breaks_but_timeout_is_a_harness_error() {
        let m = map();

        // A trap is a genuine break => defect opened.
        let sb_trap = ErrSandbox(|| SandboxError::Trap("unreachable".into()));
        let h = HuntHarness::new(&sb_trap, m.clone());
        let out = h.run(&test_with(&["parser.unicode"]), vec![]).unwrap();
        assert_eq!(out.verdict, Verdict::Broke);
        assert!(out.defect.is_some());

        // A timeout is environment-dependent => harness error, NOT a defect.
        let sb_to = ErrSandbox(|| SandboxError::Timeout);
        let h = HuntHarness::new(&sb_to, m.clone());
        let err = h.run(&test_with(&["parser.unicode"]), vec![]).unwrap_err();
        assert!(matches!(err, HuntError::Harness(SandboxError::Timeout)));

        // A compile error => malformed test => harness error.
        let sb_c = ErrSandbox(|| SandboxError::Compile("bad wasm".into()));
        let h = HuntHarness::new(&sb_c, m);
        let err = h.run(&test_with(&["parser.unicode"]), vec![]).unwrap_err();
        assert!(matches!(err, HuntError::Harness(SandboxError::Compile(_))));
    }

    #[test]
    fn escalation_pitch_varies_with_calibration() {
        let test = test_with(&["parser.unicode"]);
        let outcome = HuntOutcome {
            verdict: Verdict::Survived,
            credited: BTreeSet::new(),
            defect: None,
        };
        let sb = NoopSandbox;
        let h = HuntHarness::new(&sb, map());
        let high = h.escalate(&test, &outcome, &FixedLedger(0.9), 0, 3).unwrap();
        let low = h.escalate(&test, &outcome, &FixedLedger(0.2), 0, 3).unwrap();
        assert_ne!(high.pitch, low.pitch, "pitch is calibration-sensitive (CG-8)");
    }

    /// Minimal sandbox stub for escalation tests that never execute a module.
    struct NoopSandbox;
    impl SandboxRuntime for NoopSandbox {
        fn execute(
            &self,
            _module: SafeModule,
            _input: Bytes,
            _limits: ResourceLimits,
        ) -> Result<Bytes, SandboxError> {
            unreachable!("escalation tests must not execute a module");
        }
    }
}
