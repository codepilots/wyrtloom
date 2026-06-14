//! W5 — Fallback Socratic probe ladder (`plugin-probe-ladder`).
//!
//! Implements spec §2.2 row W5 and requirements CG-18, CG-19, CG-20, under the
//! determinism rule CG-4.
//!
//! The probe ladder is the *quiet fallback* for coverage-map territory still
//! dark after hunt / build / solo credit. It presents short **prediction
//! probes**: the human predicts what a snippet will produce, and the probe is
//! graded **by execution** — predicted output is compared, deterministically,
//! against the actual execution output. An LLM judge NEVER grades anything
//! (CG-4; the addendum notes an "F-HULA follow-up showed judge instability").
//!
//! Behaviour (CG-18 / D8–D9):
//!   * Execution-graded prediction probes (`grade`, comparing `predicted` vs
//!     `actual`).
//!   * Guided worked-example **scaffolds** that teach when a prediction misses.
//!   * Scaffolded items **do not count toward mastery** — a scaffolded pass
//!     credits *teaching*, never mastery.
//!   * **Staircase** difficulty: rises one rung on a (non-scaffolded) pass,
//!     falls one rung on a miss.
//!   * **Fading** with calibration: as the reader's calibration score climbs,
//!     probing fades out entirely.
//!   * Passed probes **crystallise** into the regression suite.
//!
//! Triggering (CG-19): probes fire only for coverage-map areas still dark,
//! per the mastery-policy mode (`strict` / `sampled(K)` / `hybrid`).
//!
//! Defect signal (CG-20): a human prediction that is *wrong but reasonable*
//! while the system's behaviour is *anomalous vs the behavioural baseline* is
//! surfaced as a **design-defect signal** about the system — never recorded as
//! a human failing.
//!
//! Determinism (CG-4): grading is byte comparison of execution output; the
//! staircase and the fading rule are pure deterministic functions. No model
//! call appears in any pass/fail, crediting, or scheduling decision.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// A coverage-map concept identifier. Represented locally (a minimal newtype)
/// rather than depending on a sibling W-crate; the real coverage map lives
/// elsewhere in the Conversation layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConceptId(pub String);

impl ConceptId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// Mastery-policy mode governing which dark concepts get probed (CG-19).
///
/// Minimal local representation; the project-owner-governed mastery policy
/// object (W8) is the authoritative source — this crate only needs the mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MasteryMode {
    /// Probe every dark concept.
    Strict,
    /// Probe a deterministic sample of at most `K` dark concepts.
    Sampled(usize),
    /// Probe every *high-criticality* dark concept, sample the remainder.
    Hybrid { sample_k: usize },
}

/// The ladder's difficulty rungs. Difficulty staircases up on a pass and down
/// on a miss (CG-18). Bounded so the staircase saturates rather than wrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Rung {
    Intro = 0,
    Easy = 1,
    Medium = 2,
    Hard = 3,
    Expert = 4,
}

impl Rung {
    const LADDER: [Rung; 5] = [
        Rung::Intro,
        Rung::Easy,
        Rung::Medium,
        Rung::Hard,
        Rung::Expert,
    ];

    /// One rung harder, saturating at `Expert`.
    pub fn up(self) -> Rung {
        let idx = (self as usize + 1).min(Self::LADDER.len() - 1);
        Self::LADDER[idx]
    }

    /// One rung easier, saturating at `Intro`.
    pub fn down(self) -> Rung {
        let idx = (self as usize).saturating_sub(1);
        Self::LADDER[idx]
    }
}

/// A prediction probe: a snippet to reason about plus the human's prediction.
///
/// `scaffolded` marks an item that was presented *with* a guided worked-example
/// scaffold (i.e. after a miss, the system taught). Scaffolded items teach but
/// never count toward mastery (CG-18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probe {
    pub concept: ConceptId,
    pub rung: Rung,
    /// The human's predicted execution output.
    pub predicted_output: String,
    /// True if this item was presented with a teaching scaffold.
    pub scaffolded: bool,
    /// True if this concept is anomalous vs the behavioural baseline — i.e. the
    /// observed system behaviour disagrees with what the baseline says it
    /// should be. Used together with a wrong prediction to raise a CG-20 signal.
    pub behaviour_is_anomalous: bool,
}

impl Probe {
    pub fn new(concept: ConceptId, rung: Rung, predicted_output: impl Into<String>) -> Self {
        Self {
            concept,
            rung,
            predicted_output: predicted_output.into(),
            scaffolded: false,
            behaviour_is_anomalous: false,
        }
    }

    /// Mark this probe as presented with a teaching scaffold.
    pub fn with_scaffold(mut self) -> Self {
        self.scaffolded = true;
        self
    }

    /// Mark the concept's observed behaviour as anomalous vs the baseline.
    pub fn with_anomalous_behaviour(mut self) -> Self {
        self.behaviour_is_anomalous = true;
        self
    }
}

/// The deterministic outcome of grading a probe by execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    /// Prediction matched the actual execution output.
    Pass,
    /// Prediction missed. `defect_signal` is true when the miss is "wrong but
    /// reasonable" against anomalous system behaviour — a CG-20 design-defect
    /// signal, not a human failing.
    Miss { defect_signal: bool },
}

impl Grade {
    pub fn is_pass(&self) -> bool {
        matches!(self, Grade::Pass)
    }
}

/// What a grading produced, including the staircase move and any crediting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub grade: Grade,
    /// The rung to present next, after the staircase move.
    pub next_rung: Rung,
    /// True only when a *non-scaffolded* probe passed: mastery is credited and
    /// the probe crystallises into the regression suite (CG-18).
    pub credits_mastery: bool,
    /// True when the passed probe should crystallise into the regression suite.
    pub crystallise: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProbeError {
    #[error("probe ladder has faded for this reader; no probe is due")]
    Faded,
    #[error("concept is not dark; probes trigger only for dark coverage areas")]
    NotDark,
}

/// Grade a probe **by execution**: compare the human's prediction with the
/// actual execution output, byte-for-byte (CG-4 — deterministic, no LLM).
///
/// On a miss against anomalous system behaviour, the result carries a CG-20
/// design-defect signal rather than treating the human as wrong.
///
/// The staircase (CG-18) rises one rung on a pass and falls one rung on a miss.
/// A *scaffolded* pass credits teaching, never mastery, and never crystallises.
pub fn grade(probe: &Probe, actual_output: &str) -> ProbeResult {
    if probe.predicted_output == actual_output {
        // Pass: staircase up. Mastery credit and crystallisation only when the
        // item was unscaffolded (CG-18).
        let credits = !probe.scaffolded;
        ProbeResult {
            grade: Grade::Pass,
            next_rung: probe.rung.up(),
            credits_mastery: credits,
            crystallise: credits,
        }
    } else {
        // Miss: staircase down. A wrong-but-reasonable prediction against
        // anomalous behaviour is a design-defect signal (CG-20), not a failing.
        ProbeResult {
            grade: Grade::Miss {
                defect_signal: probe.behaviour_is_anomalous,
            },
            next_rung: probe.rung.down(),
            credits_mastery: false,
            crystallise: false,
        }
    }
}

/// Fading rule (CG-18): probing fades as calibration climbs. At or above the
/// fade threshold the ladder is dormant for that reader.
pub const FADE_THRESHOLD: f64 = 0.85;

/// True when the reader's calibration is high enough that probing has faded.
pub fn is_faded(calibration: f64) -> bool {
    calibration >= FADE_THRESHOLD
}

/// The set of dark concepts to probe, given a reader's calibration, the dark
/// coverage-map areas, and the mastery-policy mode (CG-19).
///
/// Returns [`ProbeError::Faded`] when calibration has crossed the fade
/// threshold — the fallback is silent for well-calibrated readers.
///
/// Selection is deterministic (CG-4): concepts are sorted and, for sampled
/// modes, the first `K` are taken. `criticality` lists concepts tagged
/// high-criticality (consulted only in `Hybrid`).
pub fn select_probes(
    calibration: f64,
    dark: &[ConceptId],
    mode: &MasteryMode,
    criticality: &HashSet<ConceptId>,
) -> Result<Vec<ConceptId>, ProbeError> {
    if is_faded(calibration) {
        return Err(ProbeError::Faded);
    }

    // Deterministic ordering independent of caller insertion order (CG-4).
    let mut sorted: Vec<ConceptId> = dark.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let selected = match mode {
        MasteryMode::Strict => sorted,
        MasteryMode::Sampled(k) => sorted.into_iter().take(*k).collect(),
        MasteryMode::Hybrid { sample_k } => {
            let (critical, rest): (Vec<_>, Vec<_>) =
                sorted.into_iter().partition(|c| criticality.contains(c));
            critical
                .into_iter()
                .chain(rest.into_iter().take(*sample_k))
                .collect()
        }
    };
    Ok(selected)
}

/// Drive a sequence of graded probes, tracking the staircase and accumulating
/// only the **mastery-crediting** (unscaffolded) passes (CG-18). The crystallised
/// set is the concepts whose unscaffolded passes are ready to enter the
/// regression suite.
#[derive(Debug, Clone)]
pub struct Ladder {
    rung: Rung,
    mastered: HashSet<ConceptId>,
    crystallised: Vec<ConceptId>,
    defect_signals: Vec<ConceptId>,
}

impl Default for Ladder {
    fn default() -> Self {
        Self::new()
    }
}

impl Ladder {
    pub fn new() -> Self {
        Self {
            rung: Rung::Intro,
            mastered: HashSet::new(),
            crystallised: Vec::new(),
            defect_signals: Vec::new(),
        }
    }

    /// Start at a specific rung (e.g. pitched by the calibration ledger).
    pub fn starting_at(rung: Rung) -> Self {
        Self {
            rung,
            ..Self::new()
        }
    }

    /// The rung the next probe should be presented at.
    pub fn current_rung(&self) -> Rung {
        self.rung
    }

    /// Concepts that earned mastery credit (unscaffolded passes only).
    pub fn mastered(&self) -> &HashSet<ConceptId> {
        &self.mastered
    }

    /// Concepts whose passed probes crystallised into the regression suite.
    pub fn crystallised(&self) -> &[ConceptId] {
        &self.crystallised
    }

    /// Concepts that raised a CG-20 design-defect signal.
    pub fn defect_signals(&self) -> &[ConceptId] {
        &self.defect_signals
    }

    /// Present and grade one probe against its actual execution output,
    /// advancing the staircase. Returns the per-probe result.
    pub fn run(&mut self, probe: &Probe, actual_output: &str) -> ProbeResult {
        let result = grade(probe, actual_output);
        self.rung = result.next_rung;

        if result.credits_mastery {
            self.mastered.insert(probe.concept.clone());
        }
        if result.crystallise {
            self.crystallised.push(probe.concept.clone());
        }
        if let Grade::Miss {
            defect_signal: true,
        } = result.grade
        {
            self.defect_signals.push(probe.concept.clone());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn concept(s: &str) -> ConceptId {
        ConceptId::new(s)
    }

    // ---- CORE INTEGRATION TEST (required) -------------------------------
    //
    // Grade a probe by comparing predicted vs actual execution output
    // deterministically; assert a scaffolded pass does NOT credit mastery
    // (CG-18) and that difficulty staircases up on pass / down on miss.
    #[test]
    fn core_integration_execution_grading_scaffold_and_staircase() {
        let mut ladder = Ladder::starting_at(Rung::Medium);

        // (1) Execution grading: prediction == actual execution output => pass.
        let p_pass = Probe::new(concept("ownership"), Rung::Medium, "moved");
        let r = ladder.run(&p_pass, "moved");
        assert_eq!(r.grade, Grade::Pass);
        // Staircase rises on pass.
        assert_eq!(r.next_rung, Rung::Hard);
        assert_eq!(ladder.current_rung(), Rung::Hard);
        // Unscaffolded pass credits mastery and crystallises (CG-18).
        assert!(r.credits_mastery);
        assert!(r.crystallise);
        assert!(ladder.mastered().contains(&concept("ownership")));

        // (2) Scaffolded pass: teaches but must NOT credit mastery (CG-18).
        let p_scaffold = Probe::new(concept("lifetimes"), Rung::Hard, "ok").with_scaffold();
        let r = ladder.run(&p_scaffold, "ok");
        assert_eq!(r.grade, Grade::Pass);
        assert!(!r.credits_mastery, "scaffolded pass must not credit mastery");
        assert!(!r.crystallise, "scaffolded pass must not crystallise");
        assert!(!ladder.mastered().contains(&concept("lifetimes")));

        // (3) Staircase falls on a miss: predicted != actual.
        let p_miss = Probe::new(concept("borrows"), Rung::Expert, "compiles");
        let r = ladder.run(&p_miss, "E0502: cannot borrow");
        assert!(matches!(r.grade, Grade::Miss { .. }));
        assert_eq!(r.next_rung, Rung::Hard); // Expert -> Hard
        assert_eq!(ladder.current_rung(), Rung::Hard);
        assert!(!r.credits_mastery);
    }

    #[test]
    fn grading_is_deterministic_byte_comparison() {
        let p = Probe::new(concept("c"), Rung::Easy, "42\n");
        assert!(grade(&p, "42\n").grade.is_pass());
        assert!(!grade(&p, "42").grade.is_pass()); // trailing newline matters
        assert!(!grade(&p, " 42\n").grade.is_pass());
    }

    #[test]
    fn staircase_saturates_at_bounds() {
        assert_eq!(Rung::Expert.up(), Rung::Expert);
        assert_eq!(Rung::Intro.down(), Rung::Intro);
        assert_eq!(Rung::Intro.up(), Rung::Easy);
        assert_eq!(Rung::Expert.down(), Rung::Hard);
    }

    // CG-20: wrong-but-reasonable prediction against anomalous behaviour is a
    // design-defect signal, not a human failing.
    #[test]
    fn miss_against_anomalous_behaviour_raises_defect_signal() {
        let mut ladder = Ladder::new();
        let p = Probe::new(concept("scheduler"), Rung::Medium, "fair").with_anomalous_behaviour();
        let r = ladder.run(&p, "starves thread 3");
        assert_eq!(r.grade, Grade::Miss { defect_signal: true });
        assert_eq!(ladder.defect_signals(), &[concept("scheduler")]);
    }

    #[test]
    fn miss_without_anomaly_is_not_a_defect_signal() {
        let p = Probe::new(concept("x"), Rung::Medium, "fair");
        let r = grade(&p, "different");
        assert_eq!(r.grade, Grade::Miss { defect_signal: false });
    }

    // CG-18: fading with calibration.
    #[test]
    fn probes_fade_once_calibration_crosses_threshold() {
        let dark = vec![concept("a"), concept("b")];
        let crit = HashSet::new();
        assert!(matches!(
            select_probes(0.95, &dark, &MasteryMode::Strict, &crit),
            Err(ProbeError::Faded)
        ));
        // Below threshold: probes are due.
        let due = select_probes(0.5, &dark, &MasteryMode::Strict, &crit).unwrap();
        assert_eq!(due.len(), 2);
    }

    // CG-19: trigger only for dark areas, per mastery mode (strict/sampled/hybrid).
    #[test]
    fn selection_respects_mastery_mode() {
        let dark = vec![concept("d"), concept("a"), concept("c"), concept("b")];
        let crit: HashSet<ConceptId> = [concept("d")].into_iter().collect();

        // Strict: all dark concepts, deterministically sorted.
        let strict = select_probes(0.2, &dark, &MasteryMode::Strict, &HashSet::new()).unwrap();
        assert_eq!(
            strict,
            vec![concept("a"), concept("b"), concept("c"), concept("d")]
        );

        // Sampled(K): first K of the sorted set, deterministic.
        let sampled = select_probes(0.2, &dark, &MasteryMode::Sampled(2), &HashSet::new()).unwrap();
        assert_eq!(sampled, vec![concept("a"), concept("b")]);

        // Hybrid: all critical first, then sample of the rest.
        let hybrid =
            select_probes(0.2, &dark, &MasteryMode::Hybrid { sample_k: 1 }, &crit).unwrap();
        assert_eq!(hybrid, vec![concept("d"), concept("a")]);
    }

    #[test]
    fn crystallised_set_holds_only_unscaffolded_passes() {
        let mut ladder = Ladder::new();
        ladder.run(&Probe::new(concept("p1"), Rung::Easy, "1"), "1"); // pass, credit
        ladder.run(
            &Probe::new(concept("p2"), Rung::Easy, "2").with_scaffold(),
            "2",
        ); // scaffolded pass, no credit
        ladder.run(&Probe::new(concept("p3"), Rung::Easy, "3"), "wrong"); // miss
        assert_eq!(ladder.crystallised(), &[concept("p1")]);
        assert!(ladder.mastered().contains(&concept("p1")));
        assert_eq!(ladder.mastered().len(), 1);
    }
}
