/// W5 — Socratic probe ladder (CG-18..20): the quiet fallback for
/// coverage-map territory still dark after hunt, build, and solo-flight
/// credit. Prediction probes are graded by execution — never by an LLM
/// judge (F-HULA follow-up showed judge instability).
use crate::coverage::{ConceptId, CoverageMap};
use crate::hunt::RegressionSuite;
use crate::policy::MasteryMode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;
use wyrtloom_core::sandbox::{ResourceLimits, SafeModule, SandboxError, SandboxRuntime};
use wyrtloom_core::types::Bytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub id: Uuid,
    pub concept: ConceptId,
    /// Surface text is template-filled (an LLM may rewrite it); grading
    /// never reads it (CG-4).
    pub surface_text: String,
    pub input: Bytes,
    pub difficulty: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeGrade {
    pub probe: Uuid,
    pub passed: bool,
    /// Scaffolded attempts never count toward mastery (CG-18).
    pub counts_toward_mastery: bool,
    /// A guided worked example, offered when the prediction misses —
    /// scaffolds teach (CG-18).
    pub scaffold: Option<String>,
    /// Staircase: up on a pass, down (floor 1) on a miss (CG-18).
    pub next_difficulty: u8,
}

/// CG-20: a human prediction that is wrong while the system behaves
/// anomalously against the behavioural baseline is a defect signal about
/// the system's design — not a failing of the human.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DesignDefectSignal {
    pub concept: ConceptId,
    pub note: String,
}

pub struct ProbeLadder;

impl ProbeLadder {
    /// CG-19: probes trigger only for dark concepts, per the mastery-policy
    /// mode (strict / sampled-K / hybrid). Deterministic: dark concepts
    /// arrive sorted, and sampling takes a prefix.
    pub fn select(
        coverage: &CoverageMap,
        mode: &MasteryMode,
        critical: &BTreeSet<ConceptId>,
    ) -> Vec<ConceptId> {
        let dark = coverage.dark_concepts();
        match mode {
            MasteryMode::Strict => dark,
            MasteryMode::Sampled(k) => dark.into_iter().take(*k).collect(),
            MasteryMode::Hybrid { sample } => {
                let mut out: Vec<ConceptId> =
                    dark.iter().filter(|c| critical.contains(*c)).cloned().collect();
                out.extend(
                    dark.iter()
                        .filter(|c| !critical.contains(*c))
                        .take(*sample)
                        .cloned(),
                );
                out
            }
        }
    }

    /// Execution-graded prediction (CG-18): the human's predicted output is
    /// compared byte-for-byte with the sandboxed run. Passed, unscaffolded
    /// probes crystallise into the regression suite (§1.5).
    pub fn grade(
        probe: &Probe,
        predicted: &[u8],
        scaffolded: bool,
        sandbox: &dyn SandboxRuntime,
        module: SafeModule,
        limits: ResourceLimits,
        suite: &mut RegressionSuite,
    ) -> Result<ProbeGrade, SandboxError> {
        let actual = sandbox.execute(module, probe.input.clone(), limits)?;
        let passed = predicted == actual.as_slice();
        if passed && !scaffolded {
            suite.crystallise(probe.id);
        }
        Ok(ProbeGrade {
            probe: probe.id,
            passed,
            counts_toward_mastery: passed && !scaffolded,
            scaffold: if passed { None } else { Some(Self::scaffold_text(probe)) },
            next_difficulty: if passed {
                probe.difficulty.saturating_add(1)
            } else {
                probe.difficulty.saturating_sub(1).max(1)
            },
        })
    }

    /// Deterministic template (CG-4): a guided worked example that teaches
    /// when a prediction misses.
    fn scaffold_text(probe: &Probe) -> String {
        format!(
            "Let's walk this one together: trace the input step by step through \
             '{}', note where the behaviour surprised you, then predict again.",
            probe.concept
        )
    }

    pub fn design_defect_signal(
        probe: &Probe,
        prediction_passed: bool,
        behaviour_anomalous: bool,
    ) -> Option<DesignDefectSignal> {
        if !prediction_passed && behaviour_anomalous {
            Some(DesignDefectSignal {
                concept: probe.concept.clone(),
                note: "a reasonable prediction missed while system behaviour is \
                       anomalous vs the behavioural baseline — review the design, \
                       not the human"
                    .into(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::Concept;

    struct EchoSandbox;
    impl SandboxRuntime for EchoSandbox {
        fn execute(
            &self,
            _module: SafeModule,
            input: Bytes,
            _limits: ResourceLimits,
        ) -> Result<Bytes, SandboxError> {
            Ok(input)
        }
    }

    fn probe(difficulty: u8) -> Probe {
        Probe {
            id: Uuid::new_v4(),
            concept: "tokeniser".into(),
            surface_text: "What does the tokeniser produce for this input?".into(),
            input: b"4".to_vec(),
            difficulty,
        }
    }

    fn dark_map(ids: &[&str]) -> CoverageMap {
        let mut m = CoverageMap::new();
        for id in ids {
            m.add_concept(Concept {
                id: id.to_string(),
                component: "core".into(),
                summary: String::new(),
            });
        }
        m
    }

    #[test]
    fn cg18_correct_prediction_passes_and_crystallises() {
        let mut suite = RegressionSuite::default();
        let p = probe(2);
        let grade = ProbeLadder::grade(
            &p,
            b"4",
            false,
            &EchoSandbox,
            SafeModule::new(vec![]),
            ResourceLimits::default(),
            &mut suite,
        )
        .unwrap();
        assert!(grade.passed);
        assert!(grade.counts_toward_mastery);
        assert!(grade.scaffold.is_none());
        assert_eq!(grade.next_difficulty, 3);
        assert_eq!(suite.crystallised_tests, vec![p.id]);
    }

    #[test]
    fn cg18_missed_prediction_scaffolds_and_steps_down() {
        let mut suite = RegressionSuite::default();
        let grade = ProbeLadder::grade(
            &probe(3),
            b"5",
            false,
            &EchoSandbox,
            SafeModule::new(vec![]),
            ResourceLimits::default(),
            &mut suite,
        )
        .unwrap();
        assert!(!grade.passed);
        assert!(!grade.counts_toward_mastery);
        assert!(grade.scaffold.unwrap().contains("walk this one together"));
        assert_eq!(grade.next_difficulty, 2);
        assert!(suite.crystallised_tests.is_empty());
    }

    #[test]
    fn cg18_scaffolded_pass_does_not_count_toward_mastery() {
        let mut suite = RegressionSuite::default();
        let grade = ProbeLadder::grade(
            &probe(2),
            b"4",
            true,
            &EchoSandbox,
            SafeModule::new(vec![]),
            ResourceLimits::default(),
            &mut suite,
        )
        .unwrap();
        assert!(grade.passed);
        assert!(!grade.counts_toward_mastery);
        assert!(suite.crystallised_tests.is_empty());
    }

    #[test]
    fn cg18_difficulty_floor_is_one() {
        let mut suite = RegressionSuite::default();
        let grade = ProbeLadder::grade(
            &probe(1),
            b"5",
            false,
            &EchoSandbox,
            SafeModule::new(vec![]),
            ResourceLimits::default(),
            &mut suite,
        )
        .unwrap();
        assert_eq!(grade.next_difficulty, 1);
    }

    #[test]
    fn cg19_selection_targets_only_dark_concepts_per_mode() {
        let map = dark_map(&["a", "b", "c", "d"]);
        let critical: BTreeSet<ConceptId> = ["c".to_string()].into();

        assert_eq!(
            ProbeLadder::select(&map, &MasteryMode::Strict, &critical),
            ["a", "b", "c", "d"].map(String::from)
        );
        assert_eq!(
            ProbeLadder::select(&map, &MasteryMode::Sampled(2), &critical),
            ["a", "b"].map(String::from)
        );
        // Hybrid: every critical dark concept, plus a sample of the rest.
        assert_eq!(
            ProbeLadder::select(&map, &MasteryMode::Hybrid { sample: 1 }, &critical),
            ["c", "a"].map(String::from)
        );
    }

    #[test]
    fn cg19_credited_concepts_are_not_probed() {
        let mut map = dark_map(&["a", "b"]);
        map.credit_from_trace(
            &"human:dev".to_string(),
            &["a".into()],
            crate::coverage::CreditSource::Hunt(Uuid::new_v4()),
            wyrtloom_core::types::Timestamp::now(),
        );
        assert_eq!(
            ProbeLadder::select(&map, &MasteryMode::Strict, &BTreeSet::new()),
            ["b"].map(String::from)
        );
    }

    #[test]
    fn cg20_wrong_prediction_plus_anomaly_raises_design_defect() {
        let p = probe(2);
        assert!(ProbeLadder::design_defect_signal(&p, false, true).is_some());
        assert!(ProbeLadder::design_defect_signal(&p, false, false).is_none());
        assert!(ProbeLadder::design_defect_signal(&p, true, true).is_none());
    }
}
