/// W4 — Hunt harness (CG-5..9): sandboxed execution of human-authored
/// breaking tests against agent output, deterministic coverage crediting
/// from the execution trace, and stake escalation when the target survives.
/// No points, scores, leaderboards, or rewards exist anywhere here (CG-9):
/// the hunter is the hunter, never the specimen.
use crate::audit::{WorkflowAudit, WorkflowEventKind};
use crate::coverage::{ConceptId, CoverageMap, CreditSource};
use crate::policy::HuntPolicy;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use wyrtloom_core::sandbox::{ResourceLimits, SafeModule, SandboxRuntime};
use wyrtloom_core::types::{ActorId, Bytes, TaskId, Timestamp};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntTest {
    pub id: Uuid,
    /// Always a human (§1.3 — every hunt-test the human authored).
    pub author: ActorId,
    pub name: String,
    pub input: Bytes,
    /// When set, the target survives only if its output equals this.
    /// When None, the target survives by executing without trapping.
    pub expected_output: Option<Bytes>,
}

/// Concepts exercised by an instrumented run — the execution-trace half of
/// CG-6's `trace ∩ coverage map`.
#[derive(Debug, Clone, Default)]
pub struct ExecutionTrace {
    pub concepts_exercised: Vec<ConceptId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefectRecord {
    pub id: Uuid,
    pub test: Uuid,
    pub description: String,
    pub opened_at: Timestamp,
    pub fixed: bool,
}

/// "This version survives your last test; break it again." (CG-8)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeOffer {
    /// Ladder depth of this offer, bounded by HuntPolicy::max_ladder_depth.
    pub depth: u8,
    pub prompt: String,
}

#[derive(Debug, Serialize)]
pub enum HuntResult {
    TargetBroke { defect: DefectRecord },
    TargetSurvived { stake_offer: Option<StakeOffer> },
}

#[derive(Debug, Serialize)]
pub struct HuntReport {
    pub test: Uuid,
    pub result: HuntResult,
    /// Credited regardless of whether the target broke (CG-6).
    pub credited_concepts: Vec<ConceptId>,
}

/// Crystallised tests — breaking tests join here on fix (CG-7), as do
/// passed probes (§1.5).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RegressionSuite {
    pub crystallised_tests: Vec<Uuid>,
}

impl RegressionSuite {
    pub fn crystallise(&mut self, test: Uuid) {
        if !self.crystallised_tests.contains(&test) {
            self.crystallised_tests.push(test);
        }
    }
}

pub struct HuntHarness {
    pub sandbox: Arc<dyn SandboxRuntime>,
    pub limits: ResourceLimits,
    pub audit: WorkflowAudit,
}

impl HuntHarness {
    /// Run one hunt (CG-5): the human-authored test executes against the
    /// agent's output in the standard sandbox.
    pub fn run(
        &self,
        task: TaskId,
        test: &HuntTest,
        target: SafeModule,
        trace: &ExecutionTrace,
        coverage: &mut CoverageMap,
        policy: &HuntPolicy,
        hunter_calibration: f64,
        prior_depth: u8,
    ) -> HuntReport {
        let now = Timestamp::now();

        // CG-6: coverage credit is computed deterministically from the
        // exercised trace — before and regardless of the outcome below.
        let credited = coverage.credit_from_trace(
            &test.author,
            &trace.concepts_exercised,
            CreditSource::Hunt(test.id),
            now.clone(),
        );

        let execution = self.sandbox.execute(target, test.input.clone(), self.limits.clone());
        let broke = match &execution {
            Err(_) => true,
            Ok(output) => test
                .expected_output
                .as_ref()
                .map_or(false, |want| want != output),
        };

        let result = if broke {
            // CG-7(i): a breaking test opens a defect.
            let defect = DefectRecord {
                id: Uuid::new_v4(),
                test: test.id,
                description: format!("hunt test '{}' broke the target", test.name),
                opened_at: now,
                fixed: false,
            };
            self.audit.record(
                WorkflowEventKind::Hunt,
                task,
                &test.author,
                &format!("test '{}' broke target; defect {} opened", test.name, defect.id),
            );
            HuntResult::TargetBroke { defect }
        } else {
            // CG-8: on survival, offer an escalated-stakes variant pitched
            // by the hunter's calibration, up to the configured depth.
            let stake_offer = if policy.stake_escalation && prior_depth < policy.max_ladder_depth
            {
                Some(StakeOffer {
                    depth: prior_depth + 1,
                    prompt: Self::stake_prompt(&test.name, hunter_calibration),
                })
            } else {
                None
            };
            self.audit.record(
                WorkflowEventKind::Hunt,
                task,
                &test.author,
                &format!("test '{}' survived", test.name),
            );
            HuntResult::TargetSurvived { stake_offer }
        };

        HuntReport { test: test.id, result, credited_concepts: credited }
    }

    /// Deterministic template (CG-4); the pitch follows the hunter's
    /// calibration (CG-8) — surface text only, never a decision.
    fn stake_prompt(test_name: &str, calibration: f64) -> String {
        if calibration >= 0.75 {
            format!(
                "This version survives '{}'. You know this ground well — break it again.",
                test_name
            )
        } else {
            format!(
                "This version survives '{}'. Want a walk along the seams before you try again?",
                test_name
            )
        }
    }

    /// CG-7(iii): when the defect is fixed, the breaking test crystallises
    /// into the regression suite.
    pub fn crystallise_on_fix(
        defect: &mut DefectRecord,
        test: &HuntTest,
        suite: &mut RegressionSuite,
    ) {
        defect.fixed = true;
        suite.crystallise(test.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NoopCallLogger;
    use crate::coverage::Concept;
    use wyrtloom_core::sandbox::SandboxError;

    /// Survives: echoes its input back.
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

    /// Breaks: every execution traps.
    struct TrapSandbox;
    impl SandboxRuntime for TrapSandbox {
        fn execute(
            &self,
            _module: SafeModule,
            _input: Bytes,
            _limits: ResourceLimits,
        ) -> Result<Bytes, SandboxError> {
            Err(SandboxError::Trap("unreachable executed".into()))
        }
    }

    fn harness(sandbox: Arc<dyn SandboxRuntime>) -> HuntHarness {
        HuntHarness {
            sandbox,
            limits: ResourceLimits::default(),
            audit: WorkflowAudit::new(Arc::new(NoopCallLogger)),
        }
    }

    fn test_case() -> HuntTest {
        HuntTest {
            id: Uuid::new_v4(),
            author: "human:hunter".into(),
            name: "malformed-unicode".into(),
            input: b"\xff\xfe".to_vec(),
            expected_output: None,
        }
    }

    fn coverage() -> CoverageMap {
        let mut m = CoverageMap::new();
        m.add_concept(Concept {
            id: "tokeniser".into(),
            component: "parser".into(),
            summary: "splits raw input into tokens".into(),
        });
        m
    }

    fn trace() -> ExecutionTrace {
        ExecutionTrace { concepts_exercised: vec!["tokeniser".into(), "not-mapped".into()] }
    }

    fn policy() -> HuntPolicy {
        HuntPolicy { stake_escalation: true, max_ladder_depth: 3 }
    }

    #[test]
    fn cg5_cg7_breaking_test_opens_defect_and_credits() {
        let h = harness(Arc::new(TrapSandbox));
        let mut cov = coverage();
        let report = h.run(
            Uuid::new_v4(),
            &test_case(),
            SafeModule::new(vec![]),
            &trace(),
            &mut cov,
            &policy(),
            0.5,
            0,
        );
        assert!(matches!(report.result, HuntResult::TargetBroke { .. }));
        // CG-6: credit landed despite (and independent of) the break.
        assert_eq!(report.credited_concepts, vec!["tokeniser".to_string()]);
        assert!(!cov.is_dark("tokeniser"));
    }

    #[test]
    fn cg6_surviving_test_credits_identically() {
        let h = harness(Arc::new(EchoSandbox));
        let mut cov = coverage();
        let report = h.run(
            Uuid::new_v4(),
            &test_case(),
            SafeModule::new(vec![]),
            &trace(),
            &mut cov,
            &policy(),
            0.5,
            0,
        );
        assert!(matches!(report.result, HuntResult::TargetSurvived { .. }));
        assert_eq!(report.credited_concepts, vec!["tokeniser".to_string()]);
    }

    #[test]
    fn output_mismatch_counts_as_broken() {
        let h = harness(Arc::new(EchoSandbox));
        let mut t = test_case();
        t.expected_output = Some(b"something else".to_vec());
        let report = h.run(
            Uuid::new_v4(),
            &t,
            SafeModule::new(vec![]),
            &trace(),
            &mut coverage(),
            &policy(),
            0.5,
            0,
        );
        assert!(matches!(report.result, HuntResult::TargetBroke { .. }));
    }

    #[test]
    fn cg7_fix_crystallises_test_into_regression_suite() {
        let t = test_case();
        let mut defect = DefectRecord {
            id: Uuid::new_v4(),
            test: t.id,
            description: "broke".into(),
            opened_at: Timestamp::now(),
            fixed: false,
        };
        let mut suite = RegressionSuite::default();
        HuntHarness::crystallise_on_fix(&mut defect, &t, &mut suite);
        assert!(defect.fixed);
        assert_eq!(suite.crystallised_tests, vec![t.id]);
        // Idempotent.
        HuntHarness::crystallise_on_fix(&mut defect, &t, &mut suite);
        assert_eq!(suite.crystallised_tests.len(), 1);
    }

    #[test]
    fn cg8_survival_offers_escalated_stakes_within_ladder() {
        let h = harness(Arc::new(EchoSandbox));
        let report = h.run(
            Uuid::new_v4(),
            &test_case(),
            SafeModule::new(vec![]),
            &trace(),
            &mut coverage(),
            &policy(),
            0.9,
            0,
        );
        match report.result {
            HuntResult::TargetSurvived { stake_offer: Some(offer) } => {
                assert_eq!(offer.depth, 1);
                assert!(offer.prompt.contains("break it again"));
            }
            other => panic!("expected stake offer, got {:?}", other),
        }
    }

    #[test]
    fn cg8_ladder_depth_is_bounded() {
        let h = harness(Arc::new(EchoSandbox));
        let report = h.run(
            Uuid::new_v4(),
            &test_case(),
            SafeModule::new(vec![]),
            &trace(),
            &mut coverage(),
            &policy(),
            0.9,
            3, // already at max_ladder_depth
        );
        assert!(matches!(
            report.result,
            HuntResult::TargetSurvived { stake_offer: None }
        ));
    }

    /// CG-9: no points, scores, leaderboards, or rewards attach to hunt
    /// statistics — verified against the serialised report shape.
    #[test]
    fn cg9_no_gamification_fields_in_hunt_output() {
        let h = harness(Arc::new(EchoSandbox));
        let report = h.run(
            Uuid::new_v4(),
            &test_case(),
            SafeModule::new(vec![]),
            &trace(),
            &mut coverage(),
            &policy(),
            0.5,
            0,
        );
        let json = serde_json::to_value(&report).unwrap();
        let mut keys = Vec::new();
        collect_keys(&json, &mut keys);
        for forbidden in ["score", "points", "rank", "leaderboard", "reward", "badge"] {
            assert!(
                !keys.iter().any(|k| k.contains(forbidden)),
                "hunt output must not carry '{}' (CG-9)",
                forbidden
            );
        }
    }

    fn collect_keys(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    out.push(k.to_lowercase());
                    collect_keys(v, out);
                }
            }
            serde_json::Value::Array(items) => {
                for v in items {
                    collect_keys(v, out);
                }
            }
            _ => {}
        }
    }
}
