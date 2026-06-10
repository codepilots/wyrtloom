/// W2 — Gate engine: guarded Kanban transitions that open with a lesson
/// (CG-1) and mint approval tokens carrying the blame-allocation notice
/// (CG-24). Pass/fail is decided by the human via the escalation interface
/// and by coded checks — never by an LLM (CG-4).
use crate::audit::{WorkflowAudit, WorkflowEventKind};
use crate::coverage::Concept;
use crate::digest::{Digest, DigestGenerator, EnrichmentItem};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;
use wyrtloom_core::escalation::{ActionOption, Escalation, HumanEscalation, HumanResponse};
use wyrtloom_core::kanban::{is_legal_transition, KanbanBoard, TaskState};
use wyrtloom_core::types::{ActorId, TaskId, Timestamp};

/// CG-24: gate passage never transfers liability for agent defects to the
/// gate-passer. Every approval token carries this notice verbatim.
pub const BLAME_NOTICE: &str =
    "Passing this gate does not transfer liability for agent defects to you. \
     Override stamps are remediation signals, not culpability markers; \
     incident reviews examine the system.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gate {
    pub id: String,
    pub from: TaskState,
    pub to: TaskState,
    /// Concepts the digest teaches before the challenge is posed.
    pub concepts_in_play: Vec<Concept>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToken {
    pub id: Uuid,
    pub task: TaskId,
    pub gate: String,
    pub approved_by: ActorId,
    pub at: Timestamp,
    pub blame_notice: String,
}

#[derive(Debug)]
pub enum GateOutcome {
    Approved { token: ApprovalToken, digest: Digest },
    Held { reason: String },
    Stopped,
}

#[derive(Error, Debug)]
pub enum GateError {
    #[error("gate transition is not legal on the kanban board: {0:?} → {1:?}")]
    IllegalTransition(TaskState, TaskState),
    #[error("escalation failed: {0}")]
    Escalation(String),
    #[error("kanban error: {0}")]
    Kanban(String),
}

pub struct GateEngine {
    pub kanban: Arc<dyn KanbanBoard>,
    pub escalation: Arc<dyn HumanEscalation>,
    pub audit: WorkflowAudit,
}

impl GateEngine {
    /// The full gate prompt: the digest (the lesson) always renders before
    /// the challenge (CG-1 — instruction-first).
    pub fn gate_prompt(gate: &Gate, digest: &Digest) -> String {
        format!(
            "{}\n\n{}\n\nReady to move this task {} → {}?",
            digest.render(),
            BLAME_NOTICE,
            gate.from,
            gate.to,
        )
    }

    pub fn request_passage(
        &self,
        task: TaskId,
        gate: &Gate,
        reader: &ActorId,
        reader_calibration: f64,
        enrichment: &[EnrichmentItem],
        request_richer: bool,
    ) -> Result<GateOutcome, GateError> {
        if !is_legal_transition(&gate.from, &gate.to) {
            return Err(GateError::IllegalTransition(gate.from.clone(), gate.to.clone()));
        }

        // Gate time cost is instrumented from here — digest generation
        // through human decision — for the §2.6 economics pilot.
        let started = std::time::Instant::now();

        // Lesson first (CG-1): the digest is generated unconditionally,
        // before any challenge is posed, with coherence and fading rules
        // applied (CG-2/3).
        let digest = DigestGenerator::generate(
            &gate.concepts_in_play,
            reader_calibration,
            enrichment,
            request_richer,
        );

        let escalation = Escalation {
            task,
            prompt: Self::gate_prompt(gate, &digest),
            options: vec![
                ActionOption {
                    id: "approve".into(),
                    label: "Approve passage".into(),
                    description: Some("Open the gate and move the task".into()),
                },
                ActionOption {
                    id: "hold".into(),
                    label: "Hold".into(),
                    description: Some("Keep the task where it is".into()),
                },
            ],
        };

        match self.escalation.escalate(escalation) {
            Ok(HumanResponse::Chose(ref id)) if id == "approve" => {
                self.kanban
                    .transition(
                        task,
                        gate.to.clone(),
                        reader.clone(),
                        Some(format!("gate '{}' approved", gate.id)),
                    )
                    .map_err(|e| GateError::Kanban(e.to_string()))?;
                let token = ApprovalToken {
                    id: Uuid::new_v4(),
                    task,
                    gate: gate.id.clone(),
                    approved_by: reader.clone(),
                    at: Timestamp::now(),
                    blame_notice: BLAME_NOTICE.to_string(),
                };
                self.audit.record_timed(
                    WorkflowEventKind::Gate,
                    task,
                    reader,
                    &format!("gate '{}' approved", gate.id),
                    Some(started.elapsed()),
                );
                Ok(GateOutcome::Approved { token, digest })
            }
            Ok(HumanResponse::Stop) => {
                self.audit.record_timed(
                    WorkflowEventKind::Gate,
                    task,
                    reader,
                    &format!("gate '{}' stopped", gate.id),
                    Some(started.elapsed()),
                );
                Ok(GateOutcome::Stopped)
            }
            Ok(HumanResponse::FreeText(text)) => {
                self.audit.record_timed(
                    WorkflowEventKind::Gate,
                    task,
                    reader,
                    &format!("gate '{}' held: {}", gate.id, text),
                    Some(started.elapsed()),
                );
                Ok(GateOutcome::Held { reason: text })
            }
            Ok(HumanResponse::Chose(_)) => {
                self.audit.record_timed(
                    WorkflowEventKind::Gate,
                    task,
                    reader,
                    &format!("gate '{}' held", gate.id),
                    Some(started.elapsed()),
                );
                Ok(GateOutcome::Held { reason: "held at the gate".into() })
            }
            Err(e) => Err(GateError::Escalation(e.to_string())),
        }
    }

    /// Deterministic token validation (CG-4).
    pub fn validate_token(token: &ApprovalToken, task: TaskId, gate_id: &str) -> bool {
        token.task == task && token.gate == gate_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NoopCallLogger;
    use std::sync::Mutex;
    use wyrtloom_core::escalation::EscalationError;
    use wyrtloom_core::kanban::{BlockReason, KanbanError, NewTask, Task};

    struct MockBoard {
        transitions: Mutex<Vec<(TaskId, TaskState)>>,
    }

    impl MockBoard {
        fn new() -> Self {
            Self { transitions: Mutex::new(Vec::new()) }
        }
    }

    impl KanbanBoard for MockBoard {
        fn create(&self, _task: NewTask) -> Result<TaskId, KanbanError> {
            Ok(Uuid::new_v4())
        }
        fn transition(
            &self,
            id: TaskId,
            to: TaskState,
            _actor: ActorId,
            _reason: Option<String>,
        ) -> Result<(), KanbanError> {
            self.transitions.lock().unwrap().push((id, to));
            Ok(())
        }
        fn claim(&self, _id: TaskId, _worker: ActorId) -> Result<(), KanbanError> {
            Ok(())
        }
        fn get(&self, id: TaskId) -> Result<Task, KanbanError> {
            Err(KanbanError::NotFound(id))
        }
        fn block(
            &self,
            _id: TaskId,
            _actor: ActorId,
            _reason: BlockReason,
        ) -> Result<(), KanbanError> {
            Ok(())
        }
    }

    struct Scripted(HumanResponse);

    impl HumanEscalation for Scripted {
        fn escalate(&self, _e: Escalation) -> Result<HumanResponse, EscalationError> {
            Ok(self.0.clone())
        }
    }

    fn engine(response: HumanResponse) -> (GateEngine, Arc<MockBoard>) {
        let board = Arc::new(MockBoard::new());
        let engine = GateEngine {
            kanban: board.clone(),
            escalation: Arc::new(Scripted(response)),
            audit: WorkflowAudit::new(Arc::new(NoopCallLogger)),
        };
        (engine, board)
    }

    fn gate() -> Gate {
        Gate {
            id: "design-review".into(),
            from: TaskState::Ready,
            to: TaskState::Running,
            concepts_in_play: vec![Concept {
                id: "tokeniser".into(),
                component: "parser".into(),
                summary: "splits raw input into tokens".into(),
            }],
        }
    }

    #[test]
    fn cg1_digest_precedes_the_challenge_in_the_prompt() {
        let digest = DigestGenerator::generate(&gate().concepts_in_play, 0.0, &[], false);
        let prompt = GateEngine::gate_prompt(&gate(), &digest);
        let lesson_pos = prompt.find("Let's walk through").unwrap();
        let challenge_pos = prompt.find("Ready to move").unwrap();
        assert!(lesson_pos < challenge_pos, "instruction must precede the challenge");
    }

    #[test]
    fn cg24_prompt_and_token_carry_the_blame_notice() {
        let digest = DigestGenerator::generate(&gate().concepts_in_play, 0.0, &[], false);
        let prompt = GateEngine::gate_prompt(&gate(), &digest);
        assert!(prompt.contains("does not transfer liability"));

        let (engine, _) = engine(HumanResponse::Chose("approve".into()));
        let outcome = engine
            .request_passage(Uuid::new_v4(), &gate(), &"human:dev".into(), 0.0, &[], false)
            .unwrap();
        match outcome {
            GateOutcome::Approved { token, .. } => {
                assert_eq!(token.blame_notice, BLAME_NOTICE);
            }
            other => panic!("expected approval, got {:?}", other),
        }
    }

    #[test]
    fn approval_transitions_the_board_and_audits() {
        let (engine, board) = engine(HumanResponse::Chose("approve".into()));
        let task = Uuid::new_v4();
        let outcome = engine
            .request_passage(task, &gate(), &"human:dev".into(), 0.0, &[], false)
            .unwrap();
        assert!(matches!(outcome, GateOutcome::Approved { .. }));
        let transitions = board.transitions.lock().unwrap();
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0], (task, TaskState::Running));
        // CG-28: the gate event reached the audit trail, with the
        // digest-to-decision duration measured for the §2.6 pilot.
        let trail = engine.audit.snapshot();
        assert_eq!(trail.len(), 1);
        assert!(trail[0].duration_ms.is_some());
    }

    #[test]
    fn hold_and_stop_leave_the_board_untouched() {
        for response in [HumanResponse::Chose("hold".into()), HumanResponse::Stop] {
            let (engine, board) = engine(response);
            let outcome = engine
                .request_passage(Uuid::new_v4(), &gate(), &"human:dev".into(), 0.0, &[], false)
                .unwrap();
            assert!(matches!(outcome, GateOutcome::Held { .. } | GateOutcome::Stopped));
            assert!(board.transitions.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn gates_off_the_kanban_contract_are_rejected() {
        let (engine, _) = engine(HumanResponse::Chose("approve".into()));
        let mut bad = gate();
        bad.from = TaskState::Backlog;
        bad.to = TaskState::Done;
        let result =
            engine.request_passage(Uuid::new_v4(), &bad, &"human:dev".into(), 0.0, &[], false);
        assert!(matches!(result, Err(GateError::IllegalTransition(_, _))));
    }

    #[test]
    fn cg4_token_validation_is_deterministic() {
        let task = Uuid::new_v4();
        let token = ApprovalToken {
            id: Uuid::new_v4(),
            task,
            gate: "design-review".into(),
            approved_by: "human:dev".into(),
            at: Timestamp::now(),
            blame_notice: BLAME_NOTICE.into(),
        };
        assert!(GateEngine::validate_token(&token, task, "design-review"));
        assert!(!GateEngine::validate_token(&token, Uuid::new_v4(), "design-review"));
        assert!(!GateEngine::validate_token(&token, task, "ship-review"));
    }
}
