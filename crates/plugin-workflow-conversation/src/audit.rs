/// CG-28 — All gate, hunt, probe, withdrawal, and rotation events are
/// logged for audit via the locked call-logger contract; an in-memory trail
/// keeps the structured form. Access to per-person details follows the
/// CG-21/22 governance rules (the trail carries actor ids only for audit,
/// never for ranking — no ranking query exists).
use std::sync::{Arc, Mutex};
use wyrtloom_core::logger::{CallLog, CallLogger, CallOutcome, LogError};
use wyrtloom_core::provider::Usage;
use wyrtloom_core::types::{ActorId, TaskId, Timestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowEventKind {
    Gate,
    Hunt,
    Probe,
    Withdrawal,
    Rotation,
}

impl WorkflowEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkflowEventKind::Gate => "workflow.gate",
            WorkflowEventKind::Hunt => "workflow.hunt",
            WorkflowEventKind::Probe => "workflow.probe",
            WorkflowEventKind::Withdrawal => "workflow.withdrawal",
            WorkflowEventKind::Rotation => "workflow.rotation",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkflowEvent {
    pub kind: WorkflowEventKind,
    pub task: TaskId,
    pub actor: ActorId,
    pub detail: String,
    pub at: Timestamp,
}

#[derive(Clone)]
pub struct WorkflowAudit {
    logger: Arc<dyn CallLogger>,
    trail: Arc<Mutex<Vec<WorkflowEvent>>>,
}

impl WorkflowAudit {
    pub fn new(logger: Arc<dyn CallLogger>) -> Self {
        Self { logger, trail: Arc::new(Mutex::new(Vec::new())) }
    }

    pub fn record(
        &self,
        kind: WorkflowEventKind,
        task: TaskId,
        actor: &ActorId,
        detail: &str,
    ) {
        let event = WorkflowEvent {
            kind,
            task,
            actor: actor.clone(),
            detail: detail.into(),
            at: Timestamp::now(),
        };
        // Mirror onto the call logger (CG-28). No LLM is involved; usage is
        // zero by definition.
        let _ = self.logger.record(CallLog {
            task,
            profile: "workflow-conversation-v0.1".into(),
            provider: "workflow".into(),
            model: kind.as_str().into(),
            usage: Usage { input_tokens: 0, output_tokens: 0, cost: None },
            outcome: CallOutcome::Completed,
            at: event.at.clone(),
        });
        self.trail.lock().unwrap().push(event);
    }

    pub fn snapshot(&self) -> Vec<WorkflowEvent> {
        self.trail.lock().unwrap().clone()
    }
}

/// A call logger that drops entries — for tests and demos where no SQLite
/// logger is wired up.
pub struct NoopCallLogger;

impl CallLogger for NoopCallLogger {
    fn record(&self, _entry: CallLog) -> Result<(), LogError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    struct CapturingLogger(Mutex<Vec<CallLog>>);

    impl CallLogger for CapturingLogger {
        fn record(&self, entry: CallLog) -> Result<(), LogError> {
            self.0.lock().unwrap().push(entry);
            Ok(())
        }
    }

    #[test]
    fn cg28_events_are_mirrored_to_the_call_logger() {
        let logger = Arc::new(CapturingLogger(Mutex::new(Vec::new())));
        let audit = WorkflowAudit::new(logger.clone());
        let task = Uuid::new_v4();

        audit.record(WorkflowEventKind::Gate, task, &"human:dev".into(), "gate approved");
        audit.record(WorkflowEventKind::Hunt, task, &"human:dev".into(), "test survived");

        let logged = logger.0.lock().unwrap();
        assert_eq!(logged.len(), 2);
        assert_eq!(logged[0].provider, "workflow");
        assert_eq!(logged[0].model, "workflow.gate");
        assert_eq!(logged[1].model, "workflow.hunt");
        assert_eq!(logged[0].usage.input_tokens, 0);

        let trail = audit.snapshot();
        assert_eq!(trail.len(), 2);
        assert_eq!(trail[0].detail, "gate approved");
    }
}
