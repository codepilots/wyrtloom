/// The pre-digestion pipeline: parse → plan → execute → verify.
///
/// Security hardening (see CHANGELOG.md):
///   008 – LLM output is parsed as structured JSON rather than as a freeform
///         text prefix, preventing prompt-injection from forging DONE/BLOCKED
///         control signals.  The system prompt instructs the model to respond
///         with {"status":"done","result":"…"} or {"status":"blocked","reason":"…"}.
///   018 – All kanban operations return Result; panics from .expect() are
///         replaced by proper error handling that records a failed log entry
///         and returns PipelineOutcome::Blocked instead of crashing.
use plugin_workflow_conversation::gate::{GateEngine, GateOutcome};
use plugin_workflow_conversation::workflow::WorkflowProfile;
use std::sync::Arc;
use wyrtloom_core::escalation::{ActionOption, Escalation, HumanEscalation, HumanResponse};
use wyrtloom_core::kanban::{BlockReason, BlockedBy, KanbanBoard, NewTask, TaskState};
use wyrtloom_core::logger::{CallLog, CallLogger, CallOutcome};
use wyrtloom_core::profile::TaskProfile;
use wyrtloom_core::provider::{GenerationRequest, LlmProvider, Message};
use wyrtloom_core::types::{ActorId, TaskId, Timestamp};

/// Comprehension-first gating (SoftDevSpec addendum): when present, any
/// pipeline transition matching a gate in the workflow profile goes through
/// the gate engine — digest first, then the human's approval — instead of
/// transitioning directly.
pub struct GatedWorkflow {
    pub engine: GateEngine,
    pub profile: WorkflowProfile,
    /// The human who reads digests and answers gates.
    pub reader: ActorId,
    /// Typically `CalibrationLedger::overall_score()` for the reader.
    pub reader_calibration: f64,
}

pub struct Pipeline {
    pub kanban:     Arc<dyn KanbanBoard>,
    pub provider:   Arc<dyn LlmProvider>,
    pub logger:     Arc<dyn CallLogger>,
    pub escalation: Arc<dyn HumanEscalation>,
    pub profile:    TaskProfile,
    pub agent_id:   ActorId,
    pub gating:     Option<GatedWorkflow>,
}

/// Result of one pipeline transition, gated or direct.
enum Advance {
    Proceeded,
    Held(String),
    Stopped,
}

pub enum PipelineOutcome {
    Done    { task_id: TaskId, result: String },
    Stopped { task_id: TaskId },
    Blocked { task_id: TaskId, reason: String },
}

/// Structured response the LLM must emit (finding 008).
#[derive(serde::Deserialize)]
struct LlmResponse {
    status: String,
    result: Option<String>,
    reason: Option<String>,
}

/// Parse the LLM's structured JSON output.
/// Returns Ok((is_blocked, content)) or Err(parse_error_description).
///
/// Scans forward through all '{' positions so that prose containing braces
/// (e.g. "involves {retry logic}") before the actual JSON object does not
/// cause a false parse failure.
fn parse_llm_output(text: &str) -> Result<(bool, String), String> {
    let mut search = text;
    while let Some(offset) = search.find('{') {
        let candidate = &search[offset..];
        if let Ok(resp) = serde_json::from_str::<LlmResponse>(candidate) {
            return match resp.status.to_lowercase().as_str() {
                "done"    => Ok((false, resp.result.unwrap_or_default())),
                "blocked" => Ok((true,  resp.reason.unwrap_or_default())),
                other     => Err(format!("unknown status field: '{}'", other)),
            };
        }
        search = &search[offset + 1..];
    }
    Err("no valid JSON object found in response".into())
}

impl Pipeline {
    /// Run a single task through parse → plan → execute → verify.
    pub fn run(&self, title: &str, user_prompt: &str) -> PipelineOutcome {
        // ── parse: create task on the board (finding 018: no .expect()) ─────
        let task_id = match self.kanban.create(NewTask {
            title: title.to_string(),
            actor: self.agent_id.clone(),
            depends_on: vec![],
        }) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("[wyrtloom] failed to create task: {}", e);
                return PipelineOutcome::Blocked {
                    task_id: uuid::Uuid::nil(),
                    reason: format!("task creation failed: {}", e),
                };
            }
        };

        eprintln!("[wyrtloom] task {} created: {}", task_id, title);

        // backlog → todo → ready → claim → running
        // Every transition runs through advance(), which consults the
        // workflow gates when gating is configured.
        for (from, to, label) in [
            (TaskState::Backlog, TaskState::Todo,  "todo"),
            (TaskState::Todo,    TaskState::Ready, "ready"),
        ] {
            match self.advance(task_id, from, to, None) {
                Ok(Advance::Proceeded) => {}
                Ok(Advance::Held(reason)) => {
                    eprintln!("[wyrtloom] held at gate before {}: {}", label, reason);
                    return self.record_blocked(task_id, format!("held at gate: {}", reason));
                }
                Ok(Advance::Stopped) => return self.record_stopped(task_id),
                Err(e) => {
                    eprintln!("[wyrtloom] transition to {} failed: {}", label, e);
                    return self.record_blocked(task_id, format!("transition to {} failed", label));
                }
            }
        }

        if let Err(e) = self.kanban.claim(task_id, self.agent_id.clone()) {
            eprintln!("[wyrtloom] claim failed: {}", e);
            return self.record_blocked(task_id, format!("claim failed: {}", e));
        }

        match self.advance(task_id, TaskState::Ready, TaskState::Running, None) {
            Ok(Advance::Proceeded) => {}
            Ok(Advance::Held(reason)) => {
                eprintln!("[wyrtloom] held at gate before running: {}", reason);
                return self.record_blocked(task_id, format!("held at gate: {}", reason));
            }
            Ok(Advance::Stopped) => return self.record_stopped(task_id),
            Err(e) => {
                eprintln!("[wyrtloom] running transition failed: {}", e);
                return self.record_blocked(task_id, "running transition failed".into());
            }
        }

        eprintln!("[wyrtloom] task {} running", task_id);

        // ── plan: build a profile-scoped prompt ──────────────────────────────
        let messages = vec![
            Message::system(&self.profile.system_prompt),
            Message::user(user_prompt),
        ];
        let req = GenerationRequest {
            messages,
            max_output_tokens: self.profile.max_output_tokens,
            model: self.profile.model.clone(),
        };

        // ── execute: call the LLM ─────────────────────────────────────────────
        let (is_blocked, content) = match self.provider.generate(req) {
            Ok(resp) => {
                let raw = resp.full_text();
                eprintln!("[wyrtloom] LLM raw response: {}", raw);
                self.logger.record(self.make_call_log(
                    task_id, resp.usage, CallOutcome::Completed,
                )).ok();

                // ── verify: parse structured JSON output (finding 008) ─────
                match parse_llm_output(&raw) {
                    Ok(parsed) => parsed,
                    Err(parse_err) => {
                        eprintln!("[wyrtloom] could not parse LLM output: {}", parse_err);
                        // Treat unparseable output as blocked — don't assume success.
                        (true, format!("unparseable LLM output: {}", parse_err))
                    }
                }
            }
            Err(e) => {
                let reason = e.to_string();
                eprintln!("[wyrtloom] LLM error: {}", reason);
                self.logger.record(self.make_call_log(
                    task_id,
                    wyrtloom_core::provider::Usage { input_tokens: 0, output_tokens: 0, cost: None },
                    CallOutcome::Failed(reason.clone()),
                )).ok();
                (true, reason)
            }
        };

        if is_blocked {
            eprintln!("[wyrtloom] agent blocked: {}", content);
            return self.handle_blocked(task_id, title, content);
        }

        // ── success path ──────────────────────────────────────────────────────
        match self.advance(task_id, TaskState::Running, TaskState::Done, Some("completed".into())) {
            Ok(Advance::Proceeded) => {}
            Ok(Advance::Held(reason)) => {
                eprintln!("[wyrtloom] held at ship gate: {}", reason);
                return self.record_blocked(task_id, format!("held at ship gate: {}", reason));
            }
            Ok(Advance::Stopped) => return self.record_stopped(task_id),
            Err(e) => {
                eprintln!("[wyrtloom] done transition failed: {}", e);
            }
        }
        eprintln!("[wyrtloom] task {} done", task_id);
        PipelineOutcome::Done { task_id, result: content }
    }

    /// Move a task `from` → `to`. When a workflow gate guards this exact
    /// transition, passage goes through the gate engine — the digest is
    /// presented before the approval challenge, and the engine performs the
    /// kanban transition itself on approval. Ungated transitions go straight
    /// to the board.
    fn advance(
        &self,
        task_id: TaskId,
        from: TaskState,
        to: TaskState,
        reason: Option<String>,
    ) -> Result<Advance, String> {
        if let Some(gating) = &self.gating {
            if let Some(gate) =
                gating.profile.gates.iter().find(|g| g.from == from && g.to == to)
            {
                return match gating.engine.request_passage(
                    task_id,
                    gate,
                    &gating.reader,
                    gating.reader_calibration,
                    &[],
                    false,
                ) {
                    Ok(GateOutcome::Approved { .. }) => Ok(Advance::Proceeded),
                    Ok(GateOutcome::Held { reason }) => Ok(Advance::Held(reason)),
                    Ok(GateOutcome::Stopped) => Ok(Advance::Stopped),
                    Err(e) => Err(e.to_string()),
                };
            }
        }
        self.kanban
            .transition(task_id, to, self.agent_id.clone(), reason)
            .map(|_| Advance::Proceeded)
            .map_err(|e| e.to_string())
    }

    fn record_stopped(&self, task_id: TaskId) -> PipelineOutcome {
        let human = self
            .gating
            .as_ref()
            .map(|g| g.reader.clone())
            .unwrap_or_else(|| "human:cli".into());
        self.kanban.block(
            task_id,
            self.agent_id.clone(),
            BlockReason {
                reason: "stopped by human at gate".into(),
                blocked_by: BlockedBy::Human(human),
            },
        ).ok();
        PipelineOutcome::Stopped { task_id }
    }

    fn handle_blocked(&self, task_id: TaskId, title: &str, reason: String) -> PipelineOutcome {
        // Sanitize reason before displaying to human (finding 007 carried through).
        // The Ollama provider already strips ANSI; this is a defence-in-depth layer.
        let safe_reason: String = reason.chars()
            .filter(|&c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
            .collect();

        let escalation = Escalation {
            task: task_id,
            prompt: format!(
                "Agent is blocked on task '{}'.\nReason: {}\n\nHow should we proceed?",
                title, safe_reason
            ),
            options: vec![
                ActionOption {
                    id: "retry".into(),
                    label: "Retry".into(),
                    description: Some("Try the task again".into()),
                },
                ActionOption {
                    id: "skip".into(),
                    label: "Skip".into(),
                    description: Some("Mark done and move on".into()),
                },
            ],
        };

        match self.escalation.escalate(escalation) {
            Ok(HumanResponse::Stop) => {
                self.kanban.block(
                    task_id,
                    self.agent_id.clone(),
                    BlockReason {
                        reason: "stopped by human".into(),
                        blocked_by: BlockedBy::Human("human:cli".into()),
                    },
                ).ok();
                PipelineOutcome::Stopped { task_id }
            }
            Ok(HumanResponse::Chose(ref id)) if id == "skip" => {
                // Skip bypasses the ship gate by design: the human just made
                // this exact call through the escalation interface, and a
                // second challenge would gate their own decision.
                self.kanban.transition(
                    task_id, TaskState::Done, self.agent_id.clone(), Some("skipped".into())
                ).ok();
                PipelineOutcome::Done { task_id, result: "skipped by human".into() }
            }
            Ok(_) => {
                self.record_blocked(task_id, reason)
            }
            Err(_) => {
                self.record_blocked(task_id, "escalation failed".into())
            }
        }
    }

    fn make_call_log(
        &self,
        task_id: TaskId,
        usage: wyrtloom_core::provider::Usage,
        outcome: CallOutcome,
    ) -> CallLog {
        CallLog {
            task: task_id,
            profile: self.profile.id.clone(),
            provider: self.profile.provider.clone(),
            model: self.profile.model.clone(),
            usage,
            outcome,
            at: Timestamp::now(),
        }
    }

    fn record_blocked(&self, task_id: TaskId, reason: String) -> PipelineOutcome {
        self.kanban.block(
            task_id,
            self.agent_id.clone(),
            BlockReason {
                reason: reason.clone(),
                blocked_by: BlockedBy::Human("human:cli".into()),
            },
        ).ok();
        PipelineOutcome::Blocked { task_id, reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_escalation_cli::ScriptedEscalation;
    use plugin_kanban_sqlite::SqliteKanbanBoard;
    use plugin_workflow_conversation::audit::{NoopCallLogger, WorkflowAudit};
    use wyrtloom_core::provider::{
        ContentBlock, GenerationResponse, ModelDescriptor, ProviderError, Usage,
    };

    /// A provider that always answers with the given text — no network.
    struct ScriptedProvider(String);

    impl LlmProvider for ScriptedProvider {
        fn generate(&self, _req: GenerationRequest) -> Result<GenerationResponse, ProviderError> {
            Ok(GenerationResponse {
                content: vec![ContentBlock::Text(self.0.clone())],
                usage: Usage { input_tokens: 1, output_tokens: 1, cost: None },
            })
        }
        fn models(&self) -> Vec<ModelDescriptor> {
            vec![]
        }
    }

    const DONE_JSON: &str = r#"{"status":"done","result":"4"}"#;

    fn pipeline(
        board: Arc<SqliteKanbanBoard>,
        gating: Option<GatedWorkflow>,
    ) -> Pipeline {
        Pipeline {
            kanban: board,
            provider: Arc::new(ScriptedProvider(DONE_JSON.into())),
            logger: Arc::new(NoopCallLogger),
            escalation: Arc::new(ScriptedEscalation::stop()),
            profile: TaskProfile::default_v01(),
            agent_id: "agent:test".into(),
            gating,
        }
    }

    fn gating(board: Arc<SqliteKanbanBoard>, gate_response: HumanResponse) -> GatedWorkflow {
        struct Scripted(HumanResponse);
        impl HumanEscalation for Scripted {
            fn escalate(
                &self,
                _e: Escalation,
            ) -> Result<HumanResponse, wyrtloom_core::escalation::EscalationError> {
                Ok(self.0.clone())
            }
        }
        GatedWorkflow {
            engine: GateEngine {
                kanban: board,
                escalation: Arc::new(Scripted(gate_response)),
                audit: WorkflowAudit::new(Arc::new(NoopCallLogger)),
            },
            profile: WorkflowProfile::conversation_v01("human:owner".into()),
            reader: "human:reader".into(),
            reader_calibration: 0.0,
        }
    }

    #[test]
    fn ungated_pipeline_completes_as_before() {
        let board = Arc::new(SqliteKanbanBoard::in_memory().unwrap());
        let p = pipeline(board.clone(), None);
        match p.run("demo", "2+2?") {
            PipelineOutcome::Done { task_id, result } => {
                assert_eq!(result, "4");
                let task = board.get(task_id).unwrap();
                assert_eq!(task.state, TaskState::Done);
            }
            other => panic!("expected Done, got {:?}", outcome_name(&other)),
        }
    }

    #[test]
    fn gated_pipeline_passes_both_gates_to_done() {
        let board = Arc::new(SqliteKanbanBoard::in_memory().unwrap());
        let g = gating(board.clone(), HumanResponse::Chose("approve".into()));
        let p = pipeline(board.clone(), Some(g));

        match p.run("demo", "2+2?") {
            PipelineOutcome::Done { task_id, .. } => {
                let task = board.get(task_id).unwrap();
                assert_eq!(task.state, TaskState::Done);
                // The board history shows both gate approvals, stamped by
                // the human reader, not the agent.
                let reasons: Vec<String> = task
                    .history
                    .iter()
                    .filter_map(|h| h.reason.clone())
                    .collect();
                assert!(reasons.iter().any(|r| r.contains("gate 'design-review' approved")));
                assert!(reasons.iter().any(|r| r.contains("gate 'ship-review' approved")));
                let gate_actors: Vec<&str> = task
                    .history
                    .iter()
                    .filter(|h| h.reason.as_deref().map_or(false, |r| r.contains("gate")))
                    .map(|h| h.actor.as_str())
                    .collect();
                assert!(gate_actors.iter().all(|a| *a == "human:reader"));
            }
            other => panic!("expected Done, got {:?}", outcome_name(&other)),
        }
    }

    #[test]
    fn gated_pipeline_holds_at_the_design_gate() {
        let board = Arc::new(SqliteKanbanBoard::in_memory().unwrap());
        let g = gating(board.clone(), HumanResponse::Chose("hold".into()));
        let p = pipeline(board.clone(), Some(g));

        match p.run("demo", "2+2?") {
            PipelineOutcome::Blocked { task_id, reason } => {
                assert!(reason.contains("held at gate"));
                // The gate never opened: the task did not reach Running.
                let task = board.get(task_id).unwrap();
                assert_ne!(task.state, TaskState::Running);
                assert_ne!(task.state, TaskState::Done);
            }
            other => panic!("expected Blocked, got {:?}", outcome_name(&other)),
        }
    }

    #[test]
    fn gated_pipeline_stops_when_the_human_stops_the_gate() {
        let board = Arc::new(SqliteKanbanBoard::in_memory().unwrap());
        let g = gating(board.clone(), HumanResponse::Stop);
        let p = pipeline(board.clone(), Some(g));
        assert!(matches!(p.run("demo", "2+2?"), PipelineOutcome::Stopped { .. }));
    }

    fn outcome_name(o: &PipelineOutcome) -> &'static str {
        match o {
            PipelineOutcome::Done { .. } => "Done",
            PipelineOutcome::Stopped { .. } => "Stopped",
            PipelineOutcome::Blocked { .. } => "Blocked",
        }
    }
}
