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
use std::sync::Arc;
use wyrtloom_core::escalation::{ActionOption, Escalation, HumanEscalation, HumanResponse};
use wyrtloom_core::kanban::{BlockReason, BlockedBy, KanbanBoard, NewTask, TaskState};
use wyrtloom_core::logger::{CallLog, CallLogger, CallOutcome};
use wyrtloom_core::profile::TaskProfile;
use wyrtloom_core::provider::{GenerationRequest, LlmProvider, Message};
use wyrtloom_core::types::{ActorId, TaskId, Timestamp};

pub struct Pipeline {
    pub kanban:     Arc<dyn KanbanBoard>,
    pub provider:   Arc<dyn LlmProvider>,
    pub logger:     Arc<dyn CallLogger>,
    pub escalation: Arc<dyn HumanEscalation>,
    pub profile:    TaskProfile,
    pub agent_id:   ActorId,
}

pub enum PipelineOutcome {
    Done    { task_id: TaskId, result: String },
    Stopped { task_id: TaskId },
    Blocked { task_id: TaskId, reason: String },
}

/// Whether verbose debug logging (full model output, parse errors, blocked
/// content) is enabled. Gated behind `WYRTLOOM_DEBUG` so model output is not
/// dumped to stderr in normal operation.
fn debug_enabled() -> bool {
    std::env::var_os("WYRTLOOM_DEBUG").is_some()
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
        for (next_state, label) in [
            (TaskState::Todo,    "todo"),
            (TaskState::Ready,   "ready"),
        ] {
            if let Err(e) = self.kanban.transition(
                task_id, next_state, self.agent_id.clone(), None
            ) {
                eprintln!("[wyrtloom] transition to {} failed: {}", label, e);
                return self.record_blocked(task_id, format!("transition to {} failed", label));
            }
        }

        if let Err(e) = self.kanban.claim(task_id, self.agent_id.clone()) {
            eprintln!("[wyrtloom] claim failed: {}", e);
            return self.record_blocked(task_id, format!("claim failed: {}", e));
        }

        if let Err(e) = self.kanban.transition(
            task_id, TaskState::Running, self.agent_id.clone(), None
        ) {
            eprintln!("[wyrtloom] running transition failed: {}", e);
            return self.record_blocked(task_id, "running transition failed".into());
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
                // The full model output can carry sensitive/untrusted content;
                // only dump it when explicitly debugging (WYRTLOOM_DEBUG set).
                if debug_enabled() {
                    eprintln!("[wyrtloom] LLM raw response: {}", raw);
                }
                self.logger.record(self.make_call_log(
                    task_id, resp.usage, CallOutcome::Completed,
                )).ok();

                // ── verify: parse structured JSON output (finding 008) ─────
                match parse_llm_output(&raw) {
                    Ok(parsed) => parsed,
                    Err(parse_err) => {
                        if debug_enabled() {
                            eprintln!("[wyrtloom] could not parse LLM output: {}", parse_err);
                        }
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
            // `content` is model-derived; only echo it under WYRTLOOM_DEBUG.
            if debug_enabled() {
                eprintln!("[wyrtloom] agent blocked: {}", content);
            }
            return self.handle_blocked(task_id, title, content);
        }

        // ── success path ──────────────────────────────────────────────────────
        if let Err(e) = self.kanban.transition(
            task_id, TaskState::Done, self.agent_id.clone(), Some("completed".into())
        ) {
            eprintln!("[wyrtloom] done transition failed: {}", e);
        }
        eprintln!("[wyrtloom] task {} done", task_id);
        PipelineOutcome::Done { task_id, result: content }
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
