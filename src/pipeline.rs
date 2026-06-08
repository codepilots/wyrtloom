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

/// Maximum number of LLM attempts for a single task, including human-requested
/// retries.  Bounds the retry loop so escalation can never spin forever (C3).
const MAX_ATTEMPTS: usize = 3;

/// A human's decision when an agent is blocked, decoupled from the kanban
/// side effects the run-loop performs in response.
enum Resolution {
    /// Halt the task and record it as stopped.
    Stop,
    /// Mark the task done without further work.
    Skip,
    /// Re-run the task with the same context.
    Retry,
    /// Re-run the task with additional human guidance appended.
    Guidance(String),
    /// No actionable response — block the task.
    Abandon,
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
/// cause a false parse failure.  At each position a *streaming* deserialiser is
/// used (C2) so that a valid JSON object followed by trailing prose
/// (e.g. `{"status":"done","result":"4"} thanks!`) still parses — plain
/// `serde_json::from_str` rejects any trailing non-whitespace.
fn parse_llm_output(text: &str) -> Result<(bool, String), String> {
    let mut search = text;
    while let Some(offset) = search.find('{') {
        let candidate = &search[offset..];
        let mut stream = serde_json::Deserializer::from_str(candidate)
            .into_iter::<LlmResponse>();
        if let Some(Ok(resp)) = stream.next() {
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
        // The conversation grows across retries: human free-text guidance is
        // appended as additional context before re-running (C3).
        let mut messages = vec![
            Message::system(&self.profile.system_prompt),
            Message::user(user_prompt),
        ];

        let mut attempt = 0usize;
        loop {
            attempt += 1;

            // ── execute + verify ─────────────────────────────────────────────
            let (is_blocked, content) = self.execute(task_id, &messages);

            if !is_blocked {
                // ── success path (C5: a failed Done transition is an error,
                // not a silently-Done task) ──────────────────────────────────
                if let Err(e) = self.kanban.transition(
                    task_id, TaskState::Done, self.agent_id.clone(), Some("completed".into())
                ) {
                    eprintln!("[wyrtloom] done transition failed: {}", e);
                    return self.record_blocked(task_id, format!("done transition failed: {}", e));
                }
                eprintln!("[wyrtloom] task {} done", task_id);
                return PipelineOutcome::Done { task_id, result: content };
            }

            eprintln!("[wyrtloom] agent blocked: {}", content);

            // ── escalate and act on the human's decision (C3) ────────────────
            match self.escalate_blocked(task_id, title, &content) {
                Resolution::Stop => {
                    self.kanban.block(
                        task_id,
                        self.agent_id.clone(),
                        BlockReason {
                            reason: "stopped by human".into(),
                            blocked_by: BlockedBy::Human("human:cli".into()),
                        },
                    ).ok();
                    return PipelineOutcome::Stopped { task_id };
                }
                Resolution::Skip => {
                    if let Err(e) = self.kanban.transition(
                        task_id, TaskState::Done, self.agent_id.clone(), Some("skipped".into())
                    ) {
                        return self.record_blocked(task_id, format!("skip transition failed: {}", e));
                    }
                    return PipelineOutcome::Done {
                        task_id,
                        result: "skipped by human".into(),
                    };
                }
                Resolution::Retry if attempt < MAX_ATTEMPTS => {
                    eprintln!("[wyrtloom] retrying task {} (attempt {})", task_id, attempt + 1);
                    continue;
                }
                Resolution::Guidance(text) if attempt < MAX_ATTEMPTS => {
                    eprintln!("[wyrtloom] retrying task {} with human guidance", task_id);
                    messages.push(Message::user(format!("Human guidance: {}", text)));
                    continue;
                }
                // Retries exhausted: the guards above failed because attempt has
                // hit MAX_ATTEMPTS.  Record a reason that distinguishes this from
                // a never-escalated block.
                Resolution::Retry | Resolution::Guidance(_) => {
                    return self.record_blocked(
                        task_id,
                        format!(
                            "retry budget exhausted after {} attempts; last reason: {}",
                            attempt, content
                        ),
                    );
                }
                // Escalation failed or the human gave an unrecognised response.
                Resolution::Abandon => {
                    return self.record_blocked(
                        task_id,
                        format!("escalation produced no actionable response; agent reason: {}", content),
                    );
                }
            }
        }
    }

    /// Execute one LLM round and verify its output.
    /// Returns `(is_blocked, content)` — `content` is the result on success or
    /// the block reason otherwise.  Every call is logged (finding 008/018).
    fn execute(&self, task_id: TaskId, messages: &[Message]) -> (bool, String) {
        let req = GenerationRequest {
            messages: messages.to_vec(),
            max_output_tokens: self.profile.max_output_tokens,
            model: self.profile.model.clone(),
        };

        match self.provider.generate(req) {
            Ok(resp) => {
                let raw = resp.full_text();
                eprintln!("[wyrtloom] LLM raw response: {}", raw);
                self.logger.record(self.make_call_log(
                    task_id, resp.usage, CallOutcome::Completed,
                )).ok();

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
        }
    }

    /// Present the block to a human and translate their response into a
    /// `Resolution` the run-loop acts on.  Kanban side effects live in `run`.
    fn escalate_blocked(&self, task_id: TaskId, title: &str, reason: &str) -> Resolution {
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
            Ok(HumanResponse::Stop) => Resolution::Stop,
            Ok(HumanResponse::Chose(id)) if id == "skip" => Resolution::Skip,
            Ok(HumanResponse::Chose(id)) if id == "retry" => Resolution::Retry,
            Ok(HumanResponse::FreeText(text)) => Resolution::Guidance(text),
            // Unrecognised option or escalation error — give up cleanly.
            Ok(HumanResponse::Chose(_)) | Err(_) => Resolution::Abandon,
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
    use super::parse_llm_output;

    #[test]
    fn parses_clean_done_object() {
        let (blocked, content) = parse_llm_output(r#"{"status":"done","result":"4"}"#).unwrap();
        assert!(!blocked);
        assert_eq!(content, "4");
    }

    #[test]
    fn parses_blocked_object() {
        let (blocked, content) =
            parse_llm_output(r#"{"status":"blocked","reason":"need a key"}"#).unwrap();
        assert!(blocked);
        assert_eq!(content, "need a key");
    }

    // C2 — a valid object followed by trailing prose must still parse.
    #[test]
    fn parses_object_with_trailing_text() {
        let (blocked, content) =
            parse_llm_output(r#"{"status":"done","result":"4"} Hope that helps!"#).unwrap();
        assert!(!blocked);
        assert_eq!(content, "4");
    }

    // CR-03 — leading prose containing braces must not break parsing.
    #[test]
    fn parses_object_after_leading_prose() {
        let text = r#"Sure, this involves {some thought}. {"status":"done","result":"ok"}"#;
        let (blocked, content) = parse_llm_output(text).unwrap();
        assert!(!blocked);
        assert_eq!(content, "ok");
    }

    #[test]
    fn unknown_status_is_an_error() {
        assert!(parse_llm_output(r#"{"status":"maybe"}"#).is_err());
    }

    #[test]
    fn no_json_object_is_an_error() {
        assert!(parse_llm_output("just plain text, no json here").is_err());
    }
}
