/// The pre-digestion pipeline: parse → plan → execute → verify
/// Deterministic work first; LLM only at the execute step.
use std::sync::Arc;
use wyrtloom_core::escalation::{ActionOption, Escalation, HumanEscalation, HumanResponse};
use wyrtloom_core::kanban::{BlockReason, BlockedBy, KanbanBoard, NewTask, TaskState};
use wyrtloom_core::logger::{CallLog, CallLogger, CallOutcome};
use wyrtloom_core::profile::TaskProfile;
use wyrtloom_core::provider::{GenerationRequest, LlmProvider, Message};
use wyrtloom_core::types::{ActorId, TaskId, Timestamp};

pub struct Pipeline {
    pub kanban:    Arc<dyn KanbanBoard>,
    pub provider:  Arc<dyn LlmProvider>,
    pub logger:    Arc<dyn CallLogger>,
    pub escalation: Arc<dyn HumanEscalation>,
    pub profile:   TaskProfile,
    pub agent_id:  ActorId,
}

pub enum PipelineOutcome {
    Done { task_id: TaskId, result: String },
    Stopped { task_id: TaskId },
    Blocked { task_id: TaskId, reason: String },
}

impl Pipeline {
    /// Run a single task through parse → plan → execute → verify.
    pub fn run(&self, title: &str, user_prompt: &str) -> PipelineOutcome {
        // --- parse: create task on the board ---
        let task_id = self
            .kanban
            .create(NewTask {
                title: title.to_string(),
                actor: self.agent_id.clone(),
                depends_on: vec![],
            })
            .expect("failed to create task");

        eprintln!("[wyrtloom] task {} created: {}", task_id, title);

        // backlog → todo → ready
        self.kanban
            .transition(task_id, TaskState::Todo, self.agent_id.clone(), None)
            .expect("todo transition");
        self.kanban
            .transition(task_id, TaskState::Ready, self.agent_id.clone(), None)
            .expect("ready transition");
        self.kanban
            .claim(task_id, self.agent_id.clone())
            .expect("claim task");
        self.kanban
            .transition(task_id, TaskState::Running, self.agent_id.clone(), None)
            .expect("running transition");

        eprintln!("[wyrtloom] task {} running", task_id);

        // --- plan: build a minimal, profile-scoped prompt ---
        let messages = vec![
            Message::system(&self.profile.system_prompt),
            Message::user(user_prompt),
        ];

        let req = GenerationRequest {
            messages,
            max_output_tokens: self.profile.max_output_tokens,
            model: self.profile.model.clone(),
        };

        // --- execute: call the LLM ---
        let (_outcome, text) = match self.provider.generate(req) {
            Ok(resp) => {
                let text = resp.full_text();
                let log = CallLog {
                    task: task_id,
                    profile: self.profile.id.clone(),
                    provider: "ollama".into(),
                    model: self.profile.model.clone(),
                    usage: resp.usage,
                    outcome: CallOutcome::Completed,
                    at: Timestamp::now(),
                };
                self.logger.record(log).ok();
                (CallOutcome::Completed, text)
            }
            Err(e) => {
                let err_str = e.to_string();
                let log = CallLog {
                    task: task_id,
                    profile: self.profile.id.clone(),
                    provider: "ollama".into(),
                    model: self.profile.model.clone(),
                    usage: wyrtloom_core::provider::Usage {
                        input_tokens: 0,
                        output_tokens: 0,
                        cost: None,
                    },
                    outcome: CallOutcome::Failed(err_str.clone()),
                    at: Timestamp::now(),
                };
                self.logger.record(log).ok();
                (CallOutcome::Failed(err_str.clone()), format!("BLOCKED:{}", err_str))
            }
        };

        eprintln!("[wyrtloom] LLM response: {}", text);

        // --- verify: interpret the response ---
        if text.starts_with("BLOCKED:") {
            let reason = text.trim_start_matches("BLOCKED:").trim().to_string();
            eprintln!("[wyrtloom] agent blocked: {}", reason);

            // Escalate to human
            let escalation = Escalation {
                task: task_id,
                prompt: format!(
                    "Agent is blocked on task '{}'.\nReason: {}\n\nHow should we proceed?",
                    title, reason
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
                    self.kanban
                        .block(
                            task_id,
                            self.agent_id.clone(),
                            BlockReason {
                                reason: "stopped by human".into(),
                                blocked_by: BlockedBy::Human("human:cli".into()),
                            },
                        )
                        .ok();
                    return PipelineOutcome::Stopped { task_id };
                }
                Ok(HumanResponse::Chose(ref id)) if id == "skip" => {
                    self.kanban
                        .transition(task_id, TaskState::Done, self.agent_id.clone(), Some("skipped".into()))
                        .ok();
                    return PipelineOutcome::Done {
                        task_id,
                        result: "skipped by human".into(),
                    };
                }
                Ok(_) => {
                    // Any other response (retry / free text) — record as blocked.
                    self.kanban
                        .block(
                            task_id,
                            self.agent_id.clone(),
                            BlockReason {
                                reason,
                                blocked_by: BlockedBy::Human("human:cli".into()),
                            },
                        )
                        .ok();
                    return PipelineOutcome::Blocked { task_id, reason: text };
                }
                Err(_) => {
                    self.kanban
                        .block(
                            task_id,
                            self.agent_id.clone(),
                            BlockReason {
                                reason: "escalation failed".into(),
                                blocked_by: BlockedBy::Human("human:cli".into()),
                            },
                        )
                        .ok();
                    return PipelineOutcome::Blocked {
                        task_id,
                        reason: "escalation failed".into(),
                    };
                }
            }
        }

        // Success path
        let result = text.trim_start_matches("DONE:").trim().to_string();
        self.kanban
            .transition(task_id, TaskState::Done, self.agent_id.clone(), Some("completed".into()))
            .ok();

        eprintln!("[wyrtloom] task {} done", task_id);
        PipelineOutcome::Done { task_id, result }
    }
}
