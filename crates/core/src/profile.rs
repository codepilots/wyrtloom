use crate::types::{ModelId, ProfileId};
use serde::{Deserialize, Serialize};

/// A task profile shapes an agent's execution environment.
/// v0.1 uses a single hard-coded profile; Phase 5 makes this fully configurable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskProfile {
    pub id: ProfileId,
    pub model: ModelId,
    pub max_output_tokens: u32,
    pub system_prompt: String,
    /// Names of tools the agent is allowed to use.
    pub allowed_tools: Vec<String>,
    /// Maximum context messages to include (older messages are dropped).
    pub max_context_messages: usize,
    /// If the agent is uncertain, escalate rather than guess.
    pub escalation_threshold: EscalationThreshold,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationThreshold {
    /// Always try to complete; only escalate when truly stuck.
    Low,
    /// Escalate when confidence is moderate-or-below.
    Medium,
    /// Escalate at the first sign of uncertainty.
    High,
}

impl TaskProfile {
    /// The single hard-coded profile for v0.1.
    pub fn default_v01() -> Self {
        Self {
            id: "default".into(),
            model: "llama3.2".into(),
            max_output_tokens: 512,
            system_prompt: concat!(
                "You are Wyrtloom, a focused task-execution agent. ",
                "Complete the requested task concisely. ",
                "If you are genuinely blocked, say BLOCKED:<reason>. ",
                "Otherwise, say DONE:<result>."
            ).into(),
            allowed_tools: vec![],
            max_context_messages: 10,
            escalation_threshold: EscalationThreshold::Medium,
        }
    }
}
