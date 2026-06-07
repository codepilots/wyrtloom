use crate::types::TaskId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionOption {
    pub id: String,
    pub label: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Escalation {
    pub task: TaskId,
    pub prompt: String,
    /// Suggested actions shown as buttons in the Phase 2 UI.
    /// Free-text and stop are ALWAYS implicitly available.
    pub options: Vec<ActionOption>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HumanResponse {
    Chose(String),       // ActionOption.id
    FreeText(String),
    Stop,
}

#[derive(Error, Debug)]
pub enum EscalationError {
    #[error("escalation was interrupted")]
    Interrupted,
    #[error("io error: {0}")]
    Io(String),
}

/// Interface contract for routing a decision to a human.
/// Designed now to accommodate the Phase 2 graphical UI without interface change:
/// options → buttons, free-text → text field, stop → stop button.
pub trait HumanEscalation: Send + Sync {
    fn escalate(&self, e: Escalation) -> Result<HumanResponse, EscalationError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample_escalation() -> Escalation {
        Escalation {
            task: Uuid::new_v4(),
            prompt: "The agent is unsure how to proceed. Please advise.".into(),
            options: vec![
                ActionOption { id: "retry".into(), label: "Retry".into(), description: None },
                ActionOption {
                    id: "skip".into(),
                    label: "Skip task".into(),
                    description: Some("Mark as done without output".into()),
                },
            ],
        }
    }

    #[test]
    fn escalation_has_prompt_and_options() {
        let e = sample_escalation();
        assert!(!e.prompt.is_empty());
        assert!(!e.options.is_empty());
    }

    #[test]
    fn human_response_variants_cover_contract() {
        // Chose an option
        let r = HumanResponse::Chose("retry".into());
        assert!(matches!(r, HumanResponse::Chose(_)));

        // Free text
        let r = HumanResponse::FreeText("please try a different approach".into());
        assert!(matches!(r, HumanResponse::FreeText(_)));

        // Stop
        let r = HumanResponse::Stop;
        assert!(matches!(r, HumanResponse::Stop));
    }

    #[test]
    fn escalation_can_have_zero_options_still_offers_freetext_and_stop() {
        // Even an escalation with no suggested options must be expressible;
        // the human always has free-text and stop.
        let e = Escalation {
            task: Uuid::new_v4(),
            prompt: "Unknown state — what should I do?".into(),
            options: vec![],
        };
        assert_eq!(e.options.len(), 0);
    }
}
