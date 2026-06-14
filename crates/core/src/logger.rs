use crate::provider::Usage;
use crate::types::{ModelId, ProfileId, TaskId, Timestamp};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallOutcome {
    Completed,
    Failed(String),
    Partial(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallLog {
    pub task: TaskId,
    pub profile: ProfileId,
    pub provider: String,
    pub model: ModelId,
    pub usage: Usage,
    pub outcome: CallOutcome,
    pub at: Timestamp,
}

#[derive(Error, Debug)]
pub enum LogError {
    #[error("storage failure: {0}")]
    Storage(String),
}

/// Every LLM call must produce a log entry — the raw material for the
/// future ML tuner.  Failed or partial calls are logged, never silently dropped.
pub trait CallLogger: Send + Sync {
    fn record(&self, entry: CallLog) -> Result<(), LogError>;

    /// Return all recorded call logs. Implementations that do not retain
    /// readable history (e.g. write-only sinks) return an empty vec by default.
    fn all_logs(&self) -> Result<Vec<CallLog>, LogError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Usage;
    use uuid::Uuid;

    fn sample_log() -> CallLog {
        CallLog {
            task: Uuid::new_v4(),
            profile: "default".into(),
            provider: "ollama".into(),
            model: "llama3.2".into(),
            usage: Usage { input_tokens: 50, output_tokens: 100, cost: None },
            outcome: CallOutcome::Completed,
            at: Timestamp::now(),
        }
    }

    #[test]
    fn call_log_has_all_required_fields() {
        let log = sample_log();
        assert!(!log.provider.is_empty());
        assert!(!log.model.is_empty());
        assert_eq!(log.usage.input_tokens, 50);
        assert_eq!(log.usage.output_tokens, 100);
    }

    #[test]
    fn failed_call_is_expressible() {
        let mut log = sample_log();
        log.outcome = CallOutcome::Failed("network timeout".into());
        assert!(matches!(log.outcome, CallOutcome::Failed(_)));
    }

    #[test]
    fn partial_call_is_expressible() {
        let mut log = sample_log();
        log.outcome = CallOutcome::Partial("truncated at token limit".into());
        assert!(matches!(log.outcome, CallOutcome::Partial(_)));
    }

    #[test]
    fn cost_is_nullable() {
        let log = sample_log();
        assert!(log.usage.cost.is_none());
    }
}
