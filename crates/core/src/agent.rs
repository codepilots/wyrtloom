use crate::types::{Bytes, TaskId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Typed vocabulary for agent-to-agent communication.
/// Hop counter and origin task id are present and validated in v0.1;
/// hop-limit enforcement and cycle detection arrive in Phase 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMessage {
    Request    { origin_task: TaskId, hops: u8, body: Bytes },
    Response   { origin_task: TaskId, hops: u8, body: Bytes },
    Delegation { origin_task: TaskId, hops: u8, body: Bytes },
    Result     { origin_task: TaskId, hops: u8, body: Bytes },
    Error      { origin_task: TaskId, hops: u8, error: String },
}

#[derive(Error, Debug)]
pub enum MessageError {
    #[error("message is malformed: {0}")]
    Malformed(String),
    #[error("unknown message type")]
    UnknownType,
}

impl AgentMessage {
    pub fn origin_task(&self) -> TaskId {
        match self {
            AgentMessage::Request    { origin_task, .. } => *origin_task,
            AgentMessage::Response   { origin_task, .. } => *origin_task,
            AgentMessage::Delegation { origin_task, .. } => *origin_task,
            AgentMessage::Result     { origin_task, .. } => *origin_task,
            AgentMessage::Error      { origin_task, .. } => *origin_task,
        }
    }

    pub fn hops(&self) -> u8 {
        match self {
            AgentMessage::Request    { hops, .. } => *hops,
            AgentMessage::Response   { hops, .. } => *hops,
            AgentMessage::Delegation { hops, .. } => *hops,
            AgentMessage::Result     { hops, .. } => *hops,
            AgentMessage::Error      { hops, .. } => *hops,
        }
    }

    /// Validate the message is well-formed.
    pub fn validate(&self) -> Result<(), MessageError> {
        match self {
            AgentMessage::Error { error, .. } if error.is_empty() => {
                Err(MessageError::Malformed("error messages must have a non-empty error".into()))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn task() -> TaskId { Uuid::new_v4() }

    #[test]
    fn all_message_variants_carry_origin_task_and_hops() {
        let id = task();
        let messages = vec![
            AgentMessage::Request    { origin_task: id, hops: 0, body: vec![] },
            AgentMessage::Response   { origin_task: id, hops: 1, body: vec![] },
            AgentMessage::Delegation { origin_task: id, hops: 2, body: vec![] },
            AgentMessage::Result     { origin_task: id, hops: 3, body: vec![] },
            AgentMessage::Error      { origin_task: id, hops: 4, error: "oops".into() },
        ];
        for (i, msg) in messages.iter().enumerate() {
            assert_eq!(msg.origin_task(), id);
            assert_eq!(msg.hops(), i as u8);
        }
    }

    #[test]
    fn valid_messages_pass_validation() {
        let id = task();
        let m = AgentMessage::Request { origin_task: id, hops: 0, body: b"hello".to_vec() };
        assert!(m.validate().is_ok());
    }

    #[test]
    fn error_message_with_empty_error_is_malformed() {
        let id = task();
        let m = AgentMessage::Error { origin_task: id, hops: 0, error: "".into() };
        assert!(matches!(m.validate(), Err(MessageError::Malformed(_))));
    }

    #[test]
    fn messages_are_serialisable() {
        let id = task();
        let m = AgentMessage::Request { origin_task: id, hops: 0, body: vec![1, 2, 3] };
        let json = serde_json::to_string(&m).unwrap();
        let decoded: AgentMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.origin_task(), id);
    }
}
