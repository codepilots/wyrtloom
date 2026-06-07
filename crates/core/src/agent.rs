/// Agent message contracts.
///
/// Security hardening (see CHANGELOG.md):
///   016 – validate() now enforces MAX_HOPS (16) and MAX_BODY_BYTES (1 MiB)
///         to prevent message-loop DoS and oversized-payload attacks.
use crate::types::{Bytes, TaskId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum number of hops before a message is considered a loop.
pub const MAX_HOPS: u8 = 16;

/// Maximum body size in bytes (1 MiB).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Typed vocabulary for agent-to-agent communication.
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
    /// Enforces hop limit and body size to prevent loop-based DoS.
    pub fn validate(&self) -> Result<(), MessageError> {
        // Hop limit — enforced now, not deferred to Phase 2 (finding 016).
        if self.hops() >= MAX_HOPS {
            return Err(MessageError::Malformed(format!(
                "hop limit exceeded: {} >= {}",
                self.hops(), MAX_HOPS
            )));
        }

        match self {
            AgentMessage::Error { error, .. } if error.is_empty() => {
                return Err(MessageError::Malformed(
                    "error messages must have a non-empty error field".into(),
                ));
            }
            // Body size check for message variants that carry a body.
            AgentMessage::Request    { body, .. }
            | AgentMessage::Response   { body, .. }
            | AgentMessage::Delegation { body, .. }
            | AgentMessage::Result     { body, .. }
                if body.len() > MAX_BODY_BYTES =>
            {
                return Err(MessageError::Malformed(format!(
                    "body too large: {} bytes > {} limit",
                    body.len(), MAX_BODY_BYTES
                )));
            }
            _ => {}
        }
        Ok(())
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
        let messages = [
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
        let m = AgentMessage::Request { origin_task: task(), hops: 0, body: b"hello".to_vec() };
        assert!(m.validate().is_ok());
    }

    #[test]
    fn error_message_with_empty_error_is_malformed() {
        let m = AgentMessage::Error { origin_task: task(), hops: 0, error: "".into() };
        assert!(matches!(m.validate(), Err(MessageError::Malformed(_))));
    }

    // 016 — hop limit
    #[test]
    fn message_at_hop_limit_is_malformed() {
        let m = AgentMessage::Request { origin_task: task(), hops: MAX_HOPS, body: vec![] };
        assert!(matches!(m.validate(), Err(MessageError::Malformed(_))));
    }

    #[test]
    fn message_just_below_hop_limit_is_valid() {
        let m = AgentMessage::Request { origin_task: task(), hops: MAX_HOPS - 1, body: vec![] };
        assert!(m.validate().is_ok());
    }

    #[test]
    fn oversized_body_is_malformed() {
        let big = vec![0u8; MAX_BODY_BYTES + 1];
        let m = AgentMessage::Request { origin_task: task(), hops: 0, body: big };
        assert!(matches!(m.validate(), Err(MessageError::Malformed(_))));
    }

    #[test]
    fn body_at_size_limit_is_valid() {
        let exact = vec![0u8; MAX_BODY_BYTES];
        let m = AgentMessage::Request { origin_task: task(), hops: 0, body: exact };
        assert!(m.validate().is_ok());
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
