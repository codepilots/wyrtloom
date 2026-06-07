use crate::types::{ModelId, Money};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageRole {
    System,
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: MessageRole,
    pub content: String,
}

impl Message {
    pub fn system(content: impl Into<String>) -> Self {
        Self { role: MessageRole::System, content: content.into() }
    }
    pub fn user(content: impl Into<String>) -> Self {
        Self { role: MessageRole::User, content: content.into() }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self { role: MessageRole::Assistant, content: content.into() }
    }
}

/// Cost-model schema lives in core so all callers and the future ML tuner
/// read usage uniformly regardless of provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// None when the provider supplies no pricing information.
    pub cost: Option<Money>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationRequest {
    pub messages: Vec<Message>,
    /// Output-token budget — the provider must respect this.
    pub max_output_tokens: u32,
    pub model: ModelId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContentBlock {
    Text(String),
}

impl ContentBlock {
    pub fn as_text(&self) -> Option<&str> {
        match self { ContentBlock::Text(s) => Some(s) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationResponse {
    pub content: Vec<ContentBlock>,
    pub usage: Usage,
}

impl GenerationResponse {
    pub fn full_text(&self) -> String {
        self.content.iter().filter_map(|b| b.as_text()).collect::<Vec<_>>().join("")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDescriptor {
    pub id: ModelId,
    pub description: Option<String>,
    pub cost_per_input_token: Option<Money>,
    pub cost_per_output_token: Option<Money>,
}

#[derive(Error, Debug)]
pub enum ProviderError {
    #[error("rate limited by provider")]
    RateLimited,
    #[error("unauthorized — check credentials")]
    Unauthorized,
    #[error("output budget exceeded")]
    BudgetExceeded,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("provider error: {0}")]
    Provider(String),
}

/// Stable interface contract for calling a language model.
pub trait LlmProvider: Send + Sync {
    fn generate(&self, req: GenerationRequest) -> Result<GenerationResponse, ProviderError>;
    fn models(&self) -> Vec<ModelDescriptor>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_cost_may_be_none() {
        let u = Usage { input_tokens: 10, output_tokens: 5, cost: None };
        assert!(u.cost.is_none());
        assert_eq!(u.input_tokens, 10);
        assert_eq!(u.output_tokens, 5);
    }

    #[test]
    fn usage_cost_may_be_some() {
        let u = Usage {
            input_tokens: 10,
            output_tokens: 5,
            cost: Some(Money::usd(0.001)),
        };
        assert!(u.cost.is_some());
    }

    #[test]
    fn generation_request_carries_budget() {
        let req = GenerationRequest {
            messages: vec![Message::user("hello")],
            max_output_tokens: 100,
            model: "test-model".into(),
        };
        assert_eq!(req.max_output_tokens, 100);
    }

    #[test]
    fn generation_response_full_text_concatenates() {
        let resp = GenerationResponse {
            content: vec![ContentBlock::Text("hello ".into()), ContentBlock::Text("world".into())],
            usage: Usage { input_tokens: 5, output_tokens: 3, cost: None },
        };
        assert_eq!(resp.full_text(), "hello world");
    }

    /// Contract: provider errors must be typed, never opaque.
    #[test]
    fn provider_errors_are_typed() {
        let e = ProviderError::RateLimited;
        assert!(e.to_string().contains("rate limited"));

        let e = ProviderError::Transport("timeout".into());
        assert!(e.to_string().contains("timeout"));
    }
}
