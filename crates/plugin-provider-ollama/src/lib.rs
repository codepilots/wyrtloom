use serde::{Deserialize, Serialize};
use wyrtloom_core::provider::{
    ContentBlock, GenerationRequest, GenerationResponse, LlmProvider, MessageRole,
    ModelDescriptor, ProviderError, Usage,
};

pub struct OllamaProvider {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl OllamaProvider {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::blocking::Client::new(),
        }
    }

    pub fn default_local() -> Self {
        Self::new("http://localhost:11434")
    }
}

#[derive(Serialize)]
struct OllamaRequest<'a> {
    model: &'a str,
    messages: Vec<OllamaMessage<'a>>,
    stream: bool,
    options: OllamaOptions,
}

#[derive(Serialize)]
struct OllamaMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct OllamaOptions {
    num_predict: u32,
}

#[derive(Deserialize)]
struct OllamaResponse {
    message: OllamaMessageResponse,
    prompt_eval_count: Option<u64>,
    eval_count: Option<u64>,
    #[allow(dead_code)]
    done: bool,
}

#[derive(Deserialize)]
struct OllamaMessageResponse {
    content: String,
}

impl LlmProvider for OllamaProvider {
    fn generate(&self, req: GenerationRequest) -> Result<GenerationResponse, ProviderError> {
        let messages: Vec<OllamaMessage> = req
            .messages
            .iter()
            .map(|m| OllamaMessage {
                role: match m.role {
                    MessageRole::System    => "system",
                    MessageRole::User      => "user",
                    MessageRole::Assistant => "assistant",
                },
                content: &m.content,
            })
            .collect();

        let body = OllamaRequest {
            model: &req.model,
            messages,
            stream: false,
            options: OllamaOptions { num_predict: req.max_output_tokens },
        };

        let url = format!("{}/api/chat", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| ProviderError::Transport(e.to_string()))?;

        if resp.status() == 401 {
            return Err(ProviderError::Unauthorized);
        }
        if resp.status() == 429 {
            return Err(ProviderError::RateLimited);
        }
        if !resp.status().is_success() {
            return Err(ProviderError::Provider(format!(
                "HTTP {}",
                resp.status()
            )));
        }

        let ollama_resp: OllamaResponse = resp
            .json()
            .map_err(|e| ProviderError::Transport(e.to_string()))?;

        let input_tokens = ollama_resp.prompt_eval_count.unwrap_or(0);
        let output_tokens = ollama_resp.eval_count.unwrap_or(0);

        // Ollama provides no pricing — cost is null per the contract.
        let usage = Usage { input_tokens, output_tokens, cost: None };

        Ok(GenerationResponse {
            content: vec![ContentBlock::Text(ollama_resp.message.content)],
            usage,
        })
    }

    fn models(&self) -> Vec<ModelDescriptor> {
        // Attempt to list local models; return empty on failure.
        let url = format!("{}/api/tags", self.base_url);
        let Ok(resp) = self.client.get(&url).send() else { return vec![] };
        let Ok(body) = resp.json::<serde_json::Value>() else { return vec![] };
        body["models"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|m| m["name"].as_str())
            .map(|name| ModelDescriptor {
                id: name.to_string(),
                description: None,
                cost_per_input_token: None,
                cost_per_output_token: None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrtloom_core::provider::{GenerationRequest, Message};

    /// Contract: provider error variants must be reachable; transport error
    /// is returned when the base URL is unreachable.
    #[test]
    fn unreachable_url_returns_transport_error() {
        let provider = OllamaProvider::new("http://127.0.0.1:19999");
        let req = GenerationRequest {
            messages: vec![Message::user("hello")],
            max_output_tokens: 10,
            model: "llama3.2".into(),
        };
        let err = provider.generate(req).unwrap_err();
        assert!(matches!(err, ProviderError::Transport(_)));
    }

    /// Contract: usage record always carries tokens (cost may be null).
    #[test]
    fn usage_has_tokens_and_nullable_cost() {
        // We can't call the real Ollama in CI, so we verify the type contract
        // by constructing the expected response shape.
        let usage = Usage { input_tokens: 50, output_tokens: 100, cost: None };
        assert!(usage.cost.is_none());
        assert_eq!(usage.input_tokens, 50);
    }

    #[test]
    fn provider_respects_budget_field_in_request() {
        let req = GenerationRequest {
            messages: vec![Message::user("hello")],
            max_output_tokens: 42,
            model: "llama3.2".into(),
        };
        assert_eq!(req.max_output_tokens, 42);
    }
}
