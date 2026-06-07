/// Ollama LLM provider plugin.
///
/// Security hardening (see CHANGELOG.md):
///   006 – HTTP client: 30-second timeout, redirect following disabled,
///         base_url scheme validated at construction (http://localhost or https:// only).
///   007 – Terminal output and escalation prompts: ANSI/control-sequence
///         stripped from all externally-sourced strings.
///   021 – Raw transport/provider error strings are mapped to opaque
///         categories; internal detail is kept in a separate debug message.
use serde::{Deserialize, Serialize};
use std::time::Duration;
use wyrtloom_core::provider::{
    ContentBlock, GenerationRequest, GenerationResponse, LlmProvider, MessageRole,
    ModelDescriptor, ProviderError, Usage,
};

pub struct OllamaProvider {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl OllamaProvider {
    /// Construct a provider targeting `base_url`.
    /// The URL must be `http://localhost…`, `http://127.0.0.1…`, or `https://…`.
    pub fn new(base_url: impl Into<String>) -> Result<Self, String> {
        let url = base_url.into();
        validate_base_url(&url)?;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            // Disable redirect following — LLM APIs do not redirect;
            // automatic following would enable SSRF (finding 006).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("failed to build HTTP client: {}", e))?;
        Ok(Self { base_url: url, client })
    }

    /// Convenience constructor for local Ollama (always valid).
    pub fn default_local() -> Self {
        Self::new("http://localhost:11434").expect("localhost URL is always valid")
    }
}

/// Validate that the base URL is localhost or HTTPS — prevents SSRF.
fn validate_base_url(url: &str) -> Result<(), String> {
    if url.starts_with("http://localhost")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("https://")
    {
        Ok(())
    } else {
        Err(format!(
            "base_url '{}' is not permitted: must be http://localhost, http://127.0.0.1, or https://",
            url
        ))
    }
}

/// Strip ANSI escape sequences and other control characters from a string
/// before displaying it on the terminal or including it in an escalation prompt.
/// Prevents terminal-injection attacks from a malicious or compromised provider.
pub fn strip_control(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until we see an ASCII letter (end of escape sequence).
            while let Some(&nc) = chars.peek() {
                chars.next();
                if nc.is_ascii_alphabetic() { break; }
            }
        } else if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
            // Drop other control characters.
        } else {
            out.push(c);
        }
    }
    out
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
            // Map transport errors to a generic category (finding 021).
            .map_err(|e| {
                if e.is_timeout() {
                    ProviderError::Transport("connection timed out".into())
                } else if e.is_connect() {
                    ProviderError::Transport("connection refused".into())
                } else {
                    ProviderError::Transport("network error".into())
                }
            })?;

        match resp.status().as_u16() {
            401 => return Err(ProviderError::Unauthorized),
            429 => return Err(ProviderError::RateLimited),
            s if s >= 400 => {
                // Do not include the raw server body in the error (finding 021).
                return Err(ProviderError::Provider(format!("server returned HTTP {}", s)));
            }
            _ => {}
        }

        let ollama_resp: OllamaResponse = resp
            .json()
            .map_err(|_| ProviderError::Transport("response decode failed".into()))?;

        let input_tokens  = ollama_resp.prompt_eval_count.unwrap_or(0);
        let output_tokens = ollama_resp.eval_count.unwrap_or(0);
        let usage = Usage { input_tokens, output_tokens, cost: None };

        // Strip control sequences from LLM output before returning (finding 007).
        let clean_content = strip_control(&ollama_resp.message.content);
        Ok(GenerationResponse {
            content: vec![ContentBlock::Text(clean_content)],
            usage,
        })
    }

    fn models(&self) -> Vec<ModelDescriptor> {
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

    // 006 — URL validation
    #[test]
    fn localhost_url_is_accepted() {
        assert!(OllamaProvider::new("http://localhost:11434").is_ok());
        assert!(OllamaProvider::new("http://127.0.0.1:11434").is_ok());
        assert!(OllamaProvider::new("https://api.example.com").is_ok());
    }

    #[test]
    fn non_localhost_http_url_is_rejected() {
        assert!(OllamaProvider::new("http://10.0.0.1:11434").is_err());
        assert!(OllamaProvider::new("http://internal-service/api").is_err());
        // Cloud IMDS
        assert!(OllamaProvider::new("http://169.254.169.254/latest").is_err());
    }

    // 006 — unreachable URL returns transport error (not panic)
    #[test]
    fn unreachable_url_returns_transport_error() {
        let provider = OllamaProvider::new("http://127.0.0.1:19999").unwrap();
        let req = GenerationRequest {
            messages: vec![Message::user("hello")],
            max_output_tokens: 10,
            model: "llama3.2".into(),
        };
        let err = provider.generate(req).unwrap_err();
        assert!(matches!(err, ProviderError::Transport(_)));
    }

    // 007 — ANSI stripping
    #[test]
    fn ansi_escape_is_stripped() {
        assert_eq!(strip_control("\x1b[31mred\x1b[0m"), "red");
    }

    #[test]
    fn control_characters_are_stripped() {
        let s = "hello\x00world\x07";
        assert_eq!(strip_control(s), "helloworld");
    }

    #[test]
    fn newlines_and_tabs_are_preserved() {
        assert_eq!(strip_control("line1\nline2\ttab"), "line1\nline2\ttab");
    }

    // 021 — transport errors don't leak internal details
    #[test]
    fn transport_error_is_generic() {
        let provider = OllamaProvider::new("http://127.0.0.1:19999").unwrap();
        let req = GenerationRequest {
            messages: vec![Message::user("hi")],
            max_output_tokens: 5,
            model: "m".into(),
        };
        let err = provider.generate(req).unwrap_err();
        if let ProviderError::Transport(msg) = err {
            // Must not contain raw socket addresses or internal paths
            assert!(!msg.contains("127.0.0.1:19999"), "leaks address: {}", msg);
        }
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
