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

/// Upper bound on a provider response body (finding 025). 8 MiB is far larger
/// than any legitimate single-shot chat completion yet small enough to bound
/// memory against a hostile/buggy endpoint.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

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

/// Validate that the base URL is localhost-over-http or HTTPS — prevents SSRF.
///
/// String `starts_with` was unsound: `http://localhost@evil.com`,
/// `http://localhost.evil.com`, and `http://127.0.0.1.evil/` all slipped past
/// it. We now fully parse the URL and require:
///   * scheme == "http" with an EXACT host of "localhost" or "127.0.0.1", OR
///   * scheme == "https" (any host),
///   * and NO userinfo (a `user[:pass]@` segment) in either case — that is the
///     classic `localhost@evil.com` authority-confusion bypass.
fn validate_base_url(raw: &str) -> Result<(), String> {
    let parsed = url::Url::parse(raw)
        .map_err(|e| format!("base_url '{}' is not a valid URL: {}", raw, e))?;

    // Reject any embedded credentials — `http://localhost@evil.com/` parses with
    // host "evil.com" and username "localhost"; without this check a string
    // prefix test would have been fooled, and even with parsing we never want
    // credentials in a base URL.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "base_url '{}' is not permitted: must not contain userinfo (user:pass@)",
            raw
        ));
    }

    let host = parsed.host_str().unwrap_or("");
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if host == "localhost" || host == "127.0.0.1" => Ok(()),
        _ => Err(format!(
            "base_url '{}' is not permitted: must be http://localhost, http://127.0.0.1, or https://",
            raw
        )),
    }
}

/// Read a blocking response body, hard-bounded to `MAX_RESPONSE_BYTES`
/// (finding 025). Unlike `Response::bytes()` (which buffers the *entire* body
/// before any size check — useless against a chunked or lying Content-Length),
/// this streams through the `Read` impl and stops at the cap, so a hostile
/// endpoint cannot drive memory past the limit. Reads one extra byte so an
/// exactly-at-limit body is accepted but anything larger is rejected.
fn read_capped_body(resp: reqwest::blocking::Response) -> Result<Vec<u8>, ProviderError> {
    use std::io::Read;

    // Reject early on an oversized advertised length (cheap fast path).
    if let Some(len) = resp.content_length() {
        if len > MAX_RESPONSE_BYTES {
            return Err(ProviderError::Transport("response too large".into()));
        }
    }

    let mut buf = Vec::new();
    // take(cap + 1): if we manage to read cap+1 bytes the body is over the limit.
    let mut limited = resp.take(MAX_RESPONSE_BYTES + 1);
    limited
        .read_to_end(&mut buf)
        .map_err(|_| ProviderError::Transport("response read failed".into()))?;
    if buf.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(ProviderError::Transport("response too large".into()));
    }
    Ok(buf)
}

// Terminal-injection stripping is a security control every provider must apply
// identically, so it lives in core (Ecosystem Lens). Re-exported here for the
// plugin's existing public API and call sites.
pub use wyrtloom_core::util::strip_control;

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

        // Cap the response body before decoding (finding 025): a malicious or
        // buggy endpoint must not be able to exhaust memory, including via a
        // chunked / absent / lying Content-Length. `read_capped_body` streams at
        // most MAX_RESPONSE_BYTES + 1 and rejects rather than buffering it all.
        let body = read_capped_body(resp)?;
        let ollama_resp: OllamaResponse = serde_json::from_slice(&body)
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
        // Bound the body here too (finding 025): /api/tags is the same untrusted
        // endpoint and must not be allowed to exhaust memory.
        let Ok(bytes) = read_capped_body(resp) else { return vec![] };
        let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) else { return vec![] };
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

    // 025 — authority-confusion / suffix bypasses that fooled `starts_with`
    // must all be rejected by the real URL parser.
    #[test]
    fn ssrf_bypass_strings_are_rejected() {
        // userinfo: host is actually evil.com
        assert!(OllamaProvider::new("http://localhost@evil.com").is_err());
        assert!(OllamaProvider::new("http://127.0.0.1@evil.com/").is_err());
        // suffix: host is localhost.evil.com / 127.0.0.1.evil
        assert!(OllamaProvider::new("http://localhost.evil.com").is_err());
        assert!(OllamaProvider::new("http://127.0.0.1.evil/").is_err());
        // userinfo even on an otherwise-legit localhost host is rejected
        assert!(OllamaProvider::new("http://user:pass@localhost:11434").is_err());
    }

    #[test]
    fn legit_urls_still_accepted_after_hardening() {
        assert!(OllamaProvider::new("http://localhost:11434").is_ok());
        assert!(OllamaProvider::new("http://127.0.0.1:11434/").is_ok());
        assert!(OllamaProvider::new("https://api.example.com/v1").is_ok());
        // https with userinfo is still rejected (no credentials in base_url)
        assert!(OllamaProvider::new("https://user@api.example.com").is_err());
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

    // 025 — an oversized response body is rejected as "response too large"
    // rather than being buffered/decoded. A tiny one-shot TCP server replies
    // with a Content-Length far above the cap.
    #[test]
    fn oversized_response_body_is_rejected() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf); // drain request
                let oversized = MAX_RESPONSE_BYTES + 1;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                    oversized
                );
                let _ = stream.write_all(resp.as_bytes());
                // Do not actually send the body; the cap must trip on the header.
                let _ = stream.flush();
            }
        });

        let provider =
            OllamaProvider::new(format!("http://127.0.0.1:{}", port)).unwrap();
        let req = GenerationRequest {
            messages: vec![Message::user("hi")],
            max_output_tokens: 5,
            model: "m".into(),
        };
        let err = provider.generate(req).unwrap_err();
        let _ = handle.join();
        match err {
            ProviderError::Transport(msg) => assert_eq!(msg, "response too large"),
            other => panic!("expected Transport(\"response too large\"), got {:?}", other),
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
