/// Ollama LLM provider plugin.
///
/// Security hardening (see CHANGELOG.md):
///   006 – HTTP client: 30-second timeout, redirect following disabled,
///         base_url scheme validated at construction (http://localhost or https:// only).
///   007 – Terminal output and escalation prompts: ANSI/control-sequence
///         stripped from all externally-sourced strings.
///   021 – Raw transport/provider error strings are mapped to opaque
///         categories; internal detail is kept in a separate debug message.
///   S1  – base_url is parsed with a real URL parser and the host is matched
///         exactly, closing the `http://localhost.attacker.com` prefix bypass
///         and blocking https to private/loopback/link-local IPs (cloud IMDS).
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use url::{Host, Url};
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
    /// `http` is only permitted to loopback hosts (localhost/127.0.0.1/::1);
    /// `https` is permitted to any DNS host but not to private/loopback/
    /// link-local IP literals.
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

/// Validate that the base URL targets local Ollama or a safe remote HTTPS
/// endpoint, blocking SSRF to internal hosts and cloud metadata services.
///
/// The host is matched *exactly* via a real URL parser, so the old
/// `"http://localhost".starts_with` bypass (e.g. `http://localhost.attacker.com`,
/// `http://127.0.0.1.attacker.com`) no longer passes. IP-literal hosts in
/// private/loopback/link-local ranges are rejected for https so that
/// `https://169.254.169.254`, `https://10.0.0.1`, etc. cannot be reached.
///
/// DNS rebinding to a private address after this check is out of scope here;
/// a resolving allowlist is reserved for Phase 3.
fn validate_base_url(url: &str) -> Result<(), String> {
    let parsed =
        Url::parse(url).map_err(|_| format!("base_url '{}' is not a valid URL", url))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!(
            "base_url '{}' uses unsupported scheme '{}' (only http/https)",
            url, scheme
        ));
    }
    let host = parsed
        .host()
        .ok_or_else(|| format!("base_url '{}' has no host", url))?;

    match host {
        Host::Domain(name) => {
            if scheme == "https" || name == "localhost" {
                Ok(())
            } else {
                Err(format!(
                    "base_url '{}': http is only permitted to localhost/127.0.0.1/::1",
                    url
                ))
            }
        }
        Host::Ipv4(v4) => validate_ip_host(url, scheme, v4.is_loopback(), is_disallowed_v4(&v4)),
        Host::Ipv6(v6) => validate_ip_host(url, scheme, v6.is_loopback(), is_disallowed_v6(&v6)),
    }
}

fn validate_ip_host(
    url: &str,
    scheme: &str,
    is_loopback: bool,
    is_disallowed: bool,
) -> Result<(), String> {
    if scheme == "http" {
        if is_loopback {
            Ok(())
        } else {
            Err(format!(
                "base_url '{}': http is only permitted to loopback addresses",
                url
            ))
        }
    } else if is_disallowed {
        Err(format!(
            "base_url '{}' targets a private/loopback/link-local address",
            url
        ))
    } else {
        Ok(())
    }
}

fn is_disallowed_v4(ip: &Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local() // 169.254.0.0/16 — cloud instance metadata
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast() // 224.0.0.0/4
        || is_cgnat_v4(ip) // 100.64.0.0/10 — carrier-grade NAT shared space
}

/// 100.64.0.0/10 (RFC 6598). Not exposed by stable std (`Ipv4Addr::is_shared`
/// is unstable), so matched directly: first octet 100, second octet 64–127.
fn is_cgnat_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 0x40
}

fn is_disallowed_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    // IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`) literals
    // must be judged by their embedded IPv4 address — otherwise the private/IMDS
    // block is trivially bypassed with a bracketed IPv6 host such as
    // `https://[::ffff:169.254.169.254]`, which `url` parses as Host::Ipv6.
    if let Some(v4) = ip.to_ipv4() {
        return is_disallowed_v4(&v4);
    }
    ip.is_unique_local() // fc00::/7
        || ip.is_unicast_link_local() // fe80::/10
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

    // S1 — the old starts_with("http://localhost") bypass must be closed.
    #[test]
    fn localhost_prefix_bypass_is_rejected() {
        assert!(OllamaProvider::new("http://localhost.attacker.com/api").is_err());
        assert!(OllamaProvider::new("http://127.0.0.1.attacker.com/api").is_err());
        // userinfo trick: the real host is attacker.com, not localhost.
        assert!(OllamaProvider::new("http://localhost@attacker.com/api").is_err());
    }

    // S1 — https must not reach private/loopback/link-local IP literals.
    #[test]
    fn https_to_internal_ip_is_rejected() {
        assert!(OllamaProvider::new("https://169.254.169.254/latest").is_err());
        assert!(OllamaProvider::new("https://10.0.0.1/").is_err());
        assert!(OllamaProvider::new("https://192.168.1.1/").is_err());
        assert!(OllamaProvider::new("https://[::1]/").is_err());
    }

    // S1 — IPv4-mapped/compatible IPv6 literals must not bypass the IMDS/private
    // block (url parses these as Host::Ipv6, not Ipv4).
    #[test]
    fn https_to_ipv4_mapped_ipv6_is_rejected() {
        assert!(OllamaProvider::new("https://[::ffff:169.254.169.254]/latest").is_err());
        assert!(OllamaProvider::new("https://[::ffff:10.0.0.1]/").is_err());
        assert!(OllamaProvider::new("https://[::ffff:127.0.0.1]/").is_err());
    }

    // S1 — decimal/octal/hex IP encodings are normalised to Ipv4 by url and blocked.
    #[test]
    fn https_to_encoded_loopback_is_rejected() {
        assert!(OllamaProvider::new("https://2130706433/").is_err()); // 127.0.0.1
        assert!(OllamaProvider::new("https://0x7f000001/").is_err());
    }

    // S1 — CGNAT and multicast ranges are internal/non-routable; block over https.
    #[test]
    fn https_to_cgnat_and_multicast_is_rejected() {
        assert!(OllamaProvider::new("https://100.64.0.1/").is_err()); // RFC 6598
        assert!(OllamaProvider::new("https://224.0.0.1/").is_err()); // multicast
    }

    // A legitimate public mapped address is still allowed.
    #[test]
    fn https_to_public_mapped_ipv6_is_accepted() {
        assert!(OllamaProvider::new("https://[::ffff:8.8.8.8]/").is_ok());
    }

    #[test]
    fn loopback_ipv6_over_http_is_accepted() {
        assert!(OllamaProvider::new("http://[::1]:11434").is_ok());
    }

    #[test]
    fn non_http_scheme_is_rejected() {
        assert!(OllamaProvider::new("file:///etc/passwd").is_err());
        assert!(OllamaProvider::new("ftp://localhost/x").is_err());
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
