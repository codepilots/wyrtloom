//! Client-authentication contract — pluggable "security scheme" for verifying
//! the *client application* (web SPA, mobile app, CLI), distinct from the human
//! user.
//!
//! The reference scheme is trust-on-first-use (TOFU) with asymmetric keys: a
//! client makes first contact with a single-use bootstrap API key and presents a
//! **public key**; the server pins it and thereafter verifies each request by
//! public-key signature. The store holds only the public key + fingerprint —
//! never a recoverable secret. The scheme is swappable behind this contract
//! (mTLS, OAuth client creds, … are alternative implementations).

use crate::canon::CanonicalEncoder;
use crate::types::Timestamp;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identifier for an enrolled client.
pub type ClientId = String;

/// Domain-separation tag for the client-auth request canonicalisation.
pub const CLIENT_AUTH_DOMAIN: &str = "wyrtloom-client-auth-v1";

/// Build the canonical bytes a client signs and the server verifies for a
/// request. This lives in the contract (not a concrete scheme plugin) so the
/// client signer, the `ClientAuthScheme` implementation, and the API server all
/// produce byte-identical input — a signature therefore binds to exactly this
/// method, path, body, client, time, and nonce, with no field-boundary ambiguity.
pub fn canonical_request(
    method: &str,
    path: &str,
    body_sha256: &[u8],
    client_id: &str,
    timestamp: i64,
    nonce: &str,
) -> Vec<u8> {
    CanonicalEncoder::new(CLIENT_AUTH_DOMAIN)
        .str_field(method)
        .str_field(path)
        .field(body_sha256)
        .str_field(client_id)
        .field(&timestamp.to_be_bytes())
        .str_field(nonce)
        .finish()
}

/// First-contact enrollment request, authorised by a bootstrap API key.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    /// Single-use bootstrap key, provisioned out of band.
    pub api_key: String,
    /// Human-meaningful client name (validated, not trusted).
    pub client_name: String,
    /// The client's public key (DER/PEM/raw per scheme). Required for asymmetric
    /// schemes; the server stores only this + a fingerprint.
    pub public_key: Vec<u8>,
}

// Custom Debug that redacts the bootstrap `api_key` — a secret that must never
// reach a Debug/log sink.
impl std::fmt::Debug for EnrollmentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentRequest")
            .field("api_key", &"<redacted>")
            .field("client_name", &self.client_name)
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// The credential the server hands back / records after enrollment. Carries no
/// secret material — only the public identity the server pins (TOFU).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCredential {
    pub client_id: ClientId,
    /// Fingerprint (e.g. SHA-256 hex of the public key) used for TOFU pinning.
    pub fingerprint: String,
    pub enrolled_at: Timestamp,
}

/// Material presented on a subsequent request for verification: a signature over
/// a canonical, length-prefixed request descriptor plus anti-replay fields.
#[derive(Clone, Serialize, Deserialize)]
pub struct PresentedClientAuth {
    pub client_id: ClientId,
    /// Canonical request bytes that were signed (method/path/body-hash/…,
    /// length-prefixed to avoid field-boundary confusion).
    pub canonical_request: Vec<u8>,
    pub signature: Vec<u8>,
    /// Unix-seconds timestamp; verifier enforces a small skew window.
    pub timestamp: i64,
    /// Per-request nonce; verifier rejects replays within the skew window.
    pub nonce: String,
}

// Custom Debug that redacts `signature`. The signature is not a long-lived
// secret, but it is sensitive authentication material that should not be echoed
// into logs (and keeps Debug from dumping raw auth bytes).
impl std::fmt::Debug for PresentedClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresentedClientAuth")
            .field("client_id", &self.client_id)
            .field("canonical_request", &self.canonical_request)
            .field("signature", &"<redacted>")
            .field("timestamp", &self.timestamp)
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// A verified client identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientIdentity {
    pub client_id: ClientId,
}

#[derive(Error, Debug)]
pub enum ClientAuthError {
    #[error("invalid or already-used bootstrap key")]
    BadApiKey,
    #[error("unknown client")]
    UnknownClient,
    #[error("signature verification failed")]
    BadSignature,
    #[error("replayed or stale request")]
    Replay,
    #[error("client credential does not match the pinned key (TOFU)")]
    PinMismatch,
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("storage failure: {0}")]
    Storage(String),
}

/// Pluggable client-authentication scheme. Implementations are storage-agnostic
/// plugins (e.g. `wyrtloom-clientauth-tofu`).
pub trait ClientAuthScheme: Send + Sync {
    /// Enroll a client on first contact (validates the bootstrap key, pins the
    /// public key). Returns the recorded credential (no secret material).
    fn enroll(&self, req: EnrollmentRequest) -> Result<ClientCredential, ClientAuthError>;
    /// Verify a subsequent request's authentication material.
    fn verify(&self, presented: &PresentedClientAuth) -> Result<ClientIdentity, ClientAuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_carries_no_secret_fields() {
        // Compile-time/structural guard: ClientCredential exposes only public id +
        // fingerprint + time. (If a secret field is ever added, this serialised
        // snapshot test will surface it for review.)
        let c = ClientCredential {
            client_id: "client-1".into(),
            fingerprint: "ab12".into(),
            enrolled_at: Timestamp::now(),
        };
        let v = serde_json::to_value(&c).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        assert_eq!(keys.len(), 3, "credential should expose exactly id/fingerprint/time, got {keys:?}");
    }

    #[test]
    fn canonical_request_is_deterministic_and_binds_fields() {
        let a = canonical_request("POST", "/api/tasks", b"hash", "client-1", 1_700_000_000, "n1");
        let b = canonical_request("POST", "/api/tasks", b"hash", "client-1", 1_700_000_000, "n1");
        assert_eq!(a, b, "same inputs must produce identical bytes");
        // A different method/path/nonce must change the bytes.
        assert_ne!(a, canonical_request("GET", "/api/tasks", b"hash", "client-1", 1_700_000_000, "n1"));
        assert_ne!(a, canonical_request("POST", "/api/task", b"shash", "client-1", 1_700_000_000, "n1"));
        assert_ne!(a, canonical_request("POST", "/api/tasks", b"hash", "client-1", 1_700_000_000, "n2"));
    }

    #[test]
    fn presented_auth_roundtrips() {
        let p = PresentedClientAuth {
            client_id: "c".into(),
            canonical_request: vec![1, 2, 3],
            signature: vec![4, 5],
            timestamp: 1_700_000_000,
            nonce: "n1".into(),
        };
        let back: PresentedClientAuth =
            serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(back.nonce, "n1");
    }
}
