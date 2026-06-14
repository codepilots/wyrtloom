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

use crate::types::Timestamp;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identifier for an enrolled client.
pub type ClientId = String;

/// First-contact enrollment request, authorised by a bootstrap API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    /// Single-use bootstrap key, provisioned out of band.
    pub api_key: String,
    /// Human-meaningful client name (validated, not trusted).
    pub client_name: String,
    /// The client's public key (DER/PEM/raw per scheme). Required for asymmetric
    /// schemes; the server stores only this + a fingerprint.
    pub public_key: Vec<u8>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
