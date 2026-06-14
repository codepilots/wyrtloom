//! User-directory contract — pluggable user management.
//!
//! Core has no built-in notion of human users; consumers that need authenticated
//! users (e.g. the dashboard API server) depend on this contract, and the
//! implementation ships as a separate, swappable plugin (e.g. `wyrtloom-users`,
//! argon2 over a `PersistenceProvider`).
//!
//! Authorization roles are intentionally coarse. The directory verifies
//! *identity*; per-request authorization (and session lifetime, revocation, …)
//! is the caller's responsibility — see the security-module audit notes.

use crate::types::{ActorId, Timestamp};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Coarse role for role-based access control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Read-only access.
    Viewer,
    /// Read + task mutations.
    Operator,
    /// Full access incl. configuration and security surfaces.
    Admin,
}

/// An authenticated user. `id` reuses the core `ActorId` so user actions thread
/// through the existing actor-attributed audit/kanban machinery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: ActorId,
    pub roles: Vec<Role>,
    /// Disabled users must be rejected at authentication and on every request.
    pub active: bool,
    pub created_at: Timestamp,
}

impl User {
    pub fn has_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }
}

/// Request to create a user. The password is plaintext only in transit to the
/// implementation, which MUST hash it (argon2id) before storage.
#[derive(Clone)]
pub struct NewUser {
    pub username: ActorId,
    pub password: String,
    pub roles: Vec<Role>,
}

// Custom Debug that redacts the plaintext `password` so it never reaches a
// Debug/log sink.
impl std::fmt::Debug for NewUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewUser")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("roles", &self.roles)
            .finish()
    }
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredential,
    #[error("user is disabled")]
    Disabled,
    #[error("user already exists")]
    AlreadyExists,
    #[error("user not found")]
    NotFound,
    #[error("storage failure: {0}")]
    Storage(String),
}

/// Pluggable user directory. Implementations are storage-agnostic plugins.
pub trait UserDirectory: Send + Sync {
    /// Verify a username/password and return the user. Implementations MUST use a
    /// constant-time hash verify and SHOULD run the hash even for unknown users
    /// (uniform timing) to avoid an enumeration oracle.
    fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError>;
    /// Create a user (password hashed by the implementation).
    fn create(&self, new: NewUser) -> Result<ActorId, AuthError>;
    /// Fetch a user by id (used to re-check roles/active on each request).
    fn get(&self, id: &str) -> Result<User, AuthError>;
    /// List all users (Admin-only surface for the caller to gate).
    fn list(&self) -> Result<Vec<User>, AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_check_works() {
        let u = User {
            id: "alice".into(),
            roles: vec![Role::Viewer, Role::Operator],
            active: true,
            created_at: Timestamp::now(),
        };
        assert!(u.has_role(Role::Operator));
        assert!(!u.has_role(Role::Admin));
    }

    #[test]
    fn user_roundtrips_serde() {
        let u = User { id: "bob".into(), roles: vec![Role::Admin], active: false, created_at: Timestamp::now() };
        let s = serde_json::to_string(&u).unwrap();
        let back: User = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, "bob");
        assert!(!back.active);
        assert!(back.has_role(Role::Admin));
    }
}
