use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type TaskId    = Uuid;
pub type ActorId   = String;
pub type ModelId   = String;
pub type ProfileId = String;
pub type ContractId = String;
pub type Topic     = String;
pub type Bytes     = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp(pub DateTime<Utc>);

impl Timestamp {
    pub fn now() -> Self { Self(Utc::now()) }
}

impl Default for Timestamp {
    fn default() -> Self { Self::now() }
}

/// Semantic version — compatible means same major, minor >= required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemVer {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self { Self { major, minor, patch } }

    pub fn is_compatible_with(&self, required: &SemVer) -> bool {
        self.major == required.major && self.minor >= required.minor
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Money stored as integer microdollars to avoid floating-point drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    pub amount_microdollars: i64,
    pub currency: String,
}

impl Money {
    /// Construct from a dollar amount.
    /// Rounds to the nearest microdollar rather than truncating, preventing
    /// systematic under-reporting due to floating-point representation
    /// (finding 017 — security audit).
    pub fn usd(dollars: f64) -> Self {
        Self {
            amount_microdollars: (dollars * 1_000_000.0).round() as i64,
            currency: "USD".to_string(),
        }
    }

    pub fn as_dollars(&self) -> f64 {
        self.amount_microdollars as f64 / 1_000_000.0
    }

    pub fn zero() -> Self { Self { amount_microdollars: 0, currency: "USD".to_string() } }
}
