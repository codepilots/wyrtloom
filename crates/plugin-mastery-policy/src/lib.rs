//! W8 — Mastery policy plugin (`plugin-mastery-policy`).
//!
//! Implements the typed, project-owner-governed configuration object from
//! SoftDevSpec §2.4 ("Mastery policy schema"), satisfying row W8 of §2.2.
//!
//! Constitutional-governance (CG) requirements supported here:
//!   * **CG-10** — the policy SHALL define a reserved-rung quota: a minimum
//!     fraction of graduated, criticality-tagged work assigned to humans.
//!     Enforced as `reserved_rung_quota ∈ [0.0, 1.0]`.
//!   * **CG-17** — rotation cadence and eligible roles SHALL be mastery-policy
//!     fields; rotation SHALL respect criticality tags (e.g. a human-only
//!     specifier for safety-critical items). Modelled by [`Rotation`] with
//!     `cadence`, `eligible_roles`, and `criticality_overrides`.
//!   * **CG-23** — the ledger purpose SHALL be declared developmental and
//!     attaching performance targets to ledger data SHALL be unsupported by
//!     API design. Enforced by [`LedgerGovernance::aggregate_only_team_views`]
//!     being a *locked-true* invariant: it cannot be deserialized as `false`
//!     and there is no API to set it false. Only aggregate, never per-person,
//!     team views are expressible.
//!
//! The `owner` field reuses the core actor identifier
//! [`wyrtloom_core::types::ActorId`] (D11 — the project owner governs the
//! policy; changes pass a lightweight gate, out of scope for this object).
//!
//! Validation is a deterministic [`MasteryPolicy::validate`] returning
//! `Result<(), PolicyError>`; loading via [`MasteryPolicy::from_json`] both
//! deserializes and validates.

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use wyrtloom_core::types::ActorId;

/// Errors surfaced when loading or validating a [`MasteryPolicy`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// `reserved_rung_quota` was outside the closed interval `[0.0, 1.0]` (CG-10).
    #[error("reserved_rung_quota {0} out of range; must be in [0.0, 1.0] (CG-10)")]
    QuotaOutOfRange(String),

    /// `aggregate_only_team_views` was supplied as `false`. This is a locked
    /// invariant (CG-23): only aggregate team views are ever permitted.
    #[error("ledger_governance.aggregate_only_team_views is locked true and cannot be false (CG-23)")]
    AggregateLockViolated,

    /// `owner` (a `wyrtloom_core::types::ActorId`) was empty.
    #[error("owner must be a non-empty ActorId (D11)")]
    MissingOwner,

    /// A `redundant(R)` assignment was requested. Accepted by the schema but
    /// flagged: redundant assignment (R>1) is Phase-2 (§2.7) and not active.
    #[error("assignment 'redundant(R={0})' is a Phase-2 feature and not yet active (§2.7)")]
    RedundantAssignmentPhase2(u32),

    /// A count that must be positive (`hunt.max_ladder_depth`,
    /// `rotation.cadence_days`, or sampled `k`) was zero.
    #[error("{0} must be greater than zero")]
    NonPositive(&'static str),

    /// Serde failed to parse the JSON document.
    #[error("failed to parse policy JSON: {0}")]
    Parse(String),
}

/// Sampling/grading mode for coverage probes (CG-19): how aggressively dark
/// coverage-map areas trigger probes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Mode {
    /// Probe every dark area.
    Strict,
    /// Probe a sampled subset; `k` items per cadence.
    Sampled { k: u32 },
    /// Mix of strict (for criticality-tagged) and sampled (otherwise).
    Hybrid,
}

/// How a graduated build is assigned. `redundant(R)` is Phase-2 (§2.7): it is
/// accepted by the schema but [`MasteryPolicy::validate`] flags it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Assignment {
    /// One owner per build.
    Single,
    /// Work divided across owners.
    Divided,
    /// `R` redundant owners (Phase-2).
    Redundant { r: u32 },
}

/// Roles assignable during rotation (CG-16). Local enum — these are workflow
/// roles, not core actor identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Specifier,
    Designer,
    Developer,
    Tester,
}

/// Expanding-interval spacing parameters for scheduled withdrawal (CG-13).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpacingParams {
    /// Initial spacing, in days, before the first solo flight.
    pub initial_interval_days: u32,
    /// Multiplier applied to grow the interval after each successful flight.
    pub expansion_factor: f64,
    /// Upper bound on the interval, in days.
    pub max_interval_days: u32,
}

/// Per-criticality override of the rotation eligibility (CG-17): e.g. a
/// safety-critical tag may restrict the specifier role to humans only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticalityOverride {
    /// The criticality tag this override applies to.
    pub tag: String,
    /// Roles that, for this tag, are restricted to humans only.
    #[serde(default)]
    pub human_only_roles: Vec<Role>,
}

/// Role-rotation configuration (CG-17).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rotation {
    /// Rotation cadence in days.
    pub cadence_days: u32,
    /// Roles eligible to be rotated through.
    pub eligible_roles: Vec<Role>,
    /// Per-criticality eligibility overrides.
    #[serde(default)]
    pub criticality_overrides: Vec<CriticalityOverride>,
}

/// Hunt-harness ladder configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hunt {
    /// Whether stakes escalate as the ladder deepens.
    pub stake_escalation: bool,
    /// Maximum hunt-ladder depth; must be positive.
    pub max_ladder_depth: u32,
}

/// Ledger-governance settings (CG-23).
///
/// `aggregate_only_team_views` is a **locked-true** invariant: there is no
/// public constructor or setter that can make it false, its [`Default`] is
/// true, and its custom [`Deserialize`] rejects a `false` in the source
/// document. Team views are therefore always aggregate-only, never
/// per-person — performance targets cannot be attached to ledger data.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LedgerGovernance {
    /// Retention window for ledger entries, in days.
    pub retention_days: u32,
    /// LOCKED true (CG-23). Serialized for transparency; never settable false.
    aggregate_only_team_views: bool,
}

impl LedgerGovernance {
    /// Construct ledger governance. `aggregate_only_team_views` is always true
    /// (CG-23) and there is intentionally no parameter to change it.
    pub fn new(retention_days: u32) -> Self {
        Self { retention_days, aggregate_only_team_views: true }
    }

    /// Reports the locked flag (CG-23). Every public construction path forces
    /// this true, but the accessor reads the *stored* field so that
    /// [`MasteryPolicy::validate`] remains a genuine gate: were a `false` ever
    /// to slip in (a future regression, a relaxed deserializer), validation
    /// would catch it rather than the accessor masking it.
    pub fn aggregate_only_team_views(&self) -> bool {
        self.aggregate_only_team_views
    }
}

impl Default for LedgerGovernance {
    fn default() -> Self {
        Self::new(365)
    }
}

/// Helper mirroring the wire shape of [`LedgerGovernance`], used only to drive
/// the custom deserializer so the locked invariant is enforced at parse time.
#[derive(Deserialize)]
struct LedgerGovernanceWire {
    retention_days: u32,
    /// Optional in the document; if present it MUST be `true` (CG-23).
    #[serde(default = "default_true")]
    aggregate_only_team_views: bool,
}

fn default_true() -> bool {
    true
}

impl<'de> Deserialize<'de> for LedgerGovernance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = LedgerGovernanceWire::deserialize(deserializer)?;
        // CG-23: reject any attempt to set the lock false at the parse boundary.
        if !wire.aggregate_only_team_views {
            return Err(serde::de::Error::custom(
                "ledger_governance.aggregate_only_team_views is locked true and cannot be false (CG-23)",
            ));
        }
        Ok(Self { retention_days: wire.retention_days, aggregate_only_team_views: true })
    }
}

/// The typed mastery policy (SoftDevSpec §2.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MasteryPolicy {
    /// Probe mode: strict / sampled(K) / hybrid (CG-19).
    pub mode: Mode,
    /// Criticality tags; agent proposes, human confirms.
    #[serde(default)]
    pub criticality_tags: Vec<String>,
    /// Build assignment strategy.
    pub assignment: Assignment,
    /// Minimum fraction of graduated, criticality-tagged work reserved for
    /// humans (CG-10). Must lie in `[0.0, 1.0]`.
    pub reserved_rung_quota: f64,
    /// Expanding-interval spacing for scheduled withdrawal (CG-13).
    pub withdrawal_cadence: SpacingParams,
    /// Role-rotation configuration (CG-17).
    pub rotation: Rotation,
    /// Hunt-harness ladder configuration.
    pub hunt: Hunt,
    /// Ledger-governance settings (CG-23).
    #[serde(default)]
    pub ledger_governance: LedgerGovernance,
    /// Project owner — a core actor identifier (D11).
    pub owner: ActorId,
}

impl MasteryPolicy {
    /// Load and validate a policy from a JSON document. Combines
    /// deserialization (which enforces the CG-23 lock at the parse boundary)
    /// with [`MasteryPolicy::validate`].
    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        let policy: MasteryPolicy =
            serde_json::from_str(json).map_err(|e| PolicyError::Parse(e.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    /// Deterministic validation of all policy invariants.
    pub fn validate(&self) -> Result<(), PolicyError> {
        // CG-10: reserved_rung_quota must be a real fraction in [0.0, 1.0].
        if !self.reserved_rung_quota.is_finite()
            || self.reserved_rung_quota < 0.0
            || self.reserved_rung_quota > 1.0
        {
            return Err(PolicyError::QuotaOutOfRange(self.reserved_rung_quota.to_string()));
        }

        // CG-23: defensive re-check of the locked invariant. Deserialization
        // already guarantees this, but validate() is the authoritative gate.
        if !self.ledger_governance.aggregate_only_team_views() {
            return Err(PolicyError::AggregateLockViolated);
        }

        // D11: owner must be a non-empty actor id.
        if self.owner.trim().is_empty() {
            return Err(PolicyError::MissingOwner);
        }

        // Phase-2 (§2.7): redundant assignment is accepted but flagged.
        if let Assignment::Redundant { r } = self.assignment {
            return Err(PolicyError::RedundantAssignmentPhase2(r));
        }

        // Positive-count invariants.
        if self.hunt.max_ladder_depth == 0 {
            return Err(PolicyError::NonPositive("hunt.max_ladder_depth"));
        }
        if self.rotation.cadence_days == 0 {
            return Err(PolicyError::NonPositive("rotation.cadence_days"));
        }
        if let Mode::Sampled { k } = self.mode {
            if k == 0 {
                return Err(PolicyError::NonPositive("mode.sampled.k"));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid baseline policy document used across tests.
    fn sample_json() -> String {
        r#"{
            "mode": { "kind": "sampled", "k": 3 },
            "criticality_tags": ["safety", "billing"],
            "assignment": { "kind": "single" },
            "reserved_rung_quota": 0.25,
            "withdrawal_cadence": {
                "initial_interval_days": 7,
                "expansion_factor": 1.5,
                "max_interval_days": 90
            },
            "rotation": {
                "cadence_days": 14,
                "eligible_roles": ["specifier", "developer", "tester"],
                "criticality_overrides": [
                    { "tag": "safety", "human_only_roles": ["specifier"] }
                ]
            },
            "hunt": { "stake_escalation": true, "max_ladder_depth": 5 },
            "ledger_governance": { "retention_days": 180 },
            "owner": "actor-owner-001"
        }"#
        .to_string()
    }

    // ---- CORE INTEGRATION TEST (required) ----------------------------------

    #[test]
    fn core_integration_sample_policy_invariants_hold() {
        let policy = MasteryPolicy::from_json(&sample_json()).expect("sample policy is valid");

        // reserved_rung_quota ∈ [0.0, 1.0] (CG-10)
        assert!(policy.reserved_rung_quota >= 0.0 && policy.reserved_rung_quota <= 1.0);

        // aggregate_only_team_views is forced true (CG-23)
        assert!(policy.ledger_governance.aggregate_only_team_views());

        // owner is a real wyrtloom_core::types::ActorId
        let owner: ActorId = policy.owner.clone();
        let _assert_type: &ActorId = &owner;
        assert_eq!(owner, "actor-owner-001");
    }

    #[test]
    fn aggregate_only_false_is_rejected_at_parse() {
        // CG-23: explicitly setting the lock false must fail to deserialize.
        let json = sample_json().replace(
            r#""ledger_governance": { "retention_days": 180 }"#,
            r#""ledger_governance": { "retention_days": 180, "aggregate_only_team_views": false }"#,
        );
        let err = MasteryPolicy::from_json(&json).unwrap_err();
        assert!(matches!(err, PolicyError::Parse(_)));
        assert!(err.to_string().contains("CG-23"));
    }

    #[test]
    fn aggregate_only_true_is_accepted_explicitly() {
        let json = sample_json().replace(
            r#""ledger_governance": { "retention_days": 180 }"#,
            r#""ledger_governance": { "retention_days": 180, "aggregate_only_team_views": true }"#,
        );
        let policy = MasteryPolicy::from_json(&json).unwrap();
        assert!(policy.ledger_governance.aggregate_only_team_views());
    }

    #[test]
    fn aggregate_only_defaults_true_when_omitted() {
        // Omit ledger_governance entirely -> default is aggregate-only true.
        let json = sample_json().replace(
            r#"            "ledger_governance": { "retention_days": 180 },"#,
            "",
        );
        let policy = MasteryPolicy::from_json(&json).unwrap();
        assert!(policy.ledger_governance.aggregate_only_team_views());
    }

    #[test]
    fn ledger_governance_constructors_force_true() {
        // No public API can set aggregate_only_team_views false: the only
        // constructor and Default both force it true.
        assert!(LedgerGovernance::new(30).aggregate_only_team_views());
        assert!(LedgerGovernance::default().aggregate_only_team_views());
    }

    #[test]
    fn validate_catches_stored_false_lock() {
        // The accessor now reads the *stored* field, so validate() is a real
        // gate (CG-23). Forge a false (only possible inside this module, where
        // the private field is reachable) and confirm validate rejects it —
        // proving the defensive re-check and AggregateLockViolated are live.
        let mut policy = MasteryPolicy::from_json(&sample_json()).unwrap();
        policy.ledger_governance.aggregate_only_team_views = false;
        assert_eq!(policy.validate(), Err(PolicyError::AggregateLockViolated));
    }

    #[test]
    fn quota_above_one_is_rejected() {
        let json = sample_json().replace("\"reserved_rung_quota\": 0.25", "\"reserved_rung_quota\": 1.5");
        let err = MasteryPolicy::from_json(&json).unwrap_err();
        assert!(matches!(err, PolicyError::QuotaOutOfRange(_)));
    }

    #[test]
    fn quota_below_zero_is_rejected() {
        let json = sample_json().replace("\"reserved_rung_quota\": 0.25", "\"reserved_rung_quota\": -0.1");
        let err = MasteryPolicy::from_json(&json).unwrap_err();
        assert!(matches!(err, PolicyError::QuotaOutOfRange(_)));
    }

    #[test]
    fn quota_at_bounds_is_accepted() {
        for q in ["0.0", "1.0"] {
            let json = sample_json().replace("\"reserved_rung_quota\": 0.25", &format!("\"reserved_rung_quota\": {q}"));
            assert!(MasteryPolicy::from_json(&json).is_ok(), "quota {q} should be valid");
        }
    }

    #[test]
    fn nan_quota_is_rejected() {
        let mut policy = MasteryPolicy::from_json(&sample_json()).unwrap();
        policy.reserved_rung_quota = f64::NAN;
        assert!(matches!(policy.validate(), Err(PolicyError::QuotaOutOfRange(_))));
    }

    #[test]
    fn empty_owner_is_rejected() {
        let json = sample_json().replace("\"actor-owner-001\"", "\"  \"");
        let err = MasteryPolicy::from_json(&json).unwrap_err();
        assert!(matches!(err, PolicyError::MissingOwner));
    }

    #[test]
    fn redundant_assignment_is_flagged_phase2() {
        let json = sample_json().replace(
            r#"{ "kind": "single" }"#,
            r#"{ "kind": "redundant", "r": 3 }"#,
        );
        let err = MasteryPolicy::from_json(&json).unwrap_err();
        assert_eq!(err, PolicyError::RedundantAssignmentPhase2(3));
    }

    #[test]
    fn divided_assignment_is_accepted() {
        let json = sample_json().replace(r#"{ "kind": "single" }"#, r#"{ "kind": "divided" }"#);
        let policy = MasteryPolicy::from_json(&json).unwrap();
        assert_eq!(policy.assignment, Assignment::Divided);
    }

    #[test]
    fn zero_ladder_depth_is_rejected() {
        let json = sample_json().replace("\"max_ladder_depth\": 5", "\"max_ladder_depth\": 0");
        assert!(matches!(MasteryPolicy::from_json(&json), Err(PolicyError::NonPositive(_))));
    }

    #[test]
    fn zero_rotation_cadence_is_rejected() {
        let json = sample_json().replace("\"cadence_days\": 14", "\"cadence_days\": 0");
        assert!(matches!(MasteryPolicy::from_json(&json), Err(PolicyError::NonPositive(_))));
    }

    #[test]
    fn sampled_zero_k_is_rejected() {
        let json = sample_json().replace(r#"{ "kind": "sampled", "k": 3 }"#, r#"{ "kind": "sampled", "k": 0 }"#);
        assert!(matches!(MasteryPolicy::from_json(&json), Err(PolicyError::NonPositive(_))));
    }

    #[test]
    fn strict_and_hybrid_modes_parse() {
        let strict = sample_json().replace(r#"{ "kind": "sampled", "k": 3 }"#, r#"{ "kind": "strict" }"#);
        assert_eq!(MasteryPolicy::from_json(&strict).unwrap().mode, Mode::Strict);
        let hybrid = sample_json().replace(r#"{ "kind": "sampled", "k": 3 }"#, r#"{ "kind": "hybrid" }"#);
        assert_eq!(MasteryPolicy::from_json(&hybrid).unwrap().mode, Mode::Hybrid);
    }

    #[test]
    fn rotation_criticality_overrides_round_trip() {
        let policy = MasteryPolicy::from_json(&sample_json()).unwrap();
        assert_eq!(policy.rotation.criticality_overrides.len(), 1);
        let ov = &policy.rotation.criticality_overrides[0];
        assert_eq!(ov.tag, "safety");
        assert_eq!(ov.human_only_roles, vec![Role::Specifier]);
    }

    #[test]
    fn serialize_round_trips_through_validation() {
        let policy = MasteryPolicy::from_json(&sample_json()).unwrap();
        let json = serde_json::to_string(&policy).unwrap();
        let reparsed = MasteryPolicy::from_json(&json).unwrap();
        assert_eq!(policy, reparsed);
    }
}
