/// W8 — Mastery policy: the project-owner-governed configuration object
/// (SoftDevSpec.md §2.4). Owner changes pass a lightweight gate (D11).
use crate::rotation::Role;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use wyrtloom_core::types::ActorId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MasteryMode {
    /// Probe every dark concept.
    Strict,
    /// Probe at most K dark concepts.
    Sampled(usize),
    /// Probe every criticality-tagged dark concept plus a sample of the rest.
    Hybrid { sample: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Assignment {
    Single,
    Divided,
    /// Redundant assignment R > 1 is Phase 2 (§2.7); validate() rejects it.
    Redundant(u8),
}

/// Expanding-interval spacing parameters for solo flights (CG-13).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpacingParams {
    pub initial_interval_days: u32,
    pub multiplier: f64,
    pub max_interval_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    pub cadence_days: u32,
    pub eligible_roles: Vec<Role>,
    /// Criticality tag → roles that must be held by a human for items
    /// carrying that tag (CG-17), e.g. human-only specifier for
    /// safety-critical work.
    pub human_only_roles: BTreeMap<String, Vec<Role>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntPolicy {
    pub stake_escalation: bool,
    pub max_ladder_depth: u8,
}

/// Ledger governance (§2.4). `aggregate_only_team_views` is locked to true
/// at the type level: it cannot be constructed or deserialised as false
/// (CG-21), so de-anonymised team views are unsupported by API design.
#[derive(Debug, Clone, Serialize)]
pub struct LedgerGovernance {
    pub retention_days: u32,
    aggregate_only_team_views: bool,
}

impl LedgerGovernance {
    pub fn new(retention_days: u32) -> Self {
        Self { retention_days, aggregate_only_team_views: true }
    }

    pub fn aggregate_only_team_views(&self) -> bool {
        self.aggregate_only_team_views
    }
}

fn locked_true() -> bool {
    true
}

impl<'de> Deserialize<'de> for LedgerGovernance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            retention_days: u32,
            #[serde(default = "locked_true")]
            aggregate_only_team_views: bool,
        }
        let raw = Raw::deserialize(deserializer)?;
        if !raw.aggregate_only_team_views {
            return Err(serde::de::Error::custom(
                "aggregate_only_team_views is locked to true (CG-21)",
            ));
        }
        Ok(Self::new(raw.retention_days))
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum PolicyError {
    #[error("reserved_rung_quota must be within [0, 1], got {0}")]
    QuotaOutOfRange(f64),
    #[error("redundant assignment (R>1) is a Phase 2 feature (§2.7)")]
    RedundantAssignmentNotYetAvailable,
    #[error("rotation cadence must be at least one day")]
    ZeroRotationCadence,
    #[error("withdrawal spacing must start at one day or more")]
    ZeroWithdrawalInterval,
    #[error("only the current project owner's approval can change ownership (D11)")]
    NotOwner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasteryPolicy {
    pub mode: MasteryMode,
    /// Agent proposes, human confirms (§2.4).
    pub criticality_tags: BTreeSet<String>,
    pub assignment: Assignment,
    /// CG-10: minimum fraction of graduated, criticality-tagged work
    /// reserved for humans.
    pub reserved_rung_quota: f64,
    pub withdrawal_cadence: SpacingParams,
    pub rotation: RotationPolicy,
    pub hunt: HuntPolicy,
    pub ledger_governance: LedgerGovernance,
    pub owner: ActorId,
}

/// Declared purpose of all ledger data (CG-23). There is deliberately no
/// API anywhere in this crate for attaching performance targets to ledger
/// or hunt statistics, and no appraisal export.
pub const DECLARED_PURPOSE: &str = "developmental";

impl MasteryPolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if !(0.0..=1.0).contains(&self.reserved_rung_quota) {
            return Err(PolicyError::QuotaOutOfRange(self.reserved_rung_quota));
        }
        if matches!(self.assignment, Assignment::Redundant(_)) {
            return Err(PolicyError::RedundantAssignmentNotYetAvailable);
        }
        if self.rotation.cadence_days == 0 {
            return Err(PolicyError::ZeroRotationCadence);
        }
        if self.withdrawal_cadence.initial_interval_days == 0 {
            return Err(PolicyError::ZeroWithdrawalInterval);
        }
        Ok(())
    }

    /// Owner changes pass a lightweight gate (D11): the approval token must
    /// have been minted for the current owner.
    pub fn set_owner(
        &mut self,
        new_owner: ActorId,
        approval: &crate::gate::ApprovalToken,
    ) -> Result<(), PolicyError> {
        if approval.approved_by != self.owner {
            return Err(PolicyError::NotOwner);
        }
        self.owner = new_owner;
        Ok(())
    }

    /// Sensible defaults for the conversation workflow profile.
    pub fn conversation_default(owner: ActorId) -> Self {
        Self {
            mode: MasteryMode::Hybrid { sample: 3 },
            criticality_tags: BTreeSet::new(),
            assignment: Assignment::Single,
            reserved_rung_quota: 0.2,
            withdrawal_cadence: SpacingParams {
                initial_interval_days: 7,
                multiplier: 1.5,
                max_interval_days: 90,
            },
            rotation: RotationPolicy {
                cadence_days: 14,
                eligible_roles: vec![
                    Role::Specifier,
                    Role::Designer,
                    Role::Developer,
                    Role::Tester,
                ],
                human_only_roles: BTreeMap::new(),
            },
            hunt: HuntPolicy { stake_escalation: true, max_ladder_depth: 5 },
            ledger_governance: LedgerGovernance::new(365),
            owner,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> MasteryPolicy {
        MasteryPolicy::conversation_default("human:owner".into())
    }

    #[test]
    fn cg10_default_policy_validates_with_quota_in_range() {
        let p = policy();
        assert!(p.validate().is_ok());
        assert!(p.reserved_rung_quota > 0.0);
    }

    #[test]
    fn cg10_quota_out_of_range_is_rejected() {
        let mut p = policy();
        p.reserved_rung_quota = 1.5;
        assert_eq!(p.validate(), Err(PolicyError::QuotaOutOfRange(1.5)));
    }

    #[test]
    fn redundant_assignment_is_phase_2_and_rejected() {
        let mut p = policy();
        p.assignment = Assignment::Redundant(2);
        assert_eq!(
            p.validate(),
            Err(PolicyError::RedundantAssignmentNotYetAvailable)
        );
    }

    #[test]
    fn cg21_aggregate_only_team_views_is_locked_true() {
        let g = LedgerGovernance::new(30);
        assert!(g.aggregate_only_team_views());
        // Deserialising an explicit false must fail.
        let err = serde_json::from_str::<LedgerGovernance>(
            r#"{"retention_days":30,"aggregate_only_team_views":false}"#,
        );
        assert!(err.is_err());
        // Omitting the field defaults to the locked value.
        let ok = serde_json::from_str::<LedgerGovernance>(r#"{"retention_days":30}"#)
            .unwrap();
        assert!(ok.aggregate_only_team_views());
    }

    #[test]
    fn cg23_purpose_is_declared_developmental() {
        assert_eq!(DECLARED_PURPOSE, "developmental");
    }

    #[test]
    fn owner_change_requires_current_owner_approval() {
        use crate::gate::ApprovalToken;
        use wyrtloom_core::types::Timestamp;

        let mut p = policy();
        let stranger_token = ApprovalToken {
            id: uuid::Uuid::new_v4(),
            task: uuid::Uuid::new_v4(),
            gate: "policy-change".into(),
            approved_by: "human:stranger".into(),
            at: Timestamp::now(),
            blame_notice: crate::gate::BLAME_NOTICE.into(),
        };
        assert_eq!(
            p.set_owner("human:next".into(), &stranger_token),
            Err(PolicyError::NotOwner)
        );

        let owner_token = ApprovalToken {
            approved_by: "human:owner".into(),
            ..stranger_token
        };
        assert!(p.set_owner("human:next".into(), &owner_token).is_ok());
        assert_eq!(p.owner, "human:next");
    }

    #[test]
    fn policy_round_trips_through_serde() {
        let p = policy();
        let json = serde_json::to_string(&p).unwrap();
        let back: MasteryPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.validate().is_ok());
        assert_eq!(back.owner, p.owner);
    }
}
