/// W1 — Workflow profile: declares stages, gate placement, and task
/// profiles per stage (§2.2). The entire addendum is a profile +
/// plugin-layer construct: stages are Kanban columns, gates are guarded
/// transitions, and per-stage task profiles bound cost via the call logger.
use crate::gate::Gate;
use crate::policy::MasteryPolicy;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wyrtloom_core::kanban::{is_legal_transition, TaskState};
use wyrtloom_core::profile::TaskProfile;
use wyrtloom_core::types::ActorId;

/// §2.7: the four practices ship behind profile flags in v-next.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeatureFlags {
    pub hunt: bool,
    pub build_own: bool,
    pub withdrawal: bool,
    pub rotation: bool,
    pub insight_artifacts: bool,
    pub interest_router: bool,
}

impl FeatureFlags {
    pub fn all_enabled() -> Self {
        Self {
            hunt: true,
            build_own: true,
            withdrawal: true,
            rotation: true,
            insight_artifacts: true,
            interest_router: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageProfile {
    pub stage: TaskState,
    pub profile: TaskProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowProfile {
    pub id: String,
    /// Stages are Kanban columns — no new state machine.
    pub stages: Vec<TaskState>,
    /// Gates are guarded transitions requiring an escalation-interface
    /// approval token.
    pub gates: Vec<Gate>,
    pub stage_profiles: Vec<StageProfile>,
    pub flags: FeatureFlags,
    pub policy: MasteryPolicy,
}

#[derive(Error, Debug)]
pub enum ProfileError {
    #[error("gate '{0}' guards a transition the kanban contract does not allow")]
    GateOffTheBoard(String),
    #[error(transparent)]
    Policy(#[from] crate::policy::PolicyError),
}

impl WorkflowProfile {
    pub fn validate(&self) -> Result<(), ProfileError> {
        for gate in &self.gates {
            if !is_legal_transition(&gate.from, &gate.to) {
                return Err(ProfileError::GateOffTheBoard(gate.id.clone()));
            }
        }
        self.policy.validate()?;
        Ok(())
    }

    /// The conversation workflow, v0.1: gates at Ready→Running (design
    /// review) and Running→Done (ship review); all four practices enabled.
    pub fn conversation_v01(owner: ActorId) -> Self {
        Self {
            id: "workflow-conversation-v0.1".into(),
            stages: vec![
                TaskState::Backlog,
                TaskState::Todo,
                TaskState::Ready,
                TaskState::Running,
                TaskState::Done,
                TaskState::Archived,
            ],
            gates: vec![
                Gate {
                    id: "design-review".into(),
                    from: TaskState::Ready,
                    to: TaskState::Running,
                    concepts_in_play: vec![],
                },
                Gate {
                    id: "ship-review".into(),
                    from: TaskState::Running,
                    to: TaskState::Done,
                    concepts_in_play: vec![],
                },
            ],
            stage_profiles: vec![StageProfile {
                stage: TaskState::Running,
                profile: TaskProfile::default_v01(),
            }],
            flags: FeatureFlags::all_enabled(),
            policy: MasteryPolicy::conversation_default(owner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversation_profile_validates() {
        let p = WorkflowProfile::conversation_v01("human:owner".into());
        assert!(p.validate().is_ok());
        assert_eq!(p.gates.len(), 2);
    }

    #[test]
    fn gates_off_the_kanban_contract_fail_validation() {
        let mut p = WorkflowProfile::conversation_v01("human:owner".into());
        p.gates.push(Gate {
            id: "impossible".into(),
            from: TaskState::Backlog,
            to: TaskState::Done,
            concepts_in_play: vec![],
        });
        assert!(matches!(
            p.validate(),
            Err(ProfileError::GateOffTheBoard(id)) if id == "impossible"
        ));
    }

    #[test]
    fn invalid_policy_fails_profile_validation() {
        let mut p = WorkflowProfile::conversation_v01("human:owner".into());
        p.policy.reserved_rung_quota = -0.1;
        assert!(matches!(p.validate(), Err(ProfileError::Policy(_))));
    }

    #[test]
    fn profile_round_trips_through_serde() {
        let p = WorkflowProfile::conversation_v01("human:owner".into());
        let json = serde_json::to_string(&p).unwrap();
        let back: WorkflowProfile = serde_json::from_str(&json).unwrap();
        assert!(back.validate().is_ok());
        assert_eq!(back.id, p.id);
    }
}
