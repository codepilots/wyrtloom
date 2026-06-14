//! W1 — Workflow profile (plugin layer).
//!
//! Implements spec §2.2 row W1: a typed, in-memory configuration object that
//! declares the stages of a Wyrtloom workflow (each mapped onto a core Kanban
//! column / [`TaskState`]), where gates are placed between stages, and the
//! per-stage [`TaskProfile`] that bounds an agent's execution environment.
//!
//! Design constraints honoured here:
//!
//! * **CG-1 (gate placement).** Gates are guarded Kanban transitions. This
//!   profile declares *where* gates sit (the `(from, to)` stage pair); the
//!   actual digest-before-challenge behaviour and approval-token emission is
//!   W2's responsibility. A gate is only legal between two adjacent declared
//!   stages whose underlying core transition is itself legal — so a gate can
//!   never be placed on an edge the core Kanban state machine forbids.
//! * **CG-4 (determinism).** All validation here is pure, deterministic Rust.
//!   No LLM is consulted to decide whether a profile is valid; an identical
//!   profile always yields an identical validation result.
//!
//! The profile is serde-loadable from JSON (see [`WorkflowProfile::from_json`]).
//! Core types are reused, never redefined: stages map onto
//! [`wyrtloom_core::kanban::TaskState`] and each stage carries a
//! [`wyrtloom_core::profile::TaskProfile`].

use serde::{Deserialize, Serialize};
use thiserror::Error;
use wyrtloom_core::kanban::{is_legal_transition, TaskState};
use wyrtloom_core::profile::TaskProfile;

/// A single declared stage of the workflow.
///
/// A stage is a human-facing Kanban *column*; it is backed by exactly one core
/// [`TaskState`] so the board's legal-transition machinery still governs how
/// work moves. The stage also carries the [`TaskProfile`] that bounds any agent
/// executing work while a task sits in this column (D2 — per-stage cost bound).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage {
    /// Unique, non-empty stage name (the Kanban column label).
    pub name: String,
    /// The core Kanban state this stage maps onto.
    pub state: TaskState,
    /// Per-stage task profile bounding agent execution in this column.
    pub task_profile: TaskProfile,
}

/// A gate placed on the transition between two declared stages.
///
/// CG-1: a gate marks a *guarded* transition. The workflow profile only records
/// placement (which edge is gated); W2 (the gate engine) enforces the
/// instruction-first digest and validates the escalation-interface approval
/// token at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gate {
    /// Name of the declared stage the gated transition leaves.
    pub from_stage: String,
    /// Name of the declared stage the gated transition enters.
    pub to_stage: String,
}

/// A typed, in-memory workflow profile (spec §2.2 W1).
///
/// `stages` is *ordered*: the declared order is the intended forward path of
/// work through the board and is validated to be a legal subset of the core
/// Kanban state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowProfile {
    /// Human-readable profile identifier.
    pub id: String,
    /// Ordered stages (forward path through the board).
    pub stages: Vec<Stage>,
    /// Gate placements between declared stages (CG-1).
    pub gates: Vec<Gate>,
}

/// Validation failures for a [`WorkflowProfile`].
///
/// Every variant is produced by pure, deterministic checks (CG-4).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("a workflow profile must declare at least one stage")]
    NoStages,
    #[error("stage name must not be empty")]
    EmptyStageName,
    #[error("duplicate stage name: {0}")]
    DuplicateStageName(String),
    #[error("duplicate core state {state:?} mapped by stages {first:?} and {second:?}")]
    DuplicateState {
        state: TaskState,
        first: String,
        second: String,
    },
    #[error("gate references undeclared stage: {0}")]
    GateReferencesUndeclaredStage(String),
    #[error(
        "gate from {from:?} to {to:?} is not placed on an adjacent declared-stage edge"
    )]
    GateNotOnDeclaredEdge { from: String, to: String },
    #[error(
        "stage order is not a legal subset of the core Kanban state machine: \
         {from:?} -> {to:?} is an illegal transition"
    )]
    IllegalStageOrder { from: TaskState, to: TaskState },
    #[error("invalid JSON: {0}")]
    Json(String),
}

impl WorkflowProfile {
    /// Deserialize a workflow profile from JSON and validate it.
    ///
    /// Loading and validation are deliberately coupled: there is no way to
    /// obtain a *valid* profile without passing the deterministic checks (CG-4).
    pub fn from_json(json: &str) -> Result<Self, ProfileError> {
        let profile: WorkflowProfile =
            serde_json::from_str(json).map_err(|e| ProfileError::Json(e.to_string()))?;
        profile.validate()?;
        Ok(profile)
    }

    /// The ordered core states declared by this profile, in stage order.
    pub fn state_order(&self) -> Vec<TaskState> {
        self.stages.iter().map(|s| s.state.clone()).collect()
    }

    /// Look up a declared stage by name.
    pub fn stage(&self, name: &str) -> Option<&Stage> {
        self.stages.iter().find(|s| s.name == name)
    }

    /// Validate the profile.
    ///
    /// Checks (all deterministic, CG-4):
    /// 1. At least one stage is declared.
    /// 2. Stage names are non-empty and unique.
    /// 3. No two stages map onto the same core [`TaskState`].
    /// 4. The declared stage order is a legal subset of the core Kanban state
    ///    machine — every adjacent pair is a legal core transition.
    /// 5. Every gate references declared stages, and sits on an adjacent
    ///    declared-stage edge (CG-1 placement).
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.stages.is_empty() {
            return Err(ProfileError::NoStages);
        }

        // (2) + (3): names and state mappings are unique.
        for (i, stage) in self.stages.iter().enumerate() {
            if stage.name.trim().is_empty() {
                return Err(ProfileError::EmptyStageName);
            }
            for other in &self.stages[i + 1..] {
                if stage.name == other.name {
                    return Err(ProfileError::DuplicateStageName(stage.name.clone()));
                }
                if stage.state == other.state {
                    return Err(ProfileError::DuplicateState {
                        state: stage.state.clone(),
                        first: stage.name.clone(),
                        second: other.name.clone(),
                    });
                }
            }
        }

        // (4): declared order is a legal subset of the core state machine.
        for pair in self.stages.windows(2) {
            let from = &pair[0].state;
            let to = &pair[1].state;
            if !is_legal_transition(from, to) {
                return Err(ProfileError::IllegalStageOrder {
                    from: from.clone(),
                    to: to.clone(),
                });
            }
        }

        // (5): gate placement — references declared stages and sits on an
        // adjacent declared-stage edge (CG-1).
        for gate in &self.gates {
            let from = self.stage(&gate.from_stage).ok_or_else(|| {
                ProfileError::GateReferencesUndeclaredStage(gate.from_stage.clone())
            })?;
            let to = self.stage(&gate.to_stage).ok_or_else(|| {
                ProfileError::GateReferencesUndeclaredStage(gate.to_stage.clone())
            })?;
            if !is_adjacent_declared_edge(&self.stages, &from.name, &to.name) {
                return Err(ProfileError::GateNotOnDeclaredEdge {
                    from: from.name.clone(),
                    to: to.name.clone(),
                });
            }
        }

        Ok(())
    }
}

/// True iff `to` immediately follows `from` in the declared stage order.
///
/// Gate placement (CG-1) is only meaningful on a forward edge that the profile
/// actually declares; because the declared order is itself validated to be a
/// legal core subset (check 4), an adjacent edge is guaranteed to be a legal
/// core transition.
fn is_adjacent_declared_edge(stages: &[Stage], from: &str, to: &str) -> bool {
    stages
        .windows(2)
        .any(|w| w[0].name == from && w[1].name == to)
}

#[cfg(test)]
mod tests {
    //! Contract tests — written test-first (TDD is core to Wyrtloom).
    use super::*;
    use wyrtloom_core::profile::TaskProfile;

    fn stage(name: &str, state: TaskState) -> Stage {
        Stage {
            name: name.into(),
            state,
            task_profile: TaskProfile::default_v01(),
        }
    }

    /// A canonical, fully-legal profile covering a forward slice of the core
    /// state machine: Backlog -> Todo -> Ready -> Running -> Done -> Archived.
    fn canonical() -> WorkflowProfile {
        WorkflowProfile {
            id: "canonical".into(),
            stages: vec![
                stage("inbox", TaskState::Backlog),
                stage("queued", TaskState::Todo),
                stage("ready", TaskState::Ready),
                stage("running", TaskState::Running),
                stage("done", TaskState::Done),
                stage("archived", TaskState::Archived),
            ],
            gates: vec![Gate {
                from_stage: "ready".into(),
                to_stage: "running".into(),
            }],
        }
    }

    #[test]
    fn canonical_profile_validates() {
        assert!(canonical().validate().is_ok());
    }

    #[test]
    fn empty_profile_rejected() {
        let p = WorkflowProfile {
            id: "empty".into(),
            stages: vec![],
            gates: vec![],
        };
        assert_eq!(p.validate(), Err(ProfileError::NoStages));
    }

    #[test]
    fn empty_stage_name_rejected() {
        let mut p = canonical();
        p.stages[0].name = "  ".into();
        assert_eq!(p.validate(), Err(ProfileError::EmptyStageName));
    }

    #[test]
    fn duplicate_stage_name_rejected() {
        let mut p = canonical();
        p.stages[1].name = "inbox".into();
        assert_eq!(
            p.validate(),
            Err(ProfileError::DuplicateStageName("inbox".into()))
        );
    }

    #[test]
    fn duplicate_state_mapping_rejected() {
        let mut p = canonical();
        // Two stages now both map to Todo.
        p.stages[2].state = TaskState::Todo;
        match p.validate() {
            Err(ProfileError::DuplicateState { state, .. }) => {
                assert_eq!(state, TaskState::Todo);
            }
            other => panic!("expected DuplicateState, got {other:?}"),
        }
    }

    #[test]
    fn gate_referencing_undeclared_stage_rejected() {
        let mut p = canonical();
        p.gates = vec![Gate {
            from_stage: "ready".into(),
            to_stage: "nowhere".into(),
        }];
        assert_eq!(
            p.validate(),
            Err(ProfileError::GateReferencesUndeclaredStage("nowhere".into()))
        );
    }

    #[test]
    fn gate_not_on_declared_edge_rejected() {
        let mut p = canonical();
        // inbox -> running is not an adjacent declared edge.
        p.gates = vec![Gate {
            from_stage: "inbox".into(),
            to_stage: "running".into(),
        }];
        assert_eq!(
            p.validate(),
            Err(ProfileError::GateNotOnDeclaredEdge {
                from: "inbox".into(),
                to: "running".into(),
            })
        );
    }

    #[test]
    fn illegal_stage_order_rejected() {
        // Backlog -> Running is illegal in the core state machine.
        let p = WorkflowProfile {
            id: "bad-order".into(),
            stages: vec![
                stage("inbox", TaskState::Backlog),
                stage("running", TaskState::Running),
            ],
            gates: vec![],
        };
        assert_eq!(
            p.validate(),
            Err(ProfileError::IllegalStageOrder {
                from: TaskState::Backlog,
                to: TaskState::Running,
            })
        );
    }

    #[test]
    fn serde_roundtrip_via_json() {
        let json = serde_json::to_string(&canonical()).unwrap();
        let loaded = WorkflowProfile::from_json(&json).expect("valid profile loads");
        assert_eq!(loaded.state_order(), canonical().state_order());
        assert_eq!(loaded.id, "canonical");
    }

    #[test]
    fn from_json_rejects_invalid_profile() {
        // Valid JSON, but Backlog -> Running is an illegal stage order.
        let bad = WorkflowProfile {
            id: "bad".into(),
            stages: vec![
                stage("a", TaskState::Backlog),
                stage("b", TaskState::Running),
            ],
            gates: vec![],
        };
        let json = serde_json::to_string(&bad).unwrap();
        assert!(matches!(
            WorkflowProfile::from_json(&json),
            Err(ProfileError::IllegalStageOrder { .. })
        ));
    }

    #[test]
    fn from_json_rejects_malformed_json() {
        assert!(matches!(
            WorkflowProfile::from_json("{ not json"),
            Err(ProfileError::Json(_))
        ));
    }

    /// CORE INTEGRATION TEST (required).
    ///
    /// Map declared stages onto real `wyrtloom_core::kanban::TaskState` and
    /// assert that the profile's stage order is a legal subset of core's state
    /// machine: Backlog -> Todo -> Ready -> Running -> Blocked -> Done ->
    /// Archived. Every adjacent declared transition must be accepted by core's
    /// own `is_legal_transition`.
    #[test]
    fn stage_order_is_legal_subset_of_core_state_machine() {
        let p = WorkflowProfile {
            id: "full-path".into(),
            stages: vec![
                stage("backlog", TaskState::Backlog),
                stage("todo", TaskState::Todo),
                stage("ready", TaskState::Ready),
                stage("running", TaskState::Running),
                stage("blocked", TaskState::Blocked),
                stage("done", TaskState::Done),
                stage("archived", TaskState::Archived),
            ],
            gates: vec![],
        };

        // The profile itself accepts the order...
        assert!(p.validate().is_ok());

        // ...and independently, core's own contract agrees every adjacent edge
        // is legal — proving we ride the core state machine rather than
        // redefining it.
        for pair in p.stages.windows(2) {
            assert!(
                is_legal_transition(&pair[0].state, &pair[1].state),
                "core rejected declared edge {:?} -> {:?}",
                pair[0].state,
                pair[1].state
            );
        }

        // Negative control: a non-subset order is rejected by both.
        assert!(!is_legal_transition(&TaskState::Backlog, &TaskState::Done));
    }
}
