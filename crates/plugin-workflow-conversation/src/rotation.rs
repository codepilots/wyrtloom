/// W12 — Role rotation (CG-16..17): human and AI rotate among specifier,
/// designer, developer, and tester on a deterministic schedule. Handoffs
/// ride the existing typed agent-message contracts — rotation is policy,
/// not new core.
use crate::policy::RotationPolicy;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wyrtloom_core::agent::{AgentMessage, MessageError};
use wyrtloom_core::types::{ActorId, TaskId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Specifier,
    Designer,
    Developer,
    Tester,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub id: ActorId,
    pub is_human: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub actor: ActorId,
    pub is_human: bool,
    pub role: Role,
}

#[derive(Error, Debug, PartialEq)]
pub enum RotationError {
    #[error("no eligible roles configured")]
    NoRoles,
    #[error("criticality tag '{0}' requires a human for role {1:?}, but no human can take it")]
    NoHumanForCriticalRole(String, Role),
}

/// Deterministic rotation (CG-16): participant i takes eligible role
/// (i + period) mod roles.len(), so every period shifts every mental model.
/// Criticality overrides (CG-17) then force the configured roles onto
/// humans by deterministic swap.
pub fn assign(
    period: u32,
    participants: &[Participant],
    policy: &RotationPolicy,
    item_tag: Option<&str>,
) -> Result<Vec<RoleAssignment>, RotationError> {
    let roles = &policy.eligible_roles;
    if roles.is_empty() {
        return Err(RotationError::NoRoles);
    }

    let mut assignments: Vec<RoleAssignment> = participants
        .iter()
        .enumerate()
        .map(|(i, p)| RoleAssignment {
            actor: p.id.clone(),
            is_human: p.is_human,
            role: roles[(i + period as usize) % roles.len()],
        })
        .collect();

    if let Some(tag) = item_tag {
        if let Some(must_be_human) = policy.human_only_roles.get(tag) {
            for role in must_be_human {
                let Some(holder) = assignments.iter().position(|a| a.role == *role) else {
                    continue;
                };
                if assignments[holder].is_human {
                    continue;
                }
                // Swap with the first human not already pinned to a
                // human-only role.
                let swap = assignments
                    .iter()
                    .position(|a| a.is_human && !must_be_human.contains(&a.role));
                match swap {
                    Some(s) => {
                        let displaced = assignments[s].role;
                        assignments[s].role = *role;
                        assignments[holder].role = displaced;
                    }
                    None => {
                        return Err(RotationError::NoHumanForCriticalRole(tag.into(), *role))
                    }
                }
            }
        }
    }

    Ok(assignments)
}

/// CG-16: handoffs ride the existing typed agent-message contracts. The
/// assignment travels as a validated Delegation message.
pub fn handoff(assignment: &RoleAssignment, origin_task: TaskId) -> Result<AgentMessage, MessageError> {
    let body = serde_json::to_vec(assignment)
        .map_err(|e| MessageError::Malformed(e.to_string()))?;
    let message = AgentMessage::Delegation { origin_task, hops: 0, body };
    message.validate()?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn participants() -> Vec<Participant> {
        vec![
            Participant { id: "human:alice".into(), is_human: true },
            Participant { id: "agent:wyrt".into(), is_human: false },
        ]
    }

    fn policy() -> RotationPolicy {
        RotationPolicy {
            cadence_days: 14,
            eligible_roles: vec![Role::Specifier, Role::Designer, Role::Developer, Role::Tester],
            human_only_roles: BTreeMap::new(),
        }
    }

    #[test]
    fn cg16_rotation_is_deterministic_and_shifts_each_period() {
        let p0 = assign(0, &participants(), &policy(), None).unwrap();
        let p0_again = assign(0, &participants(), &policy(), None).unwrap();
        assert_eq!(p0[0].role, p0_again[0].role, "same period, same assignment");

        let p1 = assign(1, &participants(), &policy(), None).unwrap();
        assert_ne!(p0[0].role, p1[0].role, "a new period rotates the roles");
        assert_eq!(p0[0].role, Role::Specifier);
        assert_eq!(p1[0].role, Role::Designer);
    }

    #[test]
    fn cg16_handoff_rides_the_typed_message_contract() {
        let assignment = RoleAssignment {
            actor: "human:alice".into(),
            is_human: true,
            role: Role::Tester,
        };
        let task = Uuid::new_v4();
        let message = handoff(&assignment, task).unwrap();
        assert!(matches!(message, AgentMessage::Delegation { .. }));
        assert_eq!(message.origin_task(), task);
        assert!(message.validate().is_ok());
    }

    #[test]
    fn cg17_criticality_override_forces_role_onto_a_human() {
        let mut policy = policy();
        policy
            .human_only_roles
            .insert("safety-critical".into(), vec![Role::Specifier]);

        // Period 3: alice (index 0) gets Tester, agent (index 1) gets Specifier.
        let assignments =
            assign(3, &participants(), &policy, Some("safety-critical")).unwrap();
        let specifier = assignments.iter().find(|a| a.role == Role::Specifier).unwrap();
        assert!(specifier.is_human, "specifier must be human for this tag");
    }

    #[test]
    fn cg17_no_human_available_for_critical_role_errors() {
        let mut policy = policy();
        policy
            .human_only_roles
            .insert("safety-critical".into(), vec![Role::Specifier]);
        let agents_only = vec![
            Participant { id: "agent:one".into(), is_human: false },
            Participant { id: "agent:two".into(), is_human: false },
        ];
        // Period 0: agent:one holds Specifier and no human exists to swap in.
        let result = assign(0, &agents_only, &policy, Some("safety-critical"));
        assert!(matches!(result, Err(RotationError::NoHumanForCriticalRole(_, _))));
    }

    #[test]
    fn untagged_items_skip_the_overrides() {
        let mut policy = policy();
        policy
            .human_only_roles
            .insert("safety-critical".into(), vec![Role::Specifier]);
        // Same period-3 layout, but the item carries no tag — no swap.
        let assignments = assign(3, &participants(), &policy, None).unwrap();
        let specifier = assignments.iter().find(|a| a.role == Role::Specifier).unwrap();
        assert!(!specifier.is_human);
    }

    #[test]
    fn empty_role_list_is_an_error() {
        let mut policy = policy();
        policy.eligible_roles.clear();
        assert!(matches!(
            assign(0, &participants(), &policy, None),
            Err(RotationError::NoRoles)
        ));
    }
}
