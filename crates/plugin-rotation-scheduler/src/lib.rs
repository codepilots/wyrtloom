//! W12 — Rotation scheduler (`plugin-rotation-scheduler`).
//!
//! Assigns the specifier / designer / developer / tester roles to human and
//! agent actors and emits the resulting hand-offs over the existing typed
//! contract [`wyrtloom_core::agent::AgentMessage`].
//!
//! Spec mapping:
//!   * §2.2 row W12 — "Rotation scheduler — role assignment over typed
//!     handoff contracts".
//!   * CG-16 — rotation SHALL assign specifier/designer/developer/tester
//!     roles to human and agent over the existing typed handoff contracts.
//!   * CG-17 — rotation cadence and eligible roles SHALL be mastery-policy
//!     fields; rotation SHALL respect criticality tags (e.g. human-only
//!     specifier for safety-critical items if so configured).
//!   * CG-4 — scheduling decisions SHALL be deterministic; no LLM grades or
//!     decides anything. [`RotationScheduler::assign`] is a pure function of
//!     `(roster, cadence, eligible_roles, criticality, cycle)`.
//!
//! Design note: roles and criticality tags are defined locally as a minimal
//! config so this crate does not depend on sibling W-crates (e.g.
//! mastery-policy). A real deployment would project the relevant
//! mastery-policy fields onto [`RotationPolicy`].

use serde::{Deserialize, Serialize};
use thiserror::Error;
use wyrtloom_core::agent::AgentMessage;
use wyrtloom_core::types::{ActorId, TaskId};

/// The four roles that rotate across a work item (CG-16).
///
/// The discriminant order is also the canonical hand-off order
/// (specifier → designer → developer → tester).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Specifier,
    Designer,
    Developer,
    Tester,
}

impl Role {
    /// The four roles in canonical hand-off order.
    pub const ORDER: [Role; 4] = [
        Role::Specifier,
        Role::Designer,
        Role::Developer,
        Role::Tester,
    ];

    /// Stable index used to deterministically offset the rotation per role
    /// (CG-4). Independent of any `Hash` implementation.
    fn ordinal(self) -> usize {
        match self {
            Role::Specifier => 0,
            Role::Designer => 1,
            Role::Developer => 2,
            Role::Tester => 3,
        }
    }
}

/// Criticality tag for a work item (CG-17). Agent proposes, human confirms
/// (per spec §2.4) — here we only carry the confirmed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Criticality {
    Normal,
    SafetyCritical,
}

/// An actor eligible to take roles in the rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub id: ActorId,
    /// Whether this actor is a human (vs. an agent). Used to satisfy
    /// human-only criticality overrides (CG-17).
    pub is_human: bool,
}

impl Actor {
    pub fn new(id: ActorId, is_human: bool) -> Self {
        Self { id, is_human }
    }
}

/// A single criticality override: for items tagged with `when`, the given
/// `role` must be filled by a human (CG-17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HumanOverride {
    role: Role,
    when: Criticality,
}

/// Rotation configuration — the subset of the mastery policy this scheduler
/// needs (CG-17).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Roles eligible to be assigned, in canonical order.
    eligible_roles: Vec<Role>,
    /// The roster of actors that take part in the rotation.
    roster: Vec<Actor>,
    /// Cadence: how many work-item cycles share the same assignment before
    /// the rotation advances by one step. Must be >= 1; values < 1 are
    /// clamped to 1 so the rotation always makes progress.
    cadence: u64,
    /// Criticality overrides (e.g. human-only specifier).
    overrides: Vec<HumanOverride>,
}

impl RotationPolicy {
    /// Build a policy from eligible roles, a roster, and a cadence.
    pub fn new(eligible_roles: Vec<Role>, roster: Vec<Actor>, cadence: u64) -> Self {
        Self {
            eligible_roles,
            roster,
            cadence: cadence.max(1),
            overrides: Vec::new(),
        }
    }

    /// Force `role` to be filled by a human whenever an item is tagged with
    /// `when` (CG-17).
    pub fn force_human(&mut self, role: Role, when: Criticality) {
        self.overrides.push(HumanOverride { role, when });
    }

    /// Does any override require `role` to be human for `crit`?
    fn requires_human(&self, role: Role, crit: Criticality) -> bool {
        self.overrides
            .iter()
            .any(|o| o.role == role && o.when == crit)
    }
}

/// A work item to be scheduled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationItem {
    pub origin_task: TaskId,
    pub criticality: Criticality,
}

/// Errors raised by the scheduler.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScheduleError {
    #[error("rotation policy has no eligible roles")]
    NoRoles,
    #[error("rotation policy has an empty roster")]
    EmptyRoster,
    #[error("role {role:?} requires a human but the roster contains none")]
    NoHumanAvailable { role: Role },
}

/// The deterministic result of scheduling one item: a role → actor mapping
/// plus the hand-offs that connect the roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    origin_task: TaskId,
    /// Role → actor, stored in canonical role order.
    slots: Vec<(Role, ActorId)>,
}

impl Assignment {
    /// The actor assigned to `role`, if that role is eligible.
    pub fn actor_for(&self, role: Role) -> Option<&ActorId> {
        self.slots
            .iter()
            .find(|(r, _)| *r == role)
            .map(|(_, a)| a)
    }

    /// The roles, in the order they hand off to one another.
    pub fn roles(&self) -> impl Iterator<Item = Role> + '_ {
        self.slots.iter().map(|(r, _)| *r)
    }

    /// Build the typed hand-off contracts (CG-16): one
    /// [`AgentMessage::Delegation`] per consecutive role transition, each
    /// carrying the `origin_task`. The body names the actors so the
    /// delegation is traceable (`"<from_actor>-><to_actor>"`).
    ///
    /// `hops` is set to the transition index so the chain reflects depth and
    /// passes [`AgentMessage::validate`] under the core hop limit.
    pub fn handoffs(&self) -> Vec<AgentMessage> {
        self.slots
            .windows(2)
            .enumerate()
            .map(|(i, pair)| {
                let (_, from) = &pair[0];
                let (_, to) = &pair[1];
                AgentMessage::Delegation {
                    origin_task: self.origin_task,
                    hops: i as u8,
                    body: format!("{from}->{to}").into_bytes(),
                }
            })
            .collect()
    }
}

/// The W12 rotation scheduler.
pub struct RotationScheduler {
    policy: RotationPolicy,
}

impl RotationScheduler {
    pub fn new(policy: RotationPolicy) -> Self {
        Self { policy }
    }

    /// Deterministically assign actors to every eligible role for `item` at
    /// rotation `cycle` (CG-4 / CG-16 / CG-17).
    ///
    /// The base offset advances once per `cadence` cycles. Each role is then
    /// offset by its ordinal so distinct roles map to distinct actors when
    /// the roster is large enough. Criticality overrides (CG-17) pin a role
    /// to the first human in the roster regardless of the rotation.
    pub fn assign(&self, item: &RotationItem, cycle: u64) -> Result<Assignment, ScheduleError> {
        if self.policy.eligible_roles.is_empty() {
            return Err(ScheduleError::NoRoles);
        }
        if self.policy.roster.is_empty() {
            return Err(ScheduleError::EmptyRoster);
        }

        let roster_len = self.policy.roster.len();
        // Rotation advances one step per `cadence` cycles (CG-17 cadence).
        // Clamp defensively: a policy deserialized straight from JSON bypasses
        // `new`'s clamp, so a `cadence` of 0 must not divide-by-zero here.
        let base = cycle / self.policy.cadence.max(1);

        let mut slots = Vec::with_capacity(self.policy.eligible_roles.len());
        for &role in &self.policy.eligible_roles {
            let actor_id = if self.policy.requires_human(role, item.criticality) {
                // CG-17 — pin to a human. Deterministically pick the first
                // human in roster order.
                self.policy
                    .roster
                    .iter()
                    .find(|a| a.is_human)
                    .map(|a| a.id.clone())
                    .ok_or(ScheduleError::NoHumanAvailable { role })?
            } else {
                // Deterministic round-robin over the roster (CG-4).
                let idx = (base as usize + role.ordinal()) % roster_len;
                self.policy.roster[idx].id.clone()
            };
            slots.push((role, actor_id));
        }

        Ok(Assignment {
            origin_task: item.origin_task,
            slots,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn roster() -> Vec<Actor> {
        vec![
            Actor::new("human:a".into(), true),
            Actor::new("agent:b".into(), false),
        ]
    }

    #[test]
    fn cadence_holds_assignment_across_cycles() {
        // cadence 3 — cycles 0,1,2 share a base; cycle 3 advances.
        let policy = RotationPolicy::new(Role::ORDER.to_vec(), roster(), 3);
        let sched = RotationScheduler::new(policy);
        let it = RotationItem { origin_task: Uuid::new_v4(), criticality: Criticality::Normal };

        let a0 = sched.assign(&it, 0).unwrap();
        let a2 = sched.assign(&it, 2).unwrap();
        let a3 = sched.assign(&it, 3).unwrap();
        assert_eq!(a0, a2, "cadence window shares an assignment");
        assert_ne!(a0, a3, "rotation advances after the cadence window");
    }

    #[test]
    fn cadence_zero_is_clamped_to_one() {
        let policy = RotationPolicy::new(Role::ORDER.to_vec(), roster(), 0);
        assert_eq!(policy.cadence, 1);
    }

    #[test]
    fn deserialized_zero_cadence_does_not_panic() {
        // A policy crafted directly via serde bypasses `new`'s clamp; `assign`
        // must still not divide by zero.
        let json = r#"{"eligible_roles":["Specifier"],
            "roster":[{"id":"human:a","is_human":true}],
            "cadence":0,"overrides":[]}"#;
        let policy: RotationPolicy = serde_json::from_str(json).unwrap();
        let sched = RotationScheduler::new(policy);
        let it = RotationItem { origin_task: Uuid::new_v4(), criticality: Criticality::Normal };
        assert!(sched.assign(&it, 3).is_ok());
    }

    #[test]
    fn policy_round_trips_through_serde() {
        let mut policy = RotationPolicy::new(Role::ORDER.to_vec(), roster(), 2);
        policy.force_human(Role::Specifier, Criticality::SafetyCritical);
        let json = serde_json::to_string(&policy).unwrap();
        let back: RotationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cadence, 2);
        assert!(back.requires_human(Role::Specifier, Criticality::SafetyCritical));
    }
}
