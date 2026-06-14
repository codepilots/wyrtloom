//! Contract tests for the W12 rotation scheduler.
//!
//! These are written test-first: they pin the public behaviour required by
//! spec §2.2 (W12) and CG-16 / CG-17 before the implementation exists.
//!
//! CG-16 — rotation assigns specifier/designer/developer/tester roles to
//!         human and agent over the typed handoff contracts (`AgentMessage`).
//! CG-17 — cadence and eligible roles are policy fields; criticality
//!         overrides (e.g. human-only specifier) are respected.
//! CG-4  — assignment is deterministic; no LLM is involved.

use plugin_rotation_scheduler::{
    Actor, Criticality, Role, RotationItem, RotationPolicy, RotationScheduler,
};
use uuid::Uuid;
use wyrtloom_core::agent::AgentMessage;
use wyrtloom_core::types::{ActorId, TaskId};

fn human() -> ActorId {
    "human:alice".to_string()
}

fn agent() -> ActorId {
    "agent:builder".to_string()
}

/// A default policy: all four roles eligible, both actors in the roster,
/// cadence of 1 (rotate every item), no overrides.
fn default_policy() -> RotationPolicy {
    RotationPolicy::new(
        vec![
            Role::Specifier,
            Role::Designer,
            Role::Developer,
            Role::Tester,
        ],
        vec![
            Actor::new(human(), true),
            Actor::new(agent(), false),
        ],
        1,
    )
}

fn item(task: TaskId, crit: Criticality) -> RotationItem {
    RotationItem { origin_task: task, criticality: crit }
}

/// CG-4 / CG-16 — the same inputs always produce the same assignment.
#[test]
fn assignment_is_deterministic() {
    let policy = default_policy();
    let sched = RotationScheduler::new(policy);
    let task = Uuid::new_v4();
    let it = item(task, Criticality::Normal);

    let a = sched.assign(&it, 0).unwrap();
    let b = sched.assign(&it, 0).unwrap();
    assert_eq!(a, b, "assignment must be a pure function of its inputs");
}

/// CG-16 — every eligible role gets an actor assigned.
#[test]
fn every_eligible_role_is_assigned() {
    let policy = default_policy();
    let sched = RotationScheduler::new(policy);
    let it = item(Uuid::new_v4(), Criticality::Normal);

    let assignment = sched.assign(&it, 0).unwrap();
    for role in [Role::Specifier, Role::Designer, Role::Developer, Role::Tester] {
        assert!(
            assignment.actor_for(role).is_some(),
            "role {:?} must have an actor",
            role
        );
    }
}

/// CG-16 — rotation advances: assignment depends on the cycle index, so a
/// later cycle differs from the first (roles rotate across actors).
#[test]
fn roles_rotate_across_cycles() {
    let policy = default_policy();
    let sched = RotationScheduler::new(policy);
    let it = item(Uuid::new_v4(), Criticality::Normal);

    let cycle0 = sched.assign(&it, 0).unwrap();
    let cycle1 = sched.assign(&it, 1).unwrap();
    assert_ne!(
        cycle0.actor_for(Role::Specifier),
        cycle1.actor_for(Role::Specifier),
        "the specifier should change as the rotation advances"
    );
}

/// CG-17 — a criticality override forces the specifier to be human for a
/// tagged (safety-critical) item, regardless of cycle index.
#[test]
fn criticality_override_forces_human_specifier() {
    let mut policy = default_policy();
    policy.force_human(Role::Specifier, Criticality::SafetyCritical);
    let sched = RotationScheduler::new(policy);

    let it = item(Uuid::new_v4(), Criticality::SafetyCritical);
    // Try several cycles — the override must hold at every one.
    for cycle in 0..8 {
        let a = sched.assign(&it, cycle).unwrap();
        let specifier = a.actor_for(Role::Specifier).unwrap();
        assert_eq!(specifier, &human(), "specifier must be forced human at cycle {cycle}");
    }
}

/// CG-17 — without the matching criticality tag, the override does not apply.
#[test]
fn override_does_not_apply_to_untagged_items() {
    let mut policy = default_policy();
    policy.force_human(Role::Specifier, Criticality::SafetyCritical);
    let sched = RotationScheduler::new(policy);

    // A normal item can still land the agent on the specifier role at some cycle.
    let it = item(Uuid::new_v4(), Criticality::Normal);
    let landed_on_agent = (0..8).any(|c| {
        sched.assign(&it, c).unwrap().actor_for(Role::Specifier) == Some(&agent())
    });
    assert!(landed_on_agent, "untagged items should rotate the agent into the specifier role");
}

/// CORE INTEGRATION — assignment produces valid `AgentMessage::Delegation`
/// handoffs between actors that carry the `origin_task`.
#[test]
fn produces_valid_delegation_handoffs_carrying_origin_task() {
    let policy = default_policy();
    let sched = RotationScheduler::new(policy);
    let task = Uuid::new_v4();
    let it = item(task, Criticality::Normal);

    let assignment = sched.assign(&it, 0).unwrap();
    let handoffs = assignment.handoffs();

    // One handoff per ordered role transition (specifier->designer->developer->tester) = 3.
    assert_eq!(handoffs.len(), 3, "expected one delegation per role transition");

    for msg in &handoffs {
        assert!(matches!(msg, AgentMessage::Delegation { .. }));
        assert_eq!(msg.origin_task(), task, "delegation must carry the origin task");
        assert!(msg.validate().is_ok(), "delegation must be a valid AgentMessage");
    }
}

/// Empty eligible-roles list is a configuration error.
#[test]
fn empty_roles_is_an_error() {
    let policy = RotationPolicy::new(vec![], vec![Actor::new(human(), true)], 1);
    let sched = RotationScheduler::new(policy);
    let it = item(Uuid::new_v4(), Criticality::Normal);
    assert!(sched.assign(&it, 0).is_err());
}

/// Empty roster is a configuration error.
#[test]
fn empty_roster_is_an_error() {
    let policy = RotationPolicy::new(vec![Role::Specifier], vec![], 1);
    let sched = RotationScheduler::new(policy);
    let it = item(Uuid::new_v4(), Criticality::Normal);
    assert!(sched.assign(&it, 0).is_err());
}

/// CG-17 — if an override demands a human but no human is in the roster, the
/// scheduler must error rather than silently assigning an agent.
#[test]
fn human_override_without_human_in_roster_errors() {
    let mut policy = RotationPolicy::new(
        vec![Role::Specifier, Role::Developer],
        vec![Actor::new(agent(), false)],
        1,
    );
    policy.force_human(Role::Specifier, Criticality::SafetyCritical);
    let sched = RotationScheduler::new(policy);
    let it = item(Uuid::new_v4(), Criticality::SafetyCritical);
    assert!(sched.assign(&it, 0).is_err());
}
