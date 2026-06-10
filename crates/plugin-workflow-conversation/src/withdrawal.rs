/// W11 — Scheduled withdrawal (CG-13..15): on a spaced cadence the AI
/// deliberately absents itself — solo flights in which the human operates
/// the system unassisted. Instructional fading at the system level (F5, F9).
use crate::audit::{WorkflowAudit, WorkflowEventKind};
use crate::calibration::{CalibrationLedger, PracticeEvent, PracticeKind};
use crate::coverage::ConceptId;
use crate::policy::SpacingParams;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wyrtloom_core::types::{ActorId, TaskId, Timestamp};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FlightState {
    Scheduled,
    Active,
    Completed,
    Aborted { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoloFlight {
    pub id: Uuid,
    pub person: ActorId,
    /// The task scope for which the agent is unavailable (CG-14).
    pub scope: Vec<TaskId>,
    pub scheduled_for: Timestamp,
    pub state: FlightState,
}

/// Expanding-interval spacing (CG-13): each completed flight stretches the
/// gap to the next one, up to the configured ceiling.
pub fn next_interval_days(params: &SpacingParams, completed_flights: u32) -> u32 {
    let interval =
        params.initial_interval_days as f64 * params.multiplier.powi(completed_flights as i32);
    (interval.round() as u32)
        .min(params.max_interval_days)
        .max(1)
}

/// CG-13: plan the next solo flight from the person's history.
pub fn schedule(
    person: &ActorId,
    scope: Vec<TaskId>,
    completed_flights: u32,
    last_flight: &Timestamp,
    params: &SpacingParams,
) -> SoloFlight {
    let days = next_interval_days(params, completed_flights);
    SoloFlight {
        id: Uuid::new_v4(),
        person: person.clone(),
        scope,
        scheduled_for: Timestamp(last_flight.0 + chrono::Duration::days(days as i64)),
        state: FlightState::Scheduled,
    }
}

/// CG-14: during an active flight the agent is unavailable for the flagged
/// task scope.
pub fn agent_available(flight: &SoloFlight, task: &TaskId) -> bool {
    !(flight.state == FlightState::Active && flight.scope.contains(task))
}

/// CG-14: explicit human abort — logged, never penalised. No calibration
/// entry is written; the only trace is the audit event.
pub fn abort(flight: &mut SoloFlight, reason: &str, audit: &WorkflowAudit) {
    flight.state = FlightState::Aborted { reason: reason.into() };
    let task = flight.scope.first().copied().unwrap_or_else(Uuid::nil);
    audit.record(
        WorkflowEventKind::Withdrawal,
        task,
        &flight.person,
        &format!("solo flight {} aborted: {} (never penalised)", flight.id, reason),
    );
}

/// CG-15: solo-flight outcomes update the calibration ledger as practice
/// events, not assessments — PracticeKind::SoloFlight is the only shape
/// they can take.
pub fn complete(
    flight: &mut SoloFlight,
    outcomes: &[(ConceptId, f64, bool)],
    ledger: &mut CalibrationLedger,
    audit: &WorkflowAudit,
) {
    flight.state = FlightState::Completed;
    for (concept, confidence, success) in outcomes {
        ledger.record_practice(PracticeEvent {
            concept: concept.clone(),
            confidence: *confidence,
            success: *success,
            kind: PracticeKind::SoloFlight,
            at: Timestamp::now(),
        });
    }
    let task = flight.scope.first().copied().unwrap_or_else(Uuid::nil);
    audit.record(
        WorkflowEventKind::Withdrawal,
        task,
        &flight.person,
        &format!("solo flight {} completed", flight.id),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NoopCallLogger;
    use crate::policy::LedgerGovernance;
    use std::sync::Arc;

    fn params() -> SpacingParams {
        SpacingParams {
            initial_interval_days: 7,
            multiplier: 2.0,
            max_interval_days: 30,
        }
    }

    fn audit() -> WorkflowAudit {
        WorkflowAudit::new(Arc::new(NoopCallLogger))
    }

    #[test]
    fn cg13_intervals_expand_and_cap() {
        let p = params();
        assert_eq!(next_interval_days(&p, 0), 7);
        assert_eq!(next_interval_days(&p, 1), 14);
        assert_eq!(next_interval_days(&p, 2), 28);
        assert_eq!(next_interval_days(&p, 3), 30, "capped at max_interval_days");
    }

    #[test]
    fn cg13_schedule_uses_the_expanding_interval() {
        let last = Timestamp::now();
        let flight = schedule(&"human:dev".into(), vec![], 1, &last, &params());
        assert_eq!(flight.state, FlightState::Scheduled);
        assert_eq!((flight.scheduled_for.0 - last.0).num_days(), 14);
    }

    #[test]
    fn cg14_agent_is_unavailable_for_active_flight_scope() {
        let task = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut flight = schedule(&"human:dev".into(), vec![task], 0, &Timestamp::now(), &params());

        // Not yet active — agent still available.
        assert!(agent_available(&flight, &task));

        flight.state = FlightState::Active;
        assert!(!agent_available(&flight, &task));
        assert!(agent_available(&flight, &other), "outside the flagged scope");
    }

    #[test]
    fn cg14_abort_is_logged_and_never_penalised() {
        let audit = audit();
        let mut ledger =
            CalibrationLedger::new("human:dev".into(), LedgerGovernance::new(365));
        let mut flight =
            schedule(&"human:dev".into(), vec![Uuid::new_v4()], 0, &Timestamp::now(), &params());
        flight.state = FlightState::Active;

        abort(&mut flight, "production incident", &audit);

        assert!(matches!(flight.state, FlightState::Aborted { .. }));
        let trail = audit.snapshot();
        assert_eq!(trail.len(), 1);
        assert!(trail[0].detail.contains("never penalised"));
        // No calibration entry was written.
        assert!(ledger.events(&"human:dev".to_string()).unwrap().is_empty());
        let _ = &mut ledger;
    }

    #[test]
    fn cg15_completion_records_practice_events_not_assessments() {
        let audit = audit();
        let mut ledger =
            CalibrationLedger::new("human:dev".into(), LedgerGovernance::new(365));
        let mut flight =
            schedule(&"human:dev".into(), vec![Uuid::new_v4()], 0, &Timestamp::now(), &params());
        flight.state = FlightState::Active;

        complete(
            &mut flight,
            &[("tokeniser".into(), 0.7, true)],
            &mut ledger,
            &audit,
        );

        assert_eq!(flight.state, FlightState::Completed);
        let events = ledger.events(&"human:dev".to_string()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, PracticeKind::SoloFlight);
    }
}
