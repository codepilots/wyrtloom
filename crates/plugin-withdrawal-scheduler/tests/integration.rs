//! CORE INTEGRATION TEST for W11 (withdrawal scheduler).
//!
//! Exercises the whole path against real core types and a real
//! `wyrtloom_core::logger::CallLogger` (the in-memory SQLite logger):
//!
//!  * a schedule is computed from seed events keyed by real `ActorId` /
//!    `Timestamp`, and the expanding intervals are deterministic (CG-13);
//!  * a solo flight is begun (agent withdrawn, CG-14);
//!  * an explicit human abort is recorded through the `CallLogger` as a
//!    PRACTICE event, never penalised (CG-14 / CG-15).

use plugin_logger_sqlite::SqliteCallLogger;
use plugin_withdrawal_scheduler::{
    EventKind, ExpansionPolicy, FlightOutcome, PracticeEvent, Scheduler, SeedEvent, SoloFlight,
};
use uuid::Uuid;
use wyrtloom_core::logger::{CallLog, CallLogger, CallOutcome};
use wyrtloom_core::provider::Usage;
use wyrtloom_core::types::{ActorId, TaskId, Timestamp};

fn ts(rfc3339: &str) -> Timestamp {
    Timestamp(
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&chrono::Utc),
    )
}

/// Render a non-penalising practice event as a `CallLog` for the ledger.
///
/// CG-15: the outcome is recorded as practice, *never* as an assessment. We
/// encode it as `CallOutcome::Partial` (developmental, non-terminal) and assert
/// downstream that it is never `Failed` — a solo flight or its abort is not a
/// failure to be penalised (CG-14).
fn practice_to_log(task: TaskId, actor: &ActorId, event: &PracticeEvent, at: Timestamp) -> CallLog {
    assert_eq!(event.kind, EventKind::Practice);
    assert!(!event.penalised, "CG-14/CG-15: practice events are never penalised");
    let detail = match &event.outcome {
        FlightOutcome::Flown => "practice:solo-flight:flown".to_string(),
        FlightOutcome::Aborted { reason } => {
            format!("practice:solo-flight:aborted:{reason} (never penalised)")
        }
    };
    CallLog {
        task,
        profile: actor.clone(),
        provider: "withdrawal-scheduler".into(),
        model: "n/a".into(),
        usage: Usage { input_tokens: 0, output_tokens: 0, cost: None },
        // PRACTICE, not assessment: Partial is developmental, not a Failed/penalty.
        outcome: CallOutcome::Partial(detail),
        at,
    }
}

#[test]
fn schedule_is_deterministic_and_abort_logged_as_unpenalised_practice() {
    // --- deterministic expanding schedule from real-typed seeds (CG-13) -----
    let policy = ExpansionPolicy { base_days: 7, factor_percent: 200, cap_days: 90 };
    let sched = Scheduler::new(policy).unwrap();

    let actor: ActorId = "alice".to_string();
    let task: TaskId = Uuid::new_v4();
    let seeds = vec![SeedEvent {
        actor: actor.clone(),
        task,
        last_practiced: ts("2026-01-01T00:00:00Z"),
        prior_sessions: 0,
    }];

    let plan_a = sched.plan(&seeds, 4);
    let plan_b = sched.plan(&seeds, 4);
    assert_eq!(plan_a, plan_b, "CG-13: schedule must be deterministic");
    assert_eq!(plan_a[0].scheduled_at, ts("2026-01-08T00:00:00Z"));
    assert_eq!(plan_a[3].scheduled_at, ts("2026-04-16T00:00:00Z"));

    // --- begin a solo flight: agent withdrawn (CG-14) -----------------------
    let flight = SoloFlight::begin(&plan_a[0]);
    assert!(flight.agent_withdrawn());

    // --- explicit human abort, recorded as practice via a real CallLogger ---
    let logger = SqliteCallLogger::in_memory().unwrap();
    let (aborted, event) = sched.abort(flight, "prod incident: human took over").unwrap();
    assert!(!aborted.agent_withdrawn(), "CG-14: agent pulled back in after abort");

    logger
        .record(practice_to_log(task, &actor, &event, ts("2026-01-08T09:00:00Z")))
        .unwrap();

    // --- assertions on the persisted ledger entry ---------------------------
    let logs = logger.all_logs().unwrap();
    assert_eq!(logs.len(), 1, "the abort must be logged, never silently dropped");
    let log = &logs[0];
    assert_eq!(log.task, task);
    assert_eq!(log.profile, actor);

    // CG-15: it is a practice (Partial) event, NOT a penalising Failed one.
    match &log.outcome {
        CallOutcome::Partial(detail) => {
            assert!(detail.contains("practice:solo-flight:aborted"));
            assert!(detail.contains("never penalised"));
        }
        other => panic!("expected non-penalising Partial practice event, got {other:?}"),
    }
    assert!(
        !matches!(log.outcome, CallOutcome::Failed(_)),
        "CG-14: an abort is never recorded as a penalised failure"
    );
}

#[test]
fn completed_solo_flight_also_logged_as_practice() {
    let sched = Scheduler::new(ExpansionPolicy::default()).unwrap();
    let actor: ActorId = "bob".to_string();
    let task: TaskId = Uuid::new_v4();
    let seeds = vec![SeedEvent {
        actor: actor.clone(),
        task,
        last_practiced: ts("2026-03-01T00:00:00Z"),
        prior_sessions: 1,
    }];
    let plan = sched.plan(&seeds, 1);
    let flight = SoloFlight::begin(&plan[0]);

    let logger = SqliteCallLogger::in_memory().unwrap();
    let (_done, event) = sched.complete(flight).unwrap();
    logger
        .record(practice_to_log(task, &actor, &event, ts("2026-03-15T00:00:00Z")))
        .unwrap();

    let logs = logger.all_logs().unwrap();
    assert!(matches!(logs[0].outcome, CallOutcome::Partial(_)));
}
