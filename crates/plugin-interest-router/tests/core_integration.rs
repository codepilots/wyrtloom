//! Core integration test for W10 — Interest router.
//!
//! Feeds real `wyrtloom_core::agent::AgentMessage` values through the router
//! and asserts:
//!   1. routing is deterministic — same input yields identical routing (CG-25);
//!   2. a human decline leaves no persisted trace (CG-26).

use plugin_interest_router::{
    AcceptedSink, BehaviouralBaseline, CalibrationScore, InterestRouter, RoutedProblem,
    RoutingOutcome, SignalKind,
};
use uuid::Uuid;
use wyrtloom_core::agent::AgentMessage;
use wyrtloom_core::types::TaskId;

/// A persistence sink that we can inspect to prove what the router did and did
/// not persist. Stands in for a real ledger/store.
#[derive(Default)]
struct RecordingSink {
    persisted: Vec<RoutedProblem>,
}

impl AcceptedSink for RecordingSink {
    fn record_accepted(&mut self, problem: &RoutedProblem) {
        self.persisted.push(problem.clone());
    }
}

/// Build a real cluster of Error/retry AgentMessages sharing one origin_task,
/// plus an unanswered Delegation across module boundaries.
fn cluster(origin: TaskId) -> Vec<AgentMessage> {
    vec![
        AgentMessage::Error { origin_task: origin, hops: 2, error: "retry 1".into() },
        AgentMessage::Error { origin_task: origin, hops: 3, error: "retry 2".into() },
        AgentMessage::Error { origin_task: origin, hops: 4, error: "retry 3".into() },
        AgentMessage::Delegation { origin_task: origin, hops: 1, body: b"hand off".to_vec() },
    ]
}

#[test]
fn real_agent_messages_route_deterministically() {
    let origin: TaskId = Uuid::new_v4();
    let msgs = cluster(origin);
    let baseline = BehaviouralBaseline::new(16);
    let router = InterestRouter::new();

    // Same input -> identical signals.
    let signals_a = router.derive_signals(&msgs, &baseline);
    let signals_b = router.derive_signals(&msgs, &baseline);
    assert_eq!(signals_a, signals_b, "signal derivation must be deterministic");

    // The error cluster of 3 sharing origin_task must surface.
    assert!(signals_a
        .iter()
        .any(|s| s.kind == SignalKind::RetryFailureCluster && s.origin_task == origin));
    // Unanswered delegation -> contract-boundary ambiguity.
    assert!(signals_a
        .iter()
        .any(|s| s.kind == SignalKind::ContractBoundaryAmbiguity && s.origin_task == origin));

    // Same input -> identical routing.
    let cal = CalibrationScore::new(0.8).unwrap();
    let p1 = router.route(origin, &signals_a, "human-1", cal).unwrap();
    let p2 = router.route(origin, &signals_b, "human-1", cal).unwrap();
    assert_eq!(p1, p2, "same input must yield identical routed problem");
}

#[test]
fn decline_of_real_routed_problem_leaves_no_trace() {
    let origin: TaskId = Uuid::new_v4();
    let msgs = cluster(origin);
    let baseline = BehaviouralBaseline::new(16);

    let mut router = InterestRouter::with_sink(RecordingSink::default());
    let signals = router.derive_signals(&msgs, &baseline);

    let problem = router
        .route(origin, &signals, "human-2", CalibrationScore::new(0.5).unwrap())
        .unwrap();

    // The human declines.
    let outcome = router.resolve(problem, false);
    assert_eq!(outcome, RoutingOutcome::Declined);

    // CG-26: a decline persists nothing — the sink is empty.
    assert!(
        router.sink().persisted.is_empty(),
        "declines must leave no persisted trace (CG-26)"
    );
}

#[test]
fn accept_of_real_routed_problem_is_persisted() {
    let origin: TaskId = Uuid::new_v4();
    let msgs = cluster(origin);
    let baseline = BehaviouralBaseline::new(16);

    let mut router = InterestRouter::with_sink(RecordingSink::default());
    let signals = router.derive_signals(&msgs, &baseline);
    let problem = router
        .route(origin, &signals, "human-3", CalibrationScore::new(0.5).unwrap())
        .unwrap();

    let outcome = router.resolve(problem.clone(), true);
    assert!(matches!(outcome, RoutingOutcome::Accepted(_)));
    // Contrast with the decline case: acceptance IS recorded.
    assert_eq!(router.sink().persisted.len(), 1);
    assert_eq!(router.sink().persisted[0], problem);
}
