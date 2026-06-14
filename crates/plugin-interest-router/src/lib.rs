//! W10 — Interest router (plugin layer).
//!
//! Implements Wyrtloom Conversation spec §2.2 row W10 and satisfies
//! requirements CG-25 and CG-26.
//!
//! - **CG-25.** Interest signals SHALL be deterministic: agent retry/failure
//!   clusters, novelty vs behavioural baseline, cross-module anomalies, and
//!   contract-boundary ambiguities. This crate derives all four signal kinds as
//!   pure functions of the input `AgentMessage` stream and a supplied
//!   behavioural baseline — there is **no LLM** anywhere on the path (CG-4).
//! - **CG-26.** Routed problems SHALL be pitched into the recipient's flow
//!   channel using the calibration ledger; humans MAY decline without record.
//!   Pitch selection is a deterministic function of a calibration score; a
//!   decline returns `RoutingOutcome::Declined` and persists **nothing**
//!   (declines leave no ledger trace).
//!
//! The router depends only on `wyrtloom_core::{agent, types}` and small local
//! types — it does NOT depend on sibling W-crates (e.g. the W7 calibration
//! ledger). The caller supplies a calibration score; how it is sourced is the
//! ledger's concern, not the router's.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use wyrtloom_core::agent::AgentMessage;
use wyrtloom_core::types::TaskId;

/// Cluster size (number of error/retry messages sharing an `origin_task`) at or
/// above which a retry/failure cluster becomes an interest signal.
///
/// Fixed constant rather than tunable input so signal detection is reproducible
/// across processes (CG-25 determinism).
pub const RETRY_CLUSTER_THRESHOLD: usize = 3;

// ---------------------------------------------------------------------------
// Signals (CG-25)
// ---------------------------------------------------------------------------

/// The four deterministic interest-signal kinds enumerated by CG-25.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SignalKind {
    /// A cluster of agent retry/failure messages sharing one `origin_task`.
    RetryFailureCluster,
    /// Behaviour novel with respect to the supplied behavioural baseline.
    NoveltyVsBaseline,
    /// An anomaly observed across more than one module/task boundary.
    CrossModuleAnomaly,
    /// Ambiguity at a contract boundary (e.g. a delegation hop with no result).
    ContractBoundaryAmbiguity,
}

/// A single derived interest signal, tied to the task it concerns.
///
/// `weight` is a deterministic integer magnitude (e.g. cluster size); it is NOT
/// a probability or a learned score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterestSignal {
    pub kind: SignalKind,
    pub origin_task: TaskId,
    pub weight: u32,
}

/// A behavioural baseline against which novelty is measured (CG-25).
///
/// Minimal local representation: the set of `origin_task`s the baseline has
/// already seen, plus the maximum hop depth considered "normal". A task absent
/// from `known_tasks` is novel; a hop depth beyond `normal_max_hops` is novel.
/// Deterministic: novelty is set membership / integer comparison, no model.
#[derive(Debug, Clone, Default)]
pub struct BehaviouralBaseline {
    known_tasks: std::collections::BTreeSet<TaskId>,
    normal_max_hops: u8,
}

impl BehaviouralBaseline {
    /// An empty baseline that treats everything as novel and any hop as normal.
    pub fn new(normal_max_hops: u8) -> Self {
        Self { known_tasks: std::collections::BTreeSet::new(), normal_max_hops }
    }

    /// Record a task as already-seen, so it is no longer treated as novel.
    pub fn observe(&mut self, task: TaskId) {
        self.known_tasks.insert(task);
    }

    fn is_novel_task(&self, task: &TaskId) -> bool {
        !self.known_tasks.contains(task)
    }

    fn is_novel_hops(&self, hops: u8) -> bool {
        hops > self.normal_max_hops
    }
}

// ---------------------------------------------------------------------------
// Calibration + human channel (CG-26)
// ---------------------------------------------------------------------------

/// A human recipient and the flow channel a routed problem is pitched into.
///
/// Local minimal type — the router does not import the W7 calibration ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanChannel {
    /// Stable identifier of the human (e.g. actor id).
    pub recipient: String,
    /// The flow channel the pitch is delivered to.
    pub channel: FlowChannel,
}

/// Flow channels, ordered easiest → hardest. A problem is pitched into the
/// channel that keeps the recipient inside their flow band — neither bored nor
/// overwhelmed — given their calibration score (CG-26).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FlowChannel {
    /// Low-calibration recipient: scaffolded, low-stakes framing.
    Guided,
    /// Mid-calibration recipient: standard challenge.
    Standard,
    /// High-calibration recipient: stretch / high-stakes framing.
    Stretch,
}

/// Calibration score in `[0.0, 1.0]` — how well a person's confidence tracks
/// their accuracy. Supplied by the caller (sourced from the W7 ledger); the
/// router only reads it. Out-of-range or non-finite values are rejected so the
/// pitch mapping stays deterministic and total.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CalibrationScore(f64);

impl CalibrationScore {
    pub fn new(value: f64) -> Result<Self, RoutingError> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(RoutingError::InvalidCalibration(value))
        }
    }

    pub fn value(&self) -> f64 {
        self.0
    }

    /// Deterministic pitch mapping (CG-26): low calibration → Guided, mid →
    /// Standard, high → Stretch. Fixed thresholds, no randomness.
    fn flow_channel(&self) -> FlowChannel {
        if self.0 < 0.34 {
            FlowChannel::Guided
        } else if self.0 < 0.67 {
            FlowChannel::Standard
        } else {
            FlowChannel::Stretch
        }
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// A problem routed to a human: the originating task, the signals that raised
/// it, and the flow channel it was pitched into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutedProblem {
    pub origin_task: TaskId,
    pub signals: Vec<InterestSignal>,
    pub channel: HumanChannel,
}

/// The terminal outcome of presenting a routed problem to a human.
///
/// CG-26: a human MAY decline without record. `Declined` carries no payload and
/// the router persists nothing for it — there is deliberately no ledger field,
/// timestamp, or recipient kept on this path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingOutcome {
    /// The human accepted the routed problem.
    Accepted(RoutedProblem),
    /// The human declined. No trace is persisted (CG-26).
    Declined,
}

#[derive(Error, Debug, Clone, PartialEq)]
pub enum RoutingError {
    #[error("calibration score out of range or non-finite: {0}")]
    InvalidCalibration(f64),
    #[error("no interest signals were derived for task {0}")]
    NoSignals(TaskId),
}

/// Deterministic interest router (CG-25, CG-26).
///
/// Holds an optional persistence sink for accepted problems. Declined problems
/// are NEVER offered to the sink, guaranteeing CG-26's "no ledger trace".
pub struct InterestRouter<S: AcceptedSink = NullSink> {
    sink: S,
}

/// Sink for problems a human accepted. Accepting is recordable; declining is
/// not (CG-26) — see [`InterestRouter::resolve`].
pub trait AcceptedSink {
    fn record_accepted(&mut self, problem: &RoutedProblem);
}

/// A sink that records nothing. Default — keeps the router pure.
#[derive(Debug, Default, Clone)]
pub struct NullSink;

impl AcceptedSink for NullSink {
    fn record_accepted(&mut self, _problem: &RoutedProblem) {}
}

impl Default for InterestRouter<NullSink> {
    fn default() -> Self {
        Self { sink: NullSink }
    }
}

impl InterestRouter<NullSink> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S: AcceptedSink> InterestRouter<S> {
    /// Construct with a custom accepted-problem sink.
    pub fn with_sink(sink: S) -> Self {
        Self { sink }
    }

    /// Borrow the underlying sink (e.g. to inspect what was recorded in tests).
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Derive every interest signal from a message stream and a baseline.
    ///
    /// Pure and deterministic (CG-25): the same `messages` + `baseline` always
    /// produce the same signal vector, in a stable (task, kind) order.
    pub fn derive_signals(
        &self,
        messages: &[AgentMessage],
        baseline: &BehaviouralBaseline,
    ) -> Vec<InterestSignal> {
        derive_signals(messages, baseline)
    }

    /// Route a single task's signals to a human, pitched by calibration.
    ///
    /// Returns the `RoutedProblem` to present; the caller then calls
    /// [`Self::resolve`] with the human's accept/decline decision. Errors if no
    /// signals exist for `task`.
    pub fn route(
        &self,
        task: TaskId,
        signals: &[InterestSignal],
        recipient: &str,
        calibration: CalibrationScore,
    ) -> Result<RoutedProblem, RoutingError> {
        let mut for_task: Vec<InterestSignal> =
            signals.iter().filter(|s| s.origin_task == task).cloned().collect();
        if for_task.is_empty() {
            return Err(RoutingError::NoSignals(task));
        }
        // Normalise ordering so the routed problem is byte-for-byte
        // reproducible regardless of the caller's input order (the slice may
        // come from somewhere other than `derive_signals`). All signals here
        // share `task`, so (kind, weight) is a total key.
        for_task.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.weight.cmp(&b.weight)));

        Ok(RoutedProblem {
            origin_task: task,
            signals: for_task,
            channel: HumanChannel {
                recipient: recipient.to_string(),
                channel: calibration.flow_channel(),
            },
        })
    }

    /// Apply the human's decision to a routed problem.
    ///
    /// CG-26: on `accepted == true` the problem is offered to the sink and
    /// returned as `Accepted`. On `accepted == false` the function returns
    /// `Declined` and the sink is **never touched** — no trace persists.
    pub fn resolve(&mut self, problem: RoutedProblem, accepted: bool) -> RoutingOutcome {
        if accepted {
            self.sink.record_accepted(&problem);
            RoutingOutcome::Accepted(problem)
        } else {
            // Deliberately do nothing: declines leave no ledger trace (CG-26).
            RoutingOutcome::Declined
        }
    }
}

// ---------------------------------------------------------------------------
// Signal derivation (free functions — the deterministic core, CG-25)
// ---------------------------------------------------------------------------

/// Derive all four CG-25 signal kinds from a message stream + baseline.
fn derive_signals(messages: &[AgentMessage], baseline: &BehaviouralBaseline) -> Vec<InterestSignal> {
    // Per-task tallies, kept in a BTreeMap so output order is deterministic.
    let mut error_counts: BTreeMap<TaskId, u32> = BTreeMap::new();
    let mut delegations: BTreeMap<TaskId, u32> = BTreeMap::new();
    let mut results: BTreeMap<TaskId, u32> = BTreeMap::new();
    // Deepest hop reached by an ERROR message for a task. Used for the
    // cross-module signal so that healthy deep traffic (a normal deep Result or
    // Response) cannot fabricate an anomaly — the depth must come from where a
    // fault actually occurred.
    let mut error_max_hops: BTreeMap<TaskId, u8> = BTreeMap::new();
    let mut novel_tasks: std::collections::BTreeSet<TaskId> = std::collections::BTreeSet::new();

    for msg in messages {
        let task = msg.origin_task();
        let hops = msg.hops();
        if baseline.is_novel_task(&task) || baseline.is_novel_hops(hops) {
            novel_tasks.insert(task);
        }
        match msg {
            AgentMessage::Error { .. } => {
                *error_counts.entry(task).or_insert(0) += 1;
                let entry = error_max_hops.entry(task).or_insert(0);
                if hops > *entry {
                    *entry = hops;
                }
            }
            AgentMessage::Delegation { .. } => {
                *delegations.entry(task).or_insert(0) += 1;
            }
            AgentMessage::Result { .. } => {
                *results.entry(task).or_insert(0) += 1;
            }
            _ => {}
        }
    }

    let mut signals: Vec<InterestSignal> = Vec::new();

    // (1) Retry/failure cluster — error count at/above threshold for one task.
    for (task, count) in &error_counts {
        if (*count as usize) >= RETRY_CLUSTER_THRESHOLD {
            signals.push(InterestSignal {
                kind: SignalKind::RetryFailureCluster,
                origin_task: *task,
                weight: *count,
            });
        }
    }

    // (2) Novelty vs behavioural baseline.
    for task in &novel_tasks {
        signals.push(InterestSignal {
            kind: SignalKind::NoveltyVsBaseline,
            origin_task: *task,
            weight: 1,
        });
    }

    // (3) Cross-module anomaly — an error that occurred more than one hop deep
    // means the fault crossed module/boundary layers. Depth is taken from the
    // ERROR messages only (`error_max_hops`), never from healthy traffic.
    for (task, depth) in &error_max_hops {
        if *depth > 1 {
            signals.push(InterestSignal {
                kind: SignalKind::CrossModuleAnomaly,
                origin_task: *task,
                weight: *depth as u32,
            });
        }
    }

    // (4) Contract-boundary ambiguity — a delegation that never produced a
    // matching result leaves the contract boundary unresolved.
    for (task, deleg) in &delegations {
        let res = results.get(task).copied().unwrap_or(0);
        if *deleg > res {
            signals.push(InterestSignal {
                kind: SignalKind::ContractBoundaryAmbiguity,
                origin_task: *task,
                weight: *deleg - res,
            });
        }
    }

    // Stable global order: (task, kind, weight). BTreeMap iteration already
    // gives per-task ordering within a kind; this normalises across kinds.
    signals.sort_by(|a, b| {
        a.origin_task
            .cmp(&b.origin_task)
            .then(a.kind.cmp(&b.kind))
            .then(a.weight.cmp(&b.weight))
    });
    signals
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn task() -> TaskId {
        Uuid::new_v4()
    }

    fn err(task: TaskId, hops: u8) -> AgentMessage {
        AgentMessage::Error { origin_task: task, hops, error: "boom".into() }
    }

    fn deleg(task: TaskId, hops: u8) -> AgentMessage {
        AgentMessage::Delegation { origin_task: task, hops, body: vec![] }
    }

    fn result(task: TaskId, hops: u8) -> AgentMessage {
        AgentMessage::Result { origin_task: task, hops, body: vec![] }
    }

    /// A sink that counts records, to prove the decline path never touches it.
    #[derive(Default)]
    struct CountingSink {
        recorded: Vec<RoutedProblem>,
    }
    impl AcceptedSink for CountingSink {
        fn record_accepted(&mut self, problem: &RoutedProblem) {
            self.recorded.push(problem.clone());
        }
    }

    // ---- CG-25: deterministic signal derivation --------------------------

    #[test]
    fn retry_failure_cluster_detected_at_threshold() {
        let t = task();
        let msgs = vec![err(t, 0), err(t, 0), err(t, 0)];
        let router = InterestRouter::new();
        let sigs = router.derive_signals(&msgs, &BehaviouralBaseline::new(16));
        assert!(sigs
            .iter()
            .any(|s| s.kind == SignalKind::RetryFailureCluster && s.origin_task == t && s.weight == 3));
    }

    #[test]
    fn retry_cluster_not_raised_below_threshold() {
        let t = task();
        let msgs = vec![err(t, 0), err(t, 0)];
        let router = InterestRouter::new();
        let sigs = router.derive_signals(&msgs, &BehaviouralBaseline::new(16));
        assert!(!sigs.iter().any(|s| s.kind == SignalKind::RetryFailureCluster));
    }

    #[test]
    fn novelty_signal_for_unknown_task() {
        let t = task();
        let msgs = vec![result(t, 0)];
        let mut baseline = BehaviouralBaseline::new(16);
        // task is unknown -> novel
        let router = InterestRouter::new();
        let sigs = router.derive_signals(&msgs, &baseline);
        assert!(sigs.iter().any(|s| s.kind == SignalKind::NoveltyVsBaseline));
        // After observing it, novelty disappears.
        baseline.observe(t);
        let sigs2 = router.derive_signals(&msgs, &baseline);
        assert!(!sigs2.iter().any(|s| s.kind == SignalKind::NoveltyVsBaseline));
    }

    #[test]
    fn novelty_signal_for_abnormal_hop_depth() {
        let t = task();
        let mut baseline = BehaviouralBaseline::new(2);
        baseline.observe(t); // known task, so only hop-depth can trip novelty
        let router = InterestRouter::new();
        let normal = router.derive_signals(&[result(t, 2)], &baseline);
        assert!(!normal.iter().any(|s| s.kind == SignalKind::NoveltyVsBaseline));
        let deep = router.derive_signals(&[result(t, 3)], &baseline);
        assert!(deep.iter().any(|s| s.kind == SignalKind::NoveltyVsBaseline));
    }

    #[test]
    fn cross_module_anomaly_needs_depth() {
        let t = task();
        let router = InterestRouter::new();
        let mut baseline = BehaviouralBaseline::new(16);
        baseline.observe(t);
        let shallow = router.derive_signals(&[err(t, 0)], &baseline);
        assert!(!shallow.iter().any(|s| s.kind == SignalKind::CrossModuleAnomaly));
        let deep = router.derive_signals(&[err(t, 3)], &baseline);
        assert!(deep.iter().any(|s| s.kind == SignalKind::CrossModuleAnomaly));
    }

    #[test]
    fn healthy_deep_traffic_does_not_fabricate_cross_module() {
        // A single SHALLOW error plus a deep, healthy Result must NOT raise a
        // cross-module anomaly — depth comes from error messages only.
        let t = task();
        let router = InterestRouter::new();
        let mut baseline = BehaviouralBaseline::new(16);
        baseline.observe(t);
        let msgs = vec![err(t, 0), result(t, 9)];
        let sigs = router.derive_signals(&msgs, &baseline);
        assert!(!sigs.iter().any(|s| s.kind == SignalKind::CrossModuleAnomaly));
    }

    #[test]
    fn cross_module_weight_reflects_error_depth_not_other_traffic() {
        let t = task();
        let router = InterestRouter::new();
        let mut baseline = BehaviouralBaseline::new(16);
        baseline.observe(t);
        // Error at hop 3, healthy result far deeper at hop 9.
        let msgs = vec![err(t, 3), result(t, 9)];
        let sigs = router.derive_signals(&msgs, &baseline);
        let sig = sigs
            .iter()
            .find(|s| s.kind == SignalKind::CrossModuleAnomaly)
            .expect("anomaly from deep error");
        assert_eq!(sig.weight, 3, "weight must reflect error depth, not the result");
    }

    #[test]
    fn contract_boundary_ambiguity_when_delegation_unanswered() {
        let t = task();
        let router = InterestRouter::new();
        let mut baseline = BehaviouralBaseline::new(16);
        baseline.observe(t);
        // Two delegations, one result -> one unanswered.
        let msgs = vec![deleg(t, 1), deleg(t, 1), result(t, 1)];
        let sigs = router.derive_signals(&msgs, &baseline);
        let sig = sigs
            .iter()
            .find(|s| s.kind == SignalKind::ContractBoundaryAmbiguity)
            .expect("ambiguity signal");
        assert_eq!(sig.weight, 1);
    }

    #[test]
    fn fully_answered_delegation_has_no_ambiguity() {
        let t = task();
        let router = InterestRouter::new();
        let mut baseline = BehaviouralBaseline::new(16);
        baseline.observe(t);
        let msgs = vec![deleg(t, 1), result(t, 1)];
        let sigs = router.derive_signals(&msgs, &baseline);
        assert!(!sigs.iter().any(|s| s.kind == SignalKind::ContractBoundaryAmbiguity));
    }

    #[test]
    fn signal_derivation_is_deterministic() {
        let t1 = task();
        let t2 = task();
        let msgs = vec![err(t1, 3), err(t1, 3), err(t1, 3), deleg(t2, 2), err(t2, 2)];
        let router = InterestRouter::new();
        let baseline = BehaviouralBaseline::new(16);
        let a = router.derive_signals(&msgs, &baseline);
        let b = router.derive_signals(&msgs, &baseline);
        assert_eq!(a, b, "same input must yield identical signal vector");
    }

    // ---- CG-26: pitch by calibration -------------------------------------

    #[test]
    fn calibration_score_rejects_out_of_range() {
        assert!(CalibrationScore::new(-0.1).is_err());
        assert!(CalibrationScore::new(1.1).is_err());
        assert!(CalibrationScore::new(f64::NAN).is_err());
        assert!(CalibrationScore::new(0.5).is_ok());
    }

    #[test]
    fn pitch_channel_follows_calibration() {
        assert_eq!(CalibrationScore::new(0.1).unwrap().flow_channel(), FlowChannel::Guided);
        assert_eq!(CalibrationScore::new(0.5).unwrap().flow_channel(), FlowChannel::Standard);
        assert_eq!(CalibrationScore::new(0.9).unwrap().flow_channel(), FlowChannel::Stretch);
    }

    #[test]
    fn route_errors_without_signals() {
        let router = InterestRouter::new();
        let t = task();
        let res = router.route(t, &[], "alice", CalibrationScore::new(0.5).unwrap());
        assert!(matches!(res, Err(RoutingError::NoSignals(_))));
    }

    #[test]
    fn route_pitches_into_calibrated_channel() {
        let t = task();
        let router = InterestRouter::new();
        let sigs = vec![InterestSignal {
            kind: SignalKind::RetryFailureCluster,
            origin_task: t,
            weight: 3,
        }];
        let problem = router
            .route(t, &sigs, "bob", CalibrationScore::new(0.9).unwrap())
            .unwrap();
        assert_eq!(problem.channel.recipient, "bob");
        assert_eq!(problem.channel.channel, FlowChannel::Stretch);
        assert_eq!(problem.origin_task, t);
    }

    #[test]
    fn routing_is_deterministic_same_input_same_output() {
        let t = task();
        let router = InterestRouter::new();
        let sigs = vec![
            InterestSignal { kind: SignalKind::CrossModuleAnomaly, origin_task: t, weight: 3 },
            InterestSignal { kind: SignalKind::RetryFailureCluster, origin_task: t, weight: 4 },
        ];
        let p1 = router.route(t, &sigs, "carol", CalibrationScore::new(0.2).unwrap()).unwrap();
        let p2 = router.route(t, &sigs, "carol", CalibrationScore::new(0.2).unwrap()).unwrap();
        assert_eq!(p1, p2);
    }

    // ---- CG-26: decline leaves no trace ----------------------------------

    #[test]
    fn accept_records_to_sink() {
        let t = task();
        let mut router = InterestRouter::with_sink(CountingSink::default());
        let sigs = vec![InterestSignal {
            kind: SignalKind::RetryFailureCluster,
            origin_task: t,
            weight: 3,
        }];
        let problem = router.route(t, &sigs, "dave", CalibrationScore::new(0.5).unwrap()).unwrap();
        let outcome = router.resolve(problem, true);
        assert!(matches!(outcome, RoutingOutcome::Accepted(_)));
        assert_eq!(router.sink().recorded.len(), 1);
    }

    #[test]
    fn decline_persists_no_trace() {
        let t = task();
        let mut router = InterestRouter::with_sink(CountingSink::default());
        let sigs = vec![InterestSignal {
            kind: SignalKind::RetryFailureCluster,
            origin_task: t,
            weight: 3,
        }];
        let problem = router.route(t, &sigs, "erin", CalibrationScore::new(0.5).unwrap()).unwrap();
        let outcome = router.resolve(problem, false);
        assert_eq!(outcome, RoutingOutcome::Declined);
        // CG-26: nothing was recorded.
        assert_eq!(router.sink().recorded.len(), 0);
    }
}
