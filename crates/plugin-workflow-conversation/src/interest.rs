/// W10 — Interest router (CG-25..26): deterministic signals route the
/// problems the agent could not crack to humans at calibrated challenge.
/// The human may always decline — without record.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wyrtloom_core::logger::{CallLog, CallOutcome};
use wyrtloom_core::types::{ActorId, ContractId, TaskId};

/// Failures on one task at or beyond this count form a retry/failure
/// cluster (CG-25).
pub const RETRY_CLUSTER_THRESHOLD: usize = 3;

/// The flow channel (CG-26): challenge pitched neither below boredom nor
/// beyond reach.
pub const FLOW_LOW: f64 = 0.3;
pub const FLOW_HIGH: f64 = 0.85;

/// CG-25: the only admissible interest signals — all deterministic, none
/// judged by an LLM.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InterestSignal {
    RetryFailureCluster { task: TaskId, failures: usize },
    NoveltyVsBaseline { observation: String },
    CrossModuleAnomaly { modules: Vec<String> },
    ContractBoundaryAmbiguity { contract: ContractId },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutedProblem {
    pub signal: InterestSignal,
    pub recipient: ActorId,
}

/// CG-25: retry/failure clusters read straight off the call log.
pub fn detect_retry_clusters(logs: &[CallLog]) -> Vec<InterestSignal> {
    let mut failures: BTreeMap<TaskId, usize> = BTreeMap::new();
    for log in logs {
        if matches!(log.outcome, CallOutcome::Failed(_)) {
            *failures.entry(log.task).or_default() += 1;
        }
    }
    failures
        .into_iter()
        .filter(|(_, n)| *n >= RETRY_CLUSTER_THRESHOLD)
        .map(|(task, failures)| InterestSignal::RetryFailureCluster { task, failures })
        .collect()
}

/// CG-26: route into the recipient's flow channel. Candidates are
/// (person, calibration on the signal's ground); the first in-channel
/// candidate by id wins — deterministic.
pub fn route(signal: InterestSignal, candidates: &[(ActorId, f64)]) -> Option<RoutedProblem> {
    let mut sorted: Vec<&(ActorId, f64)> = candidates.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted
        .into_iter()
        .find(|(_, score)| (FLOW_LOW..=FLOW_HIGH).contains(score))
        .map(|(id, _)| RoutedProblem { signal, recipient: id.clone() })
}

/// CG-26: humans may decline without record. The routed problem is consumed
/// and dropped — nothing is written to any ledger, log, or trail.
pub fn decline(_routed: RoutedProblem) {}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use wyrtloom_core::provider::Usage;
    use wyrtloom_core::types::Timestamp;

    fn log(task: TaskId, outcome: CallOutcome) -> CallLog {
        CallLog {
            task,
            profile: "default".into(),
            provider: "ollama".into(),
            model: "llama3.2".into(),
            usage: Usage { input_tokens: 1, output_tokens: 1, cost: None },
            outcome,
            at: Timestamp::now(),
        }
    }

    #[test]
    fn cg25_retry_clusters_emerge_at_the_threshold() {
        let stuck = Uuid::new_v4();
        let fine = Uuid::new_v4();
        let logs = vec![
            log(stuck, CallOutcome::Failed("err".into())),
            log(stuck, CallOutcome::Failed("err".into())),
            log(stuck, CallOutcome::Failed("err".into())),
            log(fine, CallOutcome::Failed("err".into())),
            log(fine, CallOutcome::Completed),
        ];
        let signals = detect_retry_clusters(&logs);
        assert_eq!(signals.len(), 1);
        assert_eq!(
            signals[0],
            InterestSignal::RetryFailureCluster { task: stuck, failures: 3 }
        );
    }

    #[test]
    fn cg26_routing_lands_in_the_flow_channel() {
        let signal = InterestSignal::ContractBoundaryAmbiguity {
            contract: "wyrtloom.kanban".into(),
        };
        let candidates = vec![
            ("human:bored".to_string(), 0.95),  // above the channel
            ("human:fits".to_string(), 0.6),    // in the channel
            ("human:adrift".to_string(), 0.1),  // below the channel
        ];
        let routed = route(signal, &candidates).unwrap();
        assert_eq!(routed.recipient, "human:fits");
    }

    #[test]
    fn cg26_no_candidate_in_channel_routes_nowhere() {
        let signal = InterestSignal::NoveltyVsBaseline { observation: "odd".into() };
        let candidates = vec![("human:bored".to_string(), 0.99)];
        assert!(route(signal, &candidates).is_none());
    }

    #[test]
    fn cg26_decline_consumes_without_record() {
        let routed = RoutedProblem {
            signal: InterestSignal::CrossModuleAnomaly { modules: vec!["a".into()] },
            recipient: "human:fits".into(),
        };
        // decline() takes ownership and writes nowhere — there is no
        // ledger, trail, or return value through which a record could leak.
        decline(routed);
    }
}
