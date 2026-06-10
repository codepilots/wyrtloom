/// §2.6 — pilot instrumentation, carried honestly: the addendum is not
/// evidence-based until a pre-registered pilot measures it. This module is
/// the deterministic measurement half: gate time cost, defect and rework
/// rates, suite growth, and the equity watch. The criteria are configured
/// up front — pre-registered — never fitted after the fact (D15.6).
use crate::audit::{WorkflowEvent, WorkflowEventKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wyrtloom_core::types::ActorId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SprintMetrics {
    pub sprint: u32,
    /// Total digest-to-decision time across all gate passages.
    pub gate_overhead_seconds: f64,
    pub defects_opened: u32,
    pub rework_count: u32,
    /// Regression-suite size at sprint end (growth from hunt-tests).
    pub suite_size: usize,
}

/// Pre-registered abandonment criteria (CH7): if gate overhead exceeds the
/// budget for N consecutive sprints without defect-rate improvement, the
/// profile self-reports failure to the project owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbandonmentCriteria {
    pub gate_overhead_budget_seconds: f64,
    pub consecutive_sprints: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotFailureReport {
    pub to_owner: ActorId,
    pub message: String,
    pub sprints_over_budget: u32,
}

pub struct PilotInstruments {
    criteria: AbandonmentCriteria,
    owner: ActorId,
    sprints: Vec<SprintMetrics>,
}

impl PilotInstruments {
    pub fn new(criteria: AbandonmentCriteria, owner: ActorId) -> Self {
        Self { criteria, owner, sprints: Vec::new() }
    }

    pub fn record_sprint(&mut self, metrics: SprintMetrics) {
        self.sprints.push(metrics);
    }

    pub fn sprints(&self) -> &[SprintMetrics] {
        &self.sprints
    }

    /// Gate time cost over an audit window: the sum of measured gate-event
    /// durations (the gate engine times digest-to-decision).
    pub fn gate_overhead_seconds(events: &[WorkflowEvent]) -> f64 {
        events
            .iter()
            .filter(|e| e.kind == WorkflowEventKind::Gate)
            .filter_map(|e| e.duration_ms)
            .map(|ms| ms as f64 / 1000.0)
            .sum()
    }

    /// CH7 self-report. Deterministic, pre-registered rule: the last N
    /// sprints all exceeded the gate-overhead budget AND defects opened did
    /// not decrease across that window (last < first counts as improvement
    /// and resets the verdict).
    pub fn self_report(&self) -> Option<PilotFailureReport> {
        let n = self.criteria.consecutive_sprints as usize;
        if n == 0 || self.sprints.len() < n {
            return None;
        }
        let window = &self.sprints[self.sprints.len() - n..];
        let all_over_budget = window
            .iter()
            .all(|s| s.gate_overhead_seconds > self.criteria.gate_overhead_budget_seconds);
        if !all_over_budget {
            return None;
        }
        let improved =
            window.last().unwrap().defects_opened < window.first().unwrap().defects_opened;
        if improved {
            return None;
        }
        Some(PilotFailureReport {
            to_owner: self.owner.clone(),
            message: format!(
                "gate overhead exceeded the {}s budget for {} consecutive sprints \
                 without defect-rate improvement — the workflow profile self-reports \
                 failure (§2.6, pre-registered)",
                self.criteria.gate_overhead_budget_seconds, n
            ),
            sprints_over_budget: n as u32,
        })
    }
}

/// Equity watch (§2.6, part C gaps): decline rates and hunt participation
/// are disaggregated by opaque cohort label — never per person — so
/// learned-avoidance patterns surface for review without anyone being
/// individually measured. CG-26's decline-without-record holds: the
/// counters here carry no actor identity and no link to a routed problem,
/// so no individual decline is ever attributable.
#[derive(Debug, Default, Serialize)]
pub struct EquityWatch {
    per_cohort: BTreeMap<String, CohortStats>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct CohortStats {
    pub routes_offered: u32,
    pub routes_declined: u32,
    pub hunts_run: u32,
}

impl EquityWatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_route_offered(&mut self, cohort: &str) {
        self.per_cohort.entry(cohort.into()).or_default().routes_offered += 1;
    }

    pub fn record_route_declined(&mut self, cohort: &str) {
        self.per_cohort.entry(cohort.into()).or_default().routes_declined += 1;
    }

    pub fn record_hunt(&mut self, cohort: &str) {
        self.per_cohort.entry(cohort.into()).or_default().hunts_run += 1;
    }

    pub fn stats(&self, cohort: &str) -> Option<&CohortStats> {
        self.per_cohort.get(cohort)
    }

    /// Cohorts whose decline rate exceeds `threshold` once at least
    /// `min_offers` routes were offered — a review flag, not a verdict.
    pub fn avoidance_flags(&self, threshold: f64, min_offers: u32) -> Vec<String> {
        self.per_cohort
            .iter()
            .filter(|(_, s)| {
                s.routes_offered >= min_offers
                    && (s.routes_declined as f64 / s.routes_offered as f64) > threshold
            })
            .map(|(cohort, _)| cohort.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use wyrtloom_core::types::Timestamp;

    fn sprint(sprint: u32, overhead: f64, defects: u32) -> SprintMetrics {
        SprintMetrics {
            sprint,
            gate_overhead_seconds: overhead,
            defects_opened: defects,
            rework_count: 0,
            suite_size: 10,
        }
    }

    fn instruments() -> PilotInstruments {
        PilotInstruments::new(
            AbandonmentCriteria {
                gate_overhead_budget_seconds: 100.0,
                consecutive_sprints: 3,
            },
            "human:owner".into(),
        )
    }

    #[test]
    fn ch7_over_budget_without_improvement_self_reports() {
        let mut p = instruments();
        for (i, overhead, defects) in [(1, 150.0, 5), (2, 160.0, 5), (3, 170.0, 6)] {
            p.record_sprint(sprint(i, overhead, defects));
        }
        let report = p.self_report().expect("must self-report failure");
        assert_eq!(report.to_owner, "human:owner");
        assert_eq!(report.sprints_over_budget, 3);
        assert!(report.message.contains("pre-registered"));
    }

    #[test]
    fn ch7_under_budget_sprint_resets_the_verdict() {
        let mut p = instruments();
        for (i, overhead, defects) in [(1, 150.0, 5), (2, 50.0, 5), (3, 170.0, 5)] {
            p.record_sprint(sprint(i, overhead, defects));
        }
        assert!(p.self_report().is_none());
    }

    #[test]
    fn ch7_defect_improvement_resets_the_verdict() {
        let mut p = instruments();
        for (i, overhead, defects) in [(1, 150.0, 8), (2, 160.0, 5), (3, 170.0, 3)] {
            p.record_sprint(sprint(i, overhead, defects));
        }
        assert!(p.self_report().is_none(), "defects fell 8 → 3 across the window");
    }

    #[test]
    fn ch7_too_few_sprints_is_no_verdict() {
        let mut p = instruments();
        p.record_sprint(sprint(1, 999.0, 5));
        assert!(p.self_report().is_none());
    }

    #[test]
    fn gate_overhead_sums_measured_gate_durations_only() {
        let event = |kind, ms| WorkflowEvent {
            kind,
            task: Uuid::new_v4(),
            actor: "human:dev".into(),
            detail: String::new(),
            at: Timestamp::now(),
            duration_ms: ms,
        };
        let events = vec![
            event(WorkflowEventKind::Gate, Some(1_500)),
            event(WorkflowEventKind::Gate, Some(500)),
            event(WorkflowEventKind::Gate, None), // unmeasured — ignored
            event(WorkflowEventKind::Hunt, Some(9_000)), // not a gate
        ];
        let total = PilotInstruments::gate_overhead_seconds(&events);
        assert!((total - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn equity_watch_flags_high_decline_cohorts_in_aggregate() {
        let mut watch = EquityWatch::new();
        for _ in 0..10 {
            watch.record_route_offered("cohort-a");
            watch.record_route_offered("cohort-b");
        }
        for _ in 0..8 {
            watch.record_route_declined("cohort-a");
        }
        watch.record_route_declined("cohort-b");
        watch.record_hunt("cohort-b");

        let flags = watch.avoidance_flags(0.5, 5);
        assert_eq!(flags, vec!["cohort-a".to_string()]);

        // Aggregate only: the serialised watch carries cohort labels and
        // counters, never actor identities.
        let json = serde_json::to_string(&watch).unwrap();
        assert!(!json.contains("human:"));
    }

    #[test]
    fn equity_watch_needs_enough_offers_before_flagging() {
        let mut watch = EquityWatch::new();
        watch.record_route_offered("cohort-c");
        watch.record_route_declined("cohort-c");
        assert!(watch.avoidance_flags(0.5, 5).is_empty());
    }
}
