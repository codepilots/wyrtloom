/// Build & Own (CG-10..12): humans build and own important elements — not
/// leftovers — on a reserved-rung quota. The Groundwork Principle (D13):
/// reserved tasks must be legitimate, graduated, and generative; anything
/// failing the three Gs is busywork and goes to the agent.
use crate::calibration::CalibrationLedger;
use crate::coverage::ConceptId;
use crate::policy::MasteryPolicy;
use serde::{Deserialize, Serialize};
use wyrtloom_core::types::{ActorId, TaskId};

/// The calibrated zone of proximal development (CG-11): important AND
/// completable. Below the band the work is busywork; above it, the build
/// cannot complete and the IKEA effect never lands (F32).
pub const ZPD_LOW: f64 = 0.25;
pub const ZPD_HIGH: f64 = 0.9;

/// Calibration assumed for concepts the builder has no record on — mid-band,
/// so new humans still receive builds.
const UNKNOWN_CONCEPT_SCORE: f64 = 0.5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkItem {
    pub task: TaskId,
    pub title: String,
    /// Agent proposes, human confirms (§2.4); `Some` marks importance.
    pub criticality_tag: Option<String>,
    /// Passed the three Gs (legitimate, graduated, generative).
    pub graduated: bool,
    pub concepts: Vec<ConceptId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildAssignment {
    pub task: TaskId,
    pub builder: ActorId,
    /// Scaffolding is always available on request (CG-11).
    pub scaffold_available: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub message: String,
    /// CG-12: surfaced to the project owner.
    pub surface_to: ActorId,
}

/// Mean calibration over the item's concepts.
fn item_score(item: &WorkItem, ledger: &CalibrationLedger) -> f64 {
    if item.concepts.is_empty() {
        return UNKNOWN_CONCEPT_SCORE;
    }
    item.concepts
        .iter()
        .map(|c| ledger.score(c).unwrap_or(UNKNOWN_CONCEPT_SCORE))
        .sum::<f64>()
        / item.concepts.len() as f64
}

/// CG-10/11: reserve the policy quota of graduated, criticality-tagged work
/// for the builder, selecting items that are important AND completable
/// (within the builder's calibrated ZPD). Deterministic: candidates are
/// ordered by task id.
pub fn reserve(
    items: &[WorkItem],
    policy: &MasteryPolicy,
    builder: &ActorId,
    ledger: &CalibrationLedger,
) -> Vec<BuildAssignment> {
    let graduated_count = items.iter().filter(|i| i.graduated).count();
    if graduated_count == 0 {
        return vec![];
    }
    let quota = (policy.reserved_rung_quota * graduated_count as f64).ceil() as usize;

    let mut eligible: Vec<&WorkItem> = items
        .iter()
        .filter(|i| i.graduated && i.criticality_tag.is_some())
        .filter(|i| {
            let score = item_score(i, ledger);
            (ZPD_LOW..=ZPD_HIGH).contains(&score)
        })
        .collect();
    eligible.sort_by_key(|i| i.task);

    eligible
        .into_iter()
        .take(quota)
        .map(|i| BuildAssignment {
            task: i.task,
            builder: builder.clone(),
            scaffold_available: true,
        })
        .collect()
}

/// CG-12: agent absorption of 100% of graduated work is a policy violation
/// surfaced to the project owner.
pub fn absorption_violation(
    graduated_total: usize,
    human_assigned: usize,
    owner: &ActorId,
) -> Option<PolicyViolation> {
    if graduated_total > 0 && human_assigned == 0 {
        Some(PolicyViolation {
            message: "the agent absorbed 100% of graduated work — the reserved rung \
                      is empty (CG-12)"
                .into(),
            surface_to: owner.clone(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibration::{PracticeEvent, PracticeKind};
    use crate::policy::LedgerGovernance;
    use uuid::Uuid;
    use wyrtloom_core::types::Timestamp;

    fn item(tag: Option<&str>, graduated: bool, concepts: &[&str]) -> WorkItem {
        WorkItem {
            task: Uuid::new_v4(),
            title: "rate limiter".into(),
            criticality_tag: tag.map(String::from),
            graduated,
            concepts: concepts.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn ledger() -> CalibrationLedger {
        CalibrationLedger::new("human:builder".into(), LedgerGovernance::new(365))
    }

    fn policy() -> MasteryPolicy {
        MasteryPolicy::conversation_default("human:owner".into())
    }

    #[test]
    fn cg10_quota_reserves_a_minimum_fraction() {
        // 5 graduated items, quota 0.2 → at least 1 reserved.
        let items: Vec<WorkItem> =
            (0..5).map(|_| item(Some("critical"), true, &[])).collect();
        let reserved = reserve(&items, &policy(), &"human:builder".into(), &ledger());
        assert_eq!(reserved.len(), 1);
        assert!(reserved[0].scaffold_available, "scaffold on request (CG-11)");
    }

    #[test]
    fn cg11_reserved_builds_are_important_and_completable() {
        let mut ledger = ledger();
        // Builder is extremely well-calibrated on "easy" — outside ZPD (boredom).
        for _ in 0..4 {
            ledger.record_practice(PracticeEvent {
                concept: "easy".into(),
                confidence: 1.0,
                success: true,
                kind: PracticeKind::Build,
                at: Timestamp::now(),
            });
        }
        let items = vec![
            item(None, true, &[]),               // not important: no tag
            item(Some("critical"), true, &["easy"]), // outside ZPD
            item(Some("critical"), true, &["new-ground"]), // in ZPD (unknown → 0.5)
        ];
        let reserved = reserve(&items, &policy(), &"human:builder".into(), &ledger);
        assert_eq!(reserved.len(), 1);
        assert_eq!(reserved[0].task, items[2].task);
    }

    #[test]
    fn cg12_full_agent_absorption_is_a_violation() {
        let owner: ActorId = "human:owner".into();
        let violation = absorption_violation(7, 0, &owner).unwrap();
        assert_eq!(violation.surface_to, owner);
        assert!(violation.message.contains("100%"));

        assert!(absorption_violation(7, 2, &owner).is_none());
        assert!(absorption_violation(0, 0, &owner).is_none());
    }

    #[test]
    fn no_graduated_work_reserves_nothing() {
        let items = vec![item(Some("critical"), false, &[])];
        assert!(reserve(&items, &policy(), &"human:builder".into(), &ledger()).is_empty());
    }
}
