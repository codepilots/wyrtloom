/// W7 — Calibration ledger: per-person confidence-vs-outcome record.
/// Developmental, never evaluative (CG-15, CG-21..23): private by default
/// to the individual, retention-limited, exportable and deletable by the
/// owner, with governance enforced here at the storage layer. There is no
/// ranking query and no appraisal export — unsupported by API design.
use crate::coverage::ConceptId;
use crate::policy::LedgerGovernance;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wyrtloom_core::types::{ActorId, Timestamp};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PracticeKind {
    Hunt,
    Build,
    SoloFlight,
    Probe,
}

/// Every ledger entry is a practice event — there is deliberately no
/// "assessment" variant (CG-15).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PracticeEvent {
    pub concept: ConceptId,
    /// Stated confidence in [0, 1]; clamped on record.
    pub confidence: f64,
    pub success: bool,
    pub kind: PracticeKind,
    pub at: Timestamp,
}

#[derive(Error, Debug, PartialEq)]
pub enum GovernanceError {
    #[error("calibration ledgers are private to their owner (CG-21)")]
    PrivateLedger,
}

pub struct CalibrationLedger {
    owner: ActorId,
    governance: LedgerGovernance,
    events: Vec<PracticeEvent>,
}

impl CalibrationLedger {
    pub fn new(owner: ActorId, governance: LedgerGovernance) -> Self {
        Self { owner, governance, events: Vec::new() }
    }

    pub fn owner(&self) -> &ActorId {
        &self.owner
    }

    pub fn record_practice(&mut self, mut event: PracticeEvent) {
        event.confidence = event.confidence.clamp(0.0, 1.0);
        self.events.push(event);
    }

    /// Raw events are visible only to the owner (CG-21).
    pub fn events(&self, requestor: &ActorId) -> Result<&[PracticeEvent], GovernanceError> {
        if requestor != &self.owner {
            return Err(GovernanceError::PrivateLedger);
        }
        Ok(&self.events)
    }

    /// Calibration score in [0, 1] for one concept: 1 − mean Brier distance
    /// between stated confidence and outcome. Deterministic; the BKT-style
    /// update rule is a Phase-4 tuner candidate (§2.2, W7).
    pub fn score(&self, concept: &str) -> Option<f64> {
        let relevant: Vec<&PracticeEvent> =
            self.events.iter().filter(|e| e.concept == concept).collect();
        if relevant.is_empty() {
            return None;
        }
        let brier: f64 = relevant
            .iter()
            .map(|e| {
                let outcome = if e.success { 1.0 } else { 0.0 };
                (e.confidence - outcome).powi(2)
            })
            .sum::<f64>()
            / relevant.len() as f64;
        Some(1.0 - brier)
    }

    /// Overall score across all events. 0.0 when the ledger is empty, so an
    /// unknown reader receives the richest digest form (artifact fading,
    /// CG-3).
    pub fn overall_score(&self) -> f64 {
        if self.events.is_empty() {
            return 0.0;
        }
        let brier: f64 = self
            .events
            .iter()
            .map(|e| {
                let outcome = if e.success { 1.0 } else { 0.0 };
                (e.confidence - outcome).powi(2)
            })
            .sum::<f64>()
            / self.events.len() as f64;
        1.0 - brier
    }

    /// Retention limit, enforced at the storage layer (CG-22).
    pub fn enforce_retention(&mut self, now: &Timestamp) {
        let cutoff = now.0 - chrono::Duration::days(self.governance.retention_days as i64);
        self.events.retain(|e| e.at.0 >= cutoff);
    }

    /// Owner-initiated export (CG-22).
    pub fn export(&self, requestor: &ActorId) -> Result<String, GovernanceError> {
        if requestor != &self.owner {
            return Err(GovernanceError::PrivateLedger);
        }
        Ok(serde_json::to_string(&self.events).unwrap_or_else(|_| "[]".into()))
    }

    /// Owner-initiated delete (CG-22).
    pub fn delete(&mut self, requestor: &ActorId) -> Result<(), GovernanceError> {
        if requestor != &self.owner {
            return Err(GovernanceError::PrivateLedger);
        }
        self.events.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn ledger() -> CalibrationLedger {
        CalibrationLedger::new("human:alice".into(), LedgerGovernance::new(30))
    }

    fn event(concept: &str, confidence: f64, success: bool) -> PracticeEvent {
        PracticeEvent {
            concept: concept.into(),
            confidence,
            success,
            kind: PracticeKind::Probe,
            at: Timestamp::now(),
        }
    }

    #[test]
    fn cg21_events_are_private_to_owner() {
        let mut l = ledger();
        l.record_practice(event("parser", 0.8, true));
        assert!(l.events(&"human:alice".to_string()).is_ok());
        assert!(matches!(
            l.events(&"human:manager".to_string()),
            Err(GovernanceError::PrivateLedger)
        ));
    }

    #[test]
    fn cg22_export_and_delete_are_owner_only() {
        let mut l = ledger();
        l.record_practice(event("parser", 0.8, true));
        assert!(l.export(&"human:manager".to_string()).is_err());
        let exported = l.export(&"human:alice".to_string()).unwrap();
        assert!(exported.contains("parser"));

        assert!(l.delete(&"human:manager".to_string()).is_err());
        l.delete(&"human:alice".to_string()).unwrap();
        assert!(l.events(&"human:alice".to_string()).unwrap().is_empty());
    }

    #[test]
    fn cg22_retention_limit_prunes_old_events() {
        let mut l = ledger();
        let mut old = event("parser", 0.8, true);
        old.at = Timestamp(Timestamp::now().0 - Duration::days(60));
        l.record_practice(old);
        l.record_practice(event("parser", 0.9, true));

        l.enforce_retention(&Timestamp::now());
        assert_eq!(l.events(&"human:alice".to_string()).unwrap().len(), 1);
    }

    #[test]
    fn perfect_calibration_scores_one() {
        let mut l = ledger();
        l.record_practice(event("parser", 1.0, true));
        l.record_practice(event("parser", 0.0, false));
        assert!((l.score("parser").unwrap() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn overconfidence_lowers_the_score() {
        let mut l = ledger();
        l.record_practice(event("parser", 1.0, false));
        assert!((l.score("parser").unwrap() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn cg3_empty_ledger_scores_zero_for_richest_digests() {
        assert_eq!(ledger().overall_score(), 0.0);
        assert!(ledger().score("parser").is_none());
    }

    #[test]
    fn confidence_is_clamped_on_record() {
        let mut l = ledger();
        l.record_practice(event("parser", 7.0, true));
        let events = l.events(&"human:alice".to_string()).unwrap();
        assert!((events[0].confidence - 1.0).abs() < f64::EPSILON);
    }
}
