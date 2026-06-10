/// W13 — Rationale ledger: ADR-shaped decision records, agent-authored as a
/// by-product of the conversation (the agent pays the capture cost, D3;
/// shape per the rationale-capture literature, F11).
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wyrtloom_core::types::{ActorId, Timestamp};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdrRecord {
    pub id: Uuid,
    pub title: String,
    pub context: String,
    pub decision: String,
    pub consequences: String,
    /// The agent that wrote the record down.
    pub author: ActorId,
    pub at: Timestamp,
}

impl AdrRecord {
    pub fn new(
        title: impl Into<String>,
        context: impl Into<String>,
        decision: impl Into<String>,
        consequences: impl Into<String>,
        author: ActorId,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            context: context.into(),
            decision: decision.into(),
            consequences: consequences.into(),
            author,
            at: Timestamp::now(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RationaleLedger {
    records: Vec<AdrRecord>,
}

impl RationaleLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, record: AdrRecord) -> Uuid {
        let id = record.id;
        self.records.push(record);
        id
    }

    pub fn list(&self) -> &[AdrRecord] {
        &self.records
    }

    pub fn find(&self, id: Uuid) -> Option<&AdrRecord> {
        self.records.iter().find(|r| r.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adr_records_carry_context_decision_consequences() {
        let mut ledger = RationaleLedger::new();
        let id = ledger.append(AdrRecord::new(
            "Use expanding-interval spacing for solo flights",
            "Skill decay under automation requires spaced unassisted practice",
            "Adopt expanding intervals with a configurable ceiling",
            "Cadence stretches as competence consolidates; revisit at the pilot",
            "agent:wyrt".into(),
        ));
        let record = ledger.find(id).unwrap();
        assert!(!record.context.is_empty());
        assert!(!record.decision.is_empty());
        assert!(!record.consequences.is_empty());
        assert_eq!(ledger.list().len(), 1);
    }

    #[test]
    fn unknown_ids_find_nothing() {
        let ledger = RationaleLedger::new();
        assert!(ledger.find(Uuid::new_v4()).is_none());
    }
}
