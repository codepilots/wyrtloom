/// W9 — Insight Artifacts (CG-27): a first-class home for human abstraction
/// and novel explanation, beside code, tests, and documentation. Authorship
/// is human; the capture labor is the agent's (D3, D14.2).
use crate::coverage::ConceptId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wyrtloom_core::types::{ActorId, Timestamp};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BornOf {
    Hunt(Uuid),
    Build(Uuid),
    Route(Uuid),
    Gate(Uuid),
    SoloFlight(Uuid),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InsightLink {
    Code(String),
    Rationale(Uuid),
    Test(String),
    Contract(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InsightStatus {
    Living,
    Superseded { by: Uuid },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsightArtifact {
    pub id: Uuid,
    /// The human whose abstraction this is.
    pub author: ActorId,
    /// The agent that paid the capture cost.
    pub captured_by: ActorId,
    pub created_at: Timestamp,
    /// The novel explanation itself.
    pub abstraction: String,
    pub born_of: BornOf,
    /// Linkable from coverage-map concepts (CG-27).
    pub concepts: Vec<ConceptId>,
    pub links: Vec<InsightLink>,
    pub status: InsightStatus,
}

impl InsightArtifact {
    pub fn new(
        author: ActorId,
        captured_by: ActorId,
        abstraction: String,
        born_of: BornOf,
        concepts: Vec<ConceptId>,
        links: Vec<InsightLink>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            author,
            captured_by,
            created_at: Timestamp::now(),
            abstraction,
            born_of,
            concepts,
            links,
            status: InsightStatus::Living,
        }
    }

    pub fn supersede(&mut self, by: Uuid) {
        self.status = InsightStatus::Superseded { by };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> InsightArtifact {
        InsightArtifact::new(
            "human:alice".into(),
            "agent:wyrt".into(),
            "the tokeniser is really a state machine over byte classes".into(),
            BornOf::Hunt(Uuid::new_v4()),
            vec!["tokeniser".into()],
            vec![InsightLink::Code("src/parser.rs".into())],
        )
    }

    #[test]
    fn cg27_insight_is_typed_human_authored_agent_captured() {
        let a = artifact();
        assert_eq!(a.author, "human:alice");
        assert_eq!(a.captured_by, "agent:wyrt");
        assert_eq!(a.status, InsightStatus::Living);
        assert_eq!(a.concepts, vec!["tokeniser".to_string()]);
        assert!(matches!(a.born_of, BornOf::Hunt(_)));
    }

    #[test]
    fn cg27_insights_supersede_without_deletion() {
        let mut a = artifact();
        let successor = Uuid::new_v4();
        a.supersede(successor);
        assert_eq!(a.status, InsightStatus::Superseded { by: successor });
        // The abstraction text survives supersession.
        assert!(!a.abstraction.is_empty());
    }

    #[test]
    fn cg27_insights_serialise_for_storage() {
        let a = artifact();
        let json = serde_json::to_string(&a).unwrap();
        let back: InsightArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, a.id);
        assert_eq!(back.links, a.links);
    }
}
