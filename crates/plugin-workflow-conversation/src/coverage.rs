/// W6 — Coverage map: the system's concept inventory per component, linking
/// artifacts ↔ concepts ↔ humans with living theories of them (CG-6, CG-19,
/// CG-21).
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
use wyrtloom_core::types::{ActorId, Timestamp};

pub type ConceptId = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Concept {
    pub id: ConceptId,
    pub component: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditSource {
    Hunt(Uuid),
    Build(Uuid),
    SoloFlight(Uuid),
    Probe(Uuid),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditEvent {
    pub human: ActorId,
    pub concept: ConceptId,
    pub source: CreditSource,
    pub at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArtifactRef {
    Code(String),
    Test(String),
    Contract(String),
    Rationale(Uuid),
    Insight(Uuid),
}

/// Aggregate-only team view (CG-21): per-concept redundancy and nothing
/// else. Contains no actor identifiers by construction — never a
/// per-person league table.
#[derive(Debug, Clone, Serialize)]
pub struct TeamView {
    pub per_concept_redundancy: BTreeMap<ConceptId, usize>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CoverageMap {
    concepts: BTreeMap<ConceptId, Concept>,
    links: BTreeMap<ConceptId, Vec<ArtifactRef>>,
    credits: Vec<CreditEvent>,
}

impl CoverageMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_concept(&mut self, concept: Concept) {
        self.concepts.insert(concept.id.clone(), concept);
    }

    pub fn contains(&self, id: &str) -> bool {
        self.concepts.contains_key(id)
    }

    pub fn get(&self, id: &str) -> Option<&Concept> {
        self.concepts.get(id)
    }

    pub fn link_artifact(&mut self, concept: &str, artifact: ArtifactRef) {
        self.links.entry(concept.to_string()).or_default().push(artifact);
    }

    pub fn links(&self, concept: &str) -> &[ArtifactRef] {
        self.links.get(concept).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Deterministic crediting (CG-6): the exercised execution trace
    /// intersected with the concept inventory — independent of whether any
    /// test passed or broke its target.
    pub fn credit_from_trace(
        &mut self,
        human: &ActorId,
        exercised: &[ConceptId],
        source: CreditSource,
        at: Timestamp,
    ) -> Vec<ConceptId> {
        let mut credited: Vec<ConceptId> = exercised
            .iter()
            .filter(|c| self.concepts.contains_key(*c))
            .cloned()
            .collect();
        credited.sort();
        credited.dedup();
        for concept in &credited {
            self.credits.push(CreditEvent {
                human: human.clone(),
                concept: concept.clone(),
                source: source.clone(),
                at: at.clone(),
            });
        }
        credited
    }

    /// A concept is dark when no human holds living credit for it — the
    /// trigger condition for fallback probes (CG-19).
    pub fn is_dark(&self, concept: &str) -> bool {
        !self.credits.iter().any(|c| c.concept == concept)
    }

    /// Dark concepts in deterministic (sorted) order.
    pub fn dark_concepts(&self) -> Vec<ConceptId> {
        self.concepts
            .keys()
            .filter(|id| self.is_dark(id))
            .cloned()
            .collect()
    }

    /// Number of distinct humans with credit on a concept (bus-factor).
    pub fn redundancy(&self, concept: &str) -> usize {
        self.credits
            .iter()
            .filter(|c| c.concept == concept)
            .map(|c| c.human.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub fn team_view(&self) -> TeamView {
        TeamView {
            per_concept_redundancy: self
                .concepts
                .keys()
                .map(|id| (id.clone(), self.redundancy(id)))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_with(ids: &[&str]) -> CoverageMap {
        let mut m = CoverageMap::new();
        for id in ids {
            m.add_concept(Concept {
                id: id.to_string(),
                component: "parser".into(),
                summary: format!("concept {}", id),
            });
        }
        m
    }

    #[test]
    fn cg6_credit_is_trace_intersect_map() {
        let mut m = map_with(&["a", "b"]);
        let credited = m.credit_from_trace(
            &"human:dev".to_string(),
            &["a".into(), "zz-not-in-map".into(), "a".into()],
            CreditSource::Hunt(Uuid::new_v4()),
            Timestamp::now(),
        );
        // Only mapped concepts credit, deduplicated.
        assert_eq!(credited, vec!["a".to_string()]);
        assert!(!m.is_dark("a"));
        assert!(m.is_dark("b"));
    }

    #[test]
    fn cg19_dark_concepts_are_those_without_credit() {
        let mut m = map_with(&["a", "b", "c"]);
        m.credit_from_trace(
            &"human:dev".to_string(),
            &["b".into()],
            CreditSource::Build(Uuid::new_v4()),
            Timestamp::now(),
        );
        assert_eq!(m.dark_concepts(), vec!["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn cg21_team_view_is_aggregate_only_no_actor_ids() {
        let mut m = map_with(&["a"]);
        m.credit_from_trace(
            &"human:alice".to_string(),
            &["a".into()],
            CreditSource::Hunt(Uuid::new_v4()),
            Timestamp::now(),
        );
        m.credit_from_trace(
            &"human:bob".to_string(),
            &["a".into()],
            CreditSource::Probe(Uuid::new_v4()),
            Timestamp::now(),
        );
        let view = m.team_view();
        assert_eq!(view.per_concept_redundancy["a"], 2);
        // The serialised team view must not leak any per-person identifier.
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("alice"));
        assert!(!json.contains("bob"));
    }

    #[test]
    fn artifacts_link_to_concepts() {
        let mut m = map_with(&["a"]);
        m.link_artifact("a", ArtifactRef::Code("src/parser.rs".into()));
        m.link_artifact("a", ArtifactRef::Insight(Uuid::new_v4()));
        assert_eq!(m.links("a").len(), 2);
        assert!(m.links("unknown").is_empty());
    }
}
