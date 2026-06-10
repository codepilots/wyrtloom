/// W3 — Digest generator: gates are lessons first (CG-1..4). Dual coding
/// with the coherence constraint (seductive-details guard, CG-2), artifact
/// fading with reader calibration (expertise-reversal guard, CG-3), and a
/// conversational register (F22).
use crate::coverage::{Concept, ConceptId};
use serde::{Deserialize, Serialize};

/// Calibration score at or above which a digest fades to the terse,
/// single-representation form (CG-3).
pub const FADE_THRESHOLD: f64 = 0.75;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentItem {
    pub text: String,
    /// World-knowledge enrichment must map to an in-play concept or it is
    /// rejected outright (CG-2) — interest lives in relevance, never
    /// alongside it.
    pub maps_to: Option<ConceptId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Richness {
    /// Rich multimodal form for low-calibration readers.
    Voyage,
    /// Terse single-representation form for well-calibrated readers.
    Terse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digest {
    /// The lesson. Always precedes any challenge (CG-1).
    pub instruction: String,
    /// Load-bearing visual descriptions (dual coding); empty when terse.
    pub visuals: Vec<String>,
    /// Enrichment that survived the coherence filter (CG-2).
    pub enrichment: Vec<String>,
    pub richness: Richness,
}

impl Digest {
    /// Render for presentation: instruction first, then visuals, then
    /// enrichment. Callers append any challenge AFTER this text (CG-1).
    pub fn render(&self) -> String {
        let mut out = self.instruction.clone();
        for visual in &self.visuals {
            out.push_str(&format!("\n[{}]", visual));
        }
        for item in &self.enrichment {
            out.push_str(&format!("\nWorth knowing: {}", item));
        }
        out
    }
}

pub struct DigestGenerator;

impl DigestGenerator {
    /// Deterministic template filling (CG-4): an LLM may later rewrite the
    /// surface prose of these strings, but admission, fading, and ordering
    /// decisions are made here, in code — never by a model.
    pub fn generate(
        concepts_in_play: &[Concept],
        reader_calibration: f64,
        enrichment: &[EnrichmentItem],
        request_richer: bool,
    ) -> Digest {
        // Coherence constraint (CG-2): enrichment is admitted only when it
        // maps to a concept actually in play.
        let admitted: Vec<String> = enrichment
            .iter()
            .filter(|e| {
                e.maps_to
                    .as_deref()
                    .map_or(false, |c| concepts_in_play.iter().any(|p| p.id == c))
            })
            .map(|e| e.text.clone())
            .collect();

        // Artifact fading (CG-3): terse where calibration is high; the
        // richer form is always available on request.
        let richness = if reader_calibration >= FADE_THRESHOLD && !request_richer {
            Richness::Terse
        } else {
            Richness::Voyage
        };

        let mut instruction =
            String::from("Let's walk through what this change touches.\n");
        for c in concepts_in_play {
            instruction.push_str(&format!("- {} ({}): {}\n", c.id, c.component, c.summary));
        }

        let visuals = match richness {
            Richness::Terse => vec![],
            Richness::Voyage => concepts_in_play
                .iter()
                .map(|c| format!("diagram: {} within component {}", c.id, c.component))
                .collect(),
        };

        Digest { instruction, visuals, enrichment: admitted, richness }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn concepts() -> Vec<Concept> {
        vec![Concept {
            id: "tokeniser".into(),
            component: "parser".into(),
            summary: "splits raw input into tokens".into(),
        }]
    }

    #[test]
    fn cg2_unmapped_enrichment_is_rejected() {
        let enrichment = vec![
            EnrichmentItem {
                text: "fresh CVE affects tokenisers like this one".into(),
                maps_to: Some("tokeniser".into()),
            },
            EnrichmentItem {
                text: "fun fact about an unrelated subsystem".into(),
                maps_to: Some("scheduler".into()),
            },
            EnrichmentItem { text: "general trivia".into(), maps_to: None },
        ];
        let d = DigestGenerator::generate(&concepts(), 0.0, &enrichment, false);
        assert_eq!(d.enrichment.len(), 1);
        assert!(d.enrichment[0].contains("CVE"));
    }

    #[test]
    fn cg3_digest_fades_with_high_calibration() {
        let d = DigestGenerator::generate(&concepts(), 0.9, &[], false);
        assert_eq!(d.richness, Richness::Terse);
        assert!(d.visuals.is_empty());

        let d = DigestGenerator::generate(&concepts(), 0.2, &[], false);
        assert_eq!(d.richness, Richness::Voyage);
        assert!(!d.visuals.is_empty());
    }

    #[test]
    fn cg3_richer_form_available_on_request() {
        let d = DigestGenerator::generate(&concepts(), 0.9, &[], true);
        assert_eq!(d.richness, Richness::Voyage);
    }

    #[test]
    fn cg1_render_puts_instruction_first() {
        let enrichment = vec![EnrichmentItem {
            text: "context".into(),
            maps_to: Some("tokeniser".into()),
        }];
        let d = DigestGenerator::generate(&concepts(), 0.0, &enrichment, false);
        let rendered = d.render();
        let instruction_pos = rendered.find("Let's walk through").unwrap();
        let enrichment_pos = rendered.find("Worth knowing").unwrap();
        assert!(instruction_pos < enrichment_pos);
    }
}
