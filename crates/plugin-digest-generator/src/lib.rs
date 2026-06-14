//! Instruction-first digest generator (Wyrtloom W3, spec §2.2 row W3).
//!
//! A *digest* is the lesson shown when a Kanban gate opens. Instruction always
//! precedes any challenge (CG-1). This crate assembles that artifact under two
//! deterministic rules drawn from the Conversation-layer contract:
//!
//!   * **Coherence constraint (CG-2 / D15.1 — seductive-details guard).**
//!     World-knowledge enrichment (fresh threat intel, ecosystem news) is
//!     admitted *only* when it maps to a concept actually in play on the
//!     coverage map. Seductive-but-unmapped details are dropped — interest must
//!     live in relevance, never alongside it.
//!
//!   * **Artifact fading (CG-3 / D15.2 — expertise-reversal guard).** Digest
//!     richness fades as the reader's calibration score rises: rich multimodal
//!     form where calibration is low, terse single-representation form where it
//!     is high. The richer form is always available on request.
//!
//! **Determinism (CG-4 / R24).** The coherence filter, the fading selection,
//! and every other decision in this crate are plain deterministic code. The
//! [`LlmProvider`] is used to fill the digest's SURFACE TEXT ONLY — it never
//! grades, gates, selects, or makes any decision.
//!
//! Reference style: `crates/plugin-logger-sqlite/src/lib.rs`.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use wyrtloom_core::provider::{
    GenerationRequest, LlmProvider, Message, ProviderError,
};
use wyrtloom_core::types::ModelId;

/// Minimal local representation of a coverage-map concept.
///
/// W3 does not depend on the sibling coverage-map crate (not merged yet), so it
/// carries its own newtype. A `ConceptId` is an opaque, comparable identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConceptId(pub String);

impl ConceptId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl<T: Into<String>> From<T> for ConceptId {
    fn from(s: T) -> Self {
        ConceptId(s.into())
    }
}

/// A reader's calibration score for the gate's subject matter.
///
/// Calibration measures how well the reader's confidence tracks their accuracy.
/// Stored as a value in `[0.0, 1.0]`; higher means better-calibrated, which —
/// per CG-3 — earns a terser digest. The constructor clamps out-of-range input
/// so a malformed score can never widen or hide the lesson.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Calibration(f64);

impl Calibration {
    /// Construct a calibration score, clamping to `[0.0, 1.0]`.
    pub fn new(score: f64) -> Self {
        // NaN clamps to the low (richest) end — a missing/garbled signal must
        // never accidentally suppress instruction.
        let s = if score.is_nan() { 0.0 } else { score.clamp(0.0, 1.0) };
        Self(s)
    }

    pub fn score(self) -> f64 {
        self.0
    }
}

/// How rich the assembled digest is. Lower calibration earns a richer tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Richness {
    /// Rich multimodal voyage — for low calibration.
    Rich,
    /// Standard words-plus-one-visual form — mid calibration.
    Standard,
    /// Terse single-representation digest — high calibration.
    Terse,
}

impl Richness {
    /// Deterministic fading selector (CG-3). Pure function of the calibration
    /// score — no LLM, no randomness.
    ///
    /// Thresholds are inclusive at the lower bound so the mapping is total and
    /// monotone: as calibration rises, richness never increases.
    pub fn for_calibration(c: Calibration) -> Self {
        let s = c.score();
        if s >= 0.66 {
            Richness::Terse
        } else if s >= 0.33 {
            Richness::Standard
        } else {
            Richness::Rich
        }
    }

    /// Number of enrichment items this tier is allowed to surface. Fading means
    /// fewer admitted enrichments at higher calibration; `Rich` admits all.
    fn enrichment_budget(self) -> usize {
        match self {
            Richness::Rich => usize::MAX,
            Richness::Standard => 2,
            Richness::Terse => 0,
        }
    }

    /// Number of visual representations this tier carries (dual-coding lives
    /// only where it is load-bearing — D15.1).
    fn visual_count(self) -> usize {
        match self {
            Richness::Rich => 2,
            Richness::Standard => 1,
            Richness::Terse => 0,
        }
    }
}

/// A candidate world-knowledge enrichment offered to the digest (e.g. fresh
/// threat intel or ecosystem news). It is admitted only if it maps to an
/// in-play coverage-map concept (CG-2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Enrichment {
    /// Short human-readable label for the enrichment.
    pub label: String,
    /// The coverage-map concepts this enrichment claims to map to. An empty
    /// vec, or one whose concepts are none of them in play, makes the
    /// enrichment seductive-but-unmapped and it is dropped.
    pub maps_to: Vec<ConceptId>,
}

impl Enrichment {
    pub fn new(label: impl Into<String>, maps_to: Vec<ConceptId>) -> Self {
        Self { label: label.into(), maps_to }
    }
}

/// The inputs to a single digest assembly.
#[derive(Debug, Clone)]
pub struct DigestRequest {
    /// The lesson's core instruction text key/topic (always present — CG-1).
    pub instruction: String,
    /// The concepts actually in play for this gate. Drives the coherence
    /// filter (CG-2).
    pub in_play: Vec<ConceptId>,
    /// Candidate enrichments to consider admitting.
    pub candidate_enrichments: Vec<Enrichment>,
    /// The reader's calibration score for this subject (drives fading, CG-3).
    pub calibration: Calibration,
    /// Model to use for SURFACE TEXT generation only.
    pub model: ModelId,
    /// Output-token budget for the surface-text generation call.
    pub max_output_tokens: u32,
    /// When true the reader explicitly requested the richer form; fading is
    /// overridden up to `Rich` (CG-3 — "richer form available on request").
    pub request_richer: bool,
}

impl DigestRequest {
    pub fn new(
        instruction: impl Into<String>,
        in_play: Vec<ConceptId>,
        candidate_enrichments: Vec<Enrichment>,
        calibration: Calibration,
        model: impl Into<ModelId>,
    ) -> Self {
        Self {
            instruction: instruction.into(),
            in_play,
            candidate_enrichments,
            calibration,
            model: model.into(),
            max_output_tokens: 512,
            request_richer: false,
        }
    }

    /// Builder: opt into the richer form on the reader's request (CG-3).
    pub fn with_richer_form(mut self) -> Self {
        self.request_richer = true;
        self
    }
}

/// The assembled, instruction-first digest artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Digest {
    /// Surface text filled by the LLM. Decorative only — load-bearing
    /// structure lives in the fields below, all set by deterministic code.
    pub surface_text: String,
    /// The richness tier selected by the fading rule (CG-3).
    pub richness: Richness,
    /// Number of load-bearing visuals carried (dual coding, D15.1).
    pub visual_count: usize,
    /// The enrichments that survived the coherence filter (CG-2). Always a
    /// subset of the request's candidates that mapped to an in-play concept.
    pub admitted_enrichments: Vec<Enrichment>,
    /// Always true: a digest is the instruction-first artifact (CG-1).
    pub instruction_first: bool,
}

#[derive(Error, Debug)]
pub enum DigestError {
    #[error("digest must carry instruction text (CG-1)")]
    MissingInstruction,
    #[error("surface-text provider error: {0}")]
    Provider(#[from] ProviderError),
}

/// Generates instruction-first digests under the coherence (CG-2) and fading
/// (CG-3) rules. Borrows an [`LlmProvider`] for surface text only (CG-4).
pub struct DigestGenerator<'p> {
    provider: &'p dyn LlmProvider,
}

impl<'p> DigestGenerator<'p> {
    pub fn new(provider: &'p dyn LlmProvider) -> Self {
        Self { provider }
    }

    /// Deterministic coherence filter (CG-2 / D15.1).
    ///
    /// Keeps an enrichment iff at least one of its `maps_to` concepts is in
    /// play. Pure function of its inputs — order-preserving, no LLM.
    pub fn coherence_filter(
        candidates: &[Enrichment],
        in_play: &[ConceptId],
    ) -> Vec<Enrichment> {
        candidates
            .iter()
            .filter(|e| e.maps_to.iter().any(|c| in_play.contains(c)))
            .cloned()
            .collect()
    }

    /// Assemble a digest.
    ///
    /// Decision order is all-deterministic; the LLM call is the final, purely
    /// cosmetic step:
    ///   1. CG-1 — require instruction text.
    ///   2. CG-3 — select the richness tier from calibration (or honour an
    ///      explicit request for the richer form).
    ///   3. CG-2 — drop seductive/unmapped enrichment via the coherence filter.
    ///   4. CG-3 — fade: trim admitted enrichment to the tier's budget.
    ///   5. Fill SURFACE TEXT ONLY with the provider (CG-4).
    pub fn generate(&self, req: &DigestRequest) -> Result<Digest, DigestError> {
        // 1. CG-1 — instruction-first. No instruction → no digest.
        if req.instruction.trim().is_empty() {
            return Err(DigestError::MissingInstruction);
        }

        // 2. CG-3 — fading selection (deterministic). An explicit request for
        //    the richer form overrides the fade up to Rich.
        let richness = if req.request_richer {
            Richness::Rich
        } else {
            Richness::for_calibration(req.calibration)
        };

        // 3. CG-2 — coherence filter: drop unmapped/seductive enrichment.
        let mut admitted =
            Self::coherence_filter(&req.candidate_enrichments, &req.in_play);

        // 4. CG-3 — fade enrichment to the tier's budget. Truncation is
        //    order-preserving so it is deterministic.
        let budget = richness.enrichment_budget();
        if admitted.len() > budget {
            admitted.truncate(budget);
        }

        // 5. CG-4 — provider fills SURFACE TEXT ONLY. None of the structure
        //    above depends on its output.
        let surface_text = self.fill_surface_text(req, richness, &admitted)?;

        Ok(Digest {
            surface_text,
            richness,
            visual_count: richness.visual_count(),
            admitted_enrichments: admitted,
            instruction_first: true,
        })
    }

    /// Build the prompt and call the provider for decorative surface text.
    /// The returned string is never parsed for decisions (CG-4).
    fn fill_surface_text(
        &self,
        req: &DigestRequest,
        richness: Richness,
        admitted: &[Enrichment],
    ) -> Result<String, DigestError> {
        let style = match richness {
            Richness::Rich => "a rich, multimodal walkthrough",
            Richness::Standard => "a standard words-plus-one-visual brief",
            Richness::Terse => "a terse single-representation summary",
        };
        let enrichment_labels: Vec<&str> =
            admitted.iter().map(|e| e.label.as_str()).collect();

        let prompt = format!(
            "Write {style} of the following lesson. \
             Instruction: {}\nRelevant enrichments: {}\n\
             Surface text only; do not add facts beyond those listed.",
            req.instruction,
            if enrichment_labels.is_empty() {
                "(none)".to_string()
            } else {
                enrichment_labels.join(", ")
            },
        );

        let gen = GenerationRequest {
            messages: vec![
                Message::system(
                    "You fill digest surface text. You never decide, grade, \
                     or add unlisted facts.",
                ),
                Message::user(prompt),
            ],
            max_output_tokens: req.max_output_tokens,
            model: req.model.clone(),
        };

        let resp = self.provider.generate(gen)?;
        Ok(resp.full_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrtloom_core::provider::{
        ContentBlock, GenerationResponse, ModelDescriptor, Usage,
    };

    /// Deterministic stub provider: returns fixed surface text, regardless of
    /// the prompt. It never participates in any decision — that is the point.
    struct StubProvider {
        fixed: String,
    }

    impl LlmProvider for StubProvider {
        fn generate(
            &self,
            _req: GenerationRequest,
        ) -> Result<GenerationResponse, ProviderError> {
            Ok(GenerationResponse {
                content: vec![ContentBlock::Text(self.fixed.clone())],
                usage: Usage { input_tokens: 1, output_tokens: 1, cost: None },
            })
        }
        fn models(&self) -> Vec<ModelDescriptor> {
            vec![ModelDescriptor {
                id: "stub".into(),
                description: None,
                cost_per_input_token: None,
                cost_per_output_token: None,
            }]
        }
    }

    fn stub() -> StubProvider {
        StubProvider { fixed: "FIXED SURFACE TEXT".into() }
    }

    // ---- Contract tests (CG-1..CG-4) ----

    /// CG-1: a digest must carry instruction text; empty instruction is an
    /// error, never a silent empty lesson.
    #[test]
    fn cg1_instruction_first_required() {
        let p = stub();
        let g = DigestGenerator::new(&p);
        let req = DigestRequest::new(
            "   ",
            vec![],
            vec![],
            Calibration::new(0.0),
            "stub",
        );
        assert!(matches!(
            g.generate(&req),
            Err(DigestError::MissingInstruction)
        ));
    }

    /// CG-1: a well-formed digest is always flagged instruction-first.
    #[test]
    fn cg1_digest_is_instruction_first() {
        let p = stub();
        let g = DigestGenerator::new(&p);
        let req = DigestRequest::new(
            "Explain the parser contract.",
            vec![ConceptId::new("parser")],
            vec![],
            Calibration::new(0.0),
            "stub",
        );
        let d = g.generate(&req).unwrap();
        assert!(d.instruction_first);
    }

    /// CG-2: seductive/unmapped enrichment is dropped; mapped enrichment is
    /// kept. This is the required core-integration assertion.
    #[test]
    fn cg2_unmapped_enrichment_is_dropped() {
        let p = stub();
        let g = DigestGenerator::new(&p);

        let in_play = vec![ConceptId::new("unicode-parsing")];
        let mapped = Enrichment::new(
            "CVE in unicode normalisation",
            vec![ConceptId::new("unicode-parsing")],
        );
        // Seductive but irrelevant: maps to a concept NOT in play.
        let seductive = Enrichment::new(
            "shiny unrelated zero-day",
            vec![ConceptId::new("rocket-telemetry")],
        );
        // Seductive with no mapping at all.
        let unmapped = Enrichment::new("fun fact about octopuses", vec![]);

        let req = DigestRequest::new(
            "Explain unicode parsing pitfalls.",
            in_play,
            vec![mapped.clone(), seductive, unmapped],
            Calibration::new(0.0), // Rich tier: budget does not trim anything
            "stub",
        );

        let d = g.generate(&req).unwrap();
        assert_eq!(d.admitted_enrichments, vec![mapped]);
    }

    /// CG-3: richness decreases monotonically as calibration rises. This is the
    /// required core-integration assertion.
    #[test]
    fn cg3_richness_fades_with_calibration() {
        let p = stub();
        let g = DigestGenerator::new(&p);

        let make = |cal: f64| {
            let req = DigestRequest::new(
                "Lesson.",
                vec![],
                vec![],
                Calibration::new(cal),
                "stub",
            );
            g.generate(&req).unwrap()
        };

        let low = make(0.0); // poorly calibrated
        let mid = make(0.5);
        let high = make(0.9); // well calibrated

        assert_eq!(low.richness, Richness::Rich);
        assert_eq!(mid.richness, Richness::Standard);
        assert_eq!(high.richness, Richness::Terse);

        // Richness, expressed as visual count, never increases as calibration
        // rises (monotone fade).
        assert!(low.visual_count >= mid.visual_count);
        assert!(mid.visual_count >= high.visual_count);
        assert!(high.visual_count < low.visual_count);
    }

    /// CG-3: higher calibration admits fewer enrichments even when all are
    /// coherent — fading trims surviving enrichment to the tier budget.
    #[test]
    fn cg3_enrichment_count_fades_with_calibration() {
        let p = stub();
        let g = DigestGenerator::new(&p);

        let concept = ConceptId::new("c");
        let many: Vec<Enrichment> = (0..5)
            .map(|i| Enrichment::new(format!("e{i}"), vec![concept.clone()]))
            .collect();

        let mk = |cal: f64| {
            let req = DigestRequest::new(
                "Lesson.",
                vec![concept.clone()],
                many.clone(),
                Calibration::new(cal),
                "stub",
            );
            g.generate(&req).unwrap().admitted_enrichments.len()
        };

        let low = mk(0.0); // Rich — all 5
        let mid = mk(0.5); // Standard — capped at 2
        let high = mk(0.9); // Terse — 0

        assert_eq!(low, 5);
        assert_eq!(mid, 2);
        assert_eq!(high, 0);
        assert!(low >= mid && mid >= high);
    }

    /// CG-3: the reader can always request the richer form, overriding fade.
    #[test]
    fn cg3_richer_form_on_request() {
        let p = stub();
        let g = DigestGenerator::new(&p);

        let req = DigestRequest::new(
            "Lesson.",
            vec![],
            vec![],
            Calibration::new(0.95), // would fade to Terse
            "stub",
        )
        .with_richer_form();

        let d = g.generate(&req).unwrap();
        assert_eq!(d.richness, Richness::Rich);
    }

    /// CG-4: the LLM only fills surface text; structural decisions are
    /// independent of provider output. A provider error never corrupts the
    /// (already-decided) structure — it surfaces as a typed error instead.
    #[test]
    fn cg4_provider_fills_surface_text_only() {
        let p = stub();
        let g = DigestGenerator::new(&p);
        let req = DigestRequest::new(
            "Lesson.",
            vec![ConceptId::new("c")],
            vec![Enrichment::new("x", vec![ConceptId::new("c")])],
            Calibration::new(0.0),
            "stub",
        );
        let d = g.generate(&req).unwrap();
        // Surface text is exactly the stub's fixed text — proving it is
        // cosmetic and not derived from any decision.
        assert_eq!(d.surface_text, "FIXED SURFACE TEXT");
        // The decision (admitting the mapped enrichment) stands on its own.
        assert_eq!(d.admitted_enrichments.len(), 1);
    }

    /// CG-4 determinism: identical inputs yield identical structural output.
    #[test]
    fn cg4_deterministic_structure() {
        let p = stub();
        let g = DigestGenerator::new(&p);
        let concept = ConceptId::new("c");
        let build = || {
            let req = DigestRequest::new(
                "Lesson.",
                vec![concept.clone()],
                vec![
                    Enrichment::new("a", vec![concept.clone()]),
                    Enrichment::new("b", vec![ConceptId::new("nope")]),
                ],
                Calibration::new(0.4),
                "stub",
            );
            g.generate(&req).unwrap()
        };
        let d1 = build();
        let d2 = build();
        assert_eq!(d1.richness, d2.richness);
        assert_eq!(d1.admitted_enrichments, d2.admitted_enrichments);
        assert_eq!(d1.visual_count, d2.visual_count);
    }

    /// Calibration clamps out-of-range / NaN to the safe (richest) end.
    #[test]
    fn calibration_is_clamped() {
        assert_eq!(Calibration::new(2.0).score(), 1.0);
        assert_eq!(Calibration::new(-1.0).score(), 0.0);
        assert_eq!(Calibration::new(f64::NAN).score(), 0.0);
    }
}
