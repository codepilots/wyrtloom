//! Comprehension-first development workflow — the Wyrtloom specification
//! addendum "The Conversation" (SoftDevSpec.md), implemented as a
//! profile + plugin-layer construct. Zero new core components: every
//! mechanism here composes the locked core contracts (kanban state machine,
//! message bus, escalation interface, call logger, sandbox runtime, agent
//! message types).
//!
//! Determinism rule (R24 inheritance / CG-4): all gating, grading,
//! crediting, scheduling, and routing logic in this crate is coded and
//! deterministic. LLM calls may only ever fill the surface text of digests,
//! scaffolds, and probe prompts — never pass/fail decisions. v0.1 uses
//! deterministic templates throughout.
//!
//! Component inventory (SoftDevSpec.md §2.2) → module map:
//!   W1  Workflow profile      → workflow.rs
//!   W2  Gate engine           → gate.rs
//!   W3  Digest generator      → digest.rs
//!   W4  Hunt harness          → hunt.rs
//!   W5  Probe ladder          → probe.rs
//!   W6  Coverage map          → coverage.rs
//!   W7  Calibration ledger    → calibration.rs
//!   W8  Mastery policy        → policy.rs
//!   W9  Insight Artifact type → insight.rs
//!   W10 Interest router       → interest.rs
//!   W11 Withdrawal scheduler  → withdrawal.rs
//!   W12 Rotation scheduler    → rotation.rs
//!   W13 Rationale ledger      → rationale.rs
//!
//! Requirement traceability (SoftDevSpec.md §2.3):
//!   CG-1..4   gate.rs / digest.rs
//!   CG-5..9   hunt.rs
//!   CG-10..12 build_own.rs
//!   CG-13..15 withdrawal.rs
//!   CG-16..17 rotation.rs
//!   CG-18..20 probe.rs
//!   CG-21..24 calibration.rs / coverage.rs / policy.rs / gate.rs
//!   CG-25..27 interest.rs / insight.rs
//!   CG-28     audit.rs

pub mod audit;
pub mod build_own;
pub mod calibration;
pub mod coverage;
pub mod digest;
pub mod gate;
pub mod hunt;
pub mod insight;
pub mod interest;
pub mod policy;
pub mod probe;
pub mod rationale;
pub mod rotation;
pub mod withdrawal;
pub mod workflow;
