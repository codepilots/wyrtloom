# 🌿 Wyrtloom

> **wyrt** *(Old English)* — plant, herb, root · **loom** — a tool; to weave.
> *A tool woven from roots, that emerges into action.*

Wyrtloom is a minimal-core, plugin-everything platform for AI agent
workflows, built on one guiding belief: **the language model is the most
expensive consultant in the building, so you only call it when no cheaper
mechanism will do.** Deterministic, coded machinery does everything it can
before a token is spent — and security initialises first, before anything
else breathes.

## The two specifications

| Document | What it covers |
|----------|----------------|
| [`Specification`](Specification) | The main two-part spec: vision, the locked core interface contracts, the v0.1 build target, and the phased roadmap |
| [`SoftDevSpec.md`](SoftDevSpec.md) | The addendum, "The Conversation": a comprehension-first development workflow that treats human understanding as a deliverable |

## Workspace layout

| Crate | Role |
|-------|------|
| `crates/core` | The kernel: kanban state machine, message bus, escalation, call logger, plugin loader + security module, provider and sandbox contracts |
| `crates/plugin-kanban-sqlite` | SQLite task board |
| `crates/plugin-logger-sqlite` | SQLite call logger (every LLM call, tokens + cost) |
| `crates/plugin-provider-ollama` | Local Ollama LLM provider |
| `crates/plugin-sandbox-wasmtime` | WASM sandbox with memory/time limits and host isolation |
| `crates/plugin-escalation-cli` | Human escalation at the terminal |
| `crates/plugin-bus-tokio` | In-process message bus |
| `crates/plugin-workflow-conversation` | The comprehension-first workflow (gates, digests, hunts, probes, coverage and calibration ledgers, rotation, withdrawal, mastery policy) |
| `crates/plugin-workflow-sqlite` | SQLite persistence for workflow state, with governance enforced at the storage layer |
| `src/` | The `wyrtloom` binary: bootstrap sequence, gated task pipeline, demos |

The core is the smallest thing that can bootstrap the system; everything
else lives behind a stable, versioned interface contract. Interfaces are
sacred; implementations are free.

## Build, test, run

```sh
cargo build
cargo test --workspace
cargo run            # bootstrap + sandbox isolation + pipeline + workflow demos
```

The pipeline demo calls a local [Ollama](https://ollama.com) server at its
default address; without one the task blocks gracefully and the demo
continues. Set `WYRTLOOM_INTERACTIVE=1` to answer escalations and gates at
the terminal instead of using scripted responses.

## Status

v0.1 ("The Seed") plus the comprehension-first workflow addendum:

- ✅ Core contracts, bootstrap sequence, security module (audited, 22 findings fixed)
- ✅ Six v0.1 plugins, task pipeline with structured LLM output
- ✅ Workflow addendum: W1–W13 components, requirements CG-1..28 under named tests
- ✅ Gated pipeline integration and SQLite workflow persistence
- ✅ Behavioural baseline + §2.6 pilot instrumentation (gate time cost, abandonment self-report, equity watch)
- ⏳ Pre-registered pilot (§2.6) — the addendum is not evidence-based until it runs
- ⏳ Phase 2+: Connection Weaving, redundant assignment, team transactive-memory views, threat-intel digests, BKT calibration tuner

## Licence

Apache-2.0
