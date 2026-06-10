# Wyrtloom Specification Addendum: The Conversation

## Comprehension-First Development Workflow — v0.1 draft

*2026-06-10 · Addendum to the Wyrtloom two-part specification · Status: draft for review*
*Decision lineage: D2–D5, D8–D19 (audit logs 002–003). Evidence lineage: F1–F33 (quotes + URLs in logs).*

---

# Part 1 — Vision

## 1.1 Premise

AI agents now produce software faster than humans build understanding of it. The gap has a name — comprehension debt — and a failure mode: teams that ship systems no living person holds a theory of, then cannot maintain, secure, or extend them when the agent's context runs out or the world shifts (F1, F4, F6). The verified experimental record shows unrestricted AI assistance producing "fragile experts" who fail when the AI is removed, and shows scaffolded interaction roughly halving that failure rate (F5). Storey's injunction is the premise of this addendum: *treat understanding as a deliverable* (F4).

Wyrtloom's answer is not to slow the agent down with examinations. It is to change what development *is*.

## 1.2 Development as conversation

In this workflow, software development is a structured conversation between complementary minds, each bringing what the other lacks:

**The human brings the world.** Domain knowledge, user context, the threat landscape, taste, and — above all — abstraction and *novel explanation*: the human capacity to see what a thing is an instance of, to explain it a way it has never been explained, and to challenge the system with insight it could not have generated (V3). The cognitive science is clear that generating one's own explanation is where understanding forms (self-explanation effect, F22), and that human theories of a system — not its code — are the asset that keeps it alive (Naur, F6).

**The system brings the artifacts.** Total recall of every line, contract, test, decision, and historical change; tireless synthesis; multimodal teaching; and the patience to pay capture costs humans have always refused (the rationale-capture literature's graveyard is a graveyard of human overhead, F11). The system knows the code the way no human ever will. The human understands the world the way no system yet can.

**Understanding emerges in the exchange.** Neither party narrates at the other. The system teaches what it knows; the human challenges with what it cannot know; the residue of the exchange — explanations, abstractions, decisions, tests — sediments into durable artifacts. Comprehension evidence is a *by-product of the conversation*, not the output of an exam (D17/D18).

## 1.3 The four practices

The conversation has four characteristic moves, each grounded in evidence and each yielding comprehension signal implicitly.

**The Hunt.** The human designs tests to break the agent's work — the thrill of the chase. A well-aimed breaking test is impossible without a theory of the system, so each hunt yields a triple harvest: a genuine defect found, implicit comprehension evidence (credited deterministically from what the test exercises), and a new test crystallised into the regression suite. Adversarial play is among the best-evidenced motivators in technical education (F33); the human is the hunter, never the specimen — which is what dissolves the surveillance sting the adversarial review identified (CH5). When the agent's work survives, it raises the stakes: *this version survives your last test; break it again.*

**Build & Own.** Humans build and own *important* elements — not leftovers — on a reserved-rung quota. Labor produces valuation and psychological ownership (IKEA effect, F32), but only when the build *completes*: reserved builds are therefore graduated to the human's level, with scaffolding available on request. The abstractions born of building are captured as Insight Artifacts (§1.4). This is the Groundwork Principle in action (D13): tasks kept for humans must be **legitimate** (output genuinely used), **graduated** (within reach), and **generative** (demand production, not recognition). Anything failing the three Gs is busywork and goes to the agent.

**Scheduled Withdrawal.** On a spaced cadence, the AI deliberately absents itself: solo flights in which the human operates, modifies, or extends the system unassisted. The experimental literature used AI-blackout as a *measurement* of fragile expertise (F5); Wyrtloom converts it into a *practice* — instructional fading at the system level, and the only direct cure the automation literature admits for skill decay under automation (Bainbridge, F9). A platform that periodically steps out of the room is making a commitment no dashboard can fake.

**Role Rotation.** Human and AI rotate among specifier, designer, developer, and tester. Each role exercises a different mental model of the system (program model vs situation model, F7), and rotation is the deterministic schedule that prevents any single model from atrophying. The strongest adversarial-education designs already swap attack and defense roles for exactly this reason (F33). Handoffs ride the existing typed agent-message contracts — rotation is policy, not new core.

## 1.4 Where the conversation sediments

Four durable artifact streams capture the exchange, all written by the agent as a by-product (the agent pays the capture cost; D3):

1. **Code and tests** — including every hunt-test the human authored.
2. **Rationale ledger** — ADR-shaped records of decisions: context, decision, consequences (F11).
3. **Insight Artifacts** — a first-class home for human abstraction and novel explanation, beside code, tests, and documentation (D14.2). This is where the human's distinctive contribution stops being ephemeral.
4. **Coverage and calibration ledgers** — the system's map of which concepts have living human theories, and how well each person's confidence tracks their accuracy (D8, governed per §1.6).

## 1.5 Supporting machinery: gates that teach

Stage transitions on the Kanban board are gates, and gates are *lessons first*. A gate opens with a digest — instruction always precedes any challenge (D15.3; the direct-instruction and productive-failure camps both demand this ordering and both agree prior knowledge is the moderator, CH1). Digests obey:

- **Dual coding with coherence.** Words plus load-bearing visuals; world-knowledge enrichment (fresh threat intel, ecosystem news) is admitted *only* when it maps to a concept actually in play — interest must live in relevance, never alongside it (seductive-details guard, D15.1).
- **Artifact fading.** Rich multimodal voyages where the reader's calibration is low; terse single-representation digests where it is high; the human can always request the richer form (expertise-reversal guard, D15.2).
- **Conversational register**, which the multimedia evidence favors (F22), tempered by the logged caution that it can raise pressure in some contexts.

Where the Hunt and the other practices leave coverage-map territory dark, the **Socratic probe ladder** (D8–D9) remains as quiet fallback: short prediction probes graded by execution — never by an LLM judge (F-HULA follow-up showed judge instability) — with guided scaffolds that teach when a prediction misses, and difficulty that staircases. Passed probes crystallise into the regression suite. A human prediction that is *wrong but reasonable* is treated as a defect signal about the system's design, not a failing of the human.

## 1.6 Commitments

The adversarial review (log_002, CH1–CH8) forced these into the vision as non-negotiables:

- **Developmental, never evaluative.** Calibration ledgers are private by default to the individual; team views are aggregate-only (per-concept redundancy, bus-factor — never per-person league tables); no appraisal use; no performance targets over probe or hunt statistics; retention limits; export and delete. Employment or education deployments require local legal and ethics review (D15.4). The monitoring meta-analyses are unambiguous that targets and evaluative purpose are what turn measurement into harm (F30).
- **No bolted-on gamification.** The chase, the build, and the solo flight are intrinsically rewarding; extrinsic points would corrode them (undermining effect, F26).
- **Blame stays with the system.** Gate passage never transfers liability for agent defects to the gate-passer; override stamps are remediation signals, not culpability markers; incident reviews examine the system (moral-crumple-zone guard, D15.5).
- **Standing disconfirmation.** Every future review includes a counter-evidence pass; major decisions record what would change our mind (D15.6).
- **The Comprehension Lens** joins Bootstrap and Ecosystem as Wyrtloom's third design lens: *does this build or erode the human's theory of the system?* (D5).

## 1.7 A week in the conversation

Monday: the agent proposes a contract change; the gate opens with a two-panel digest (you're well-calibrated here, so it's terse) and you approve after one prediction. Tuesday: interest routing hands you the problem the agent failed three times — a contract-boundary ambiguity that needs a judgment call about how *your users* actually behave; your resolution and the explanation you give become an Insight Artifact. Wednesday: you hunt — the agent's new parser survived your last two tests, and you've been thinking about a malformed-unicode angle all morning. Your third test breaks it. The defect is fixed; your test joins the suite; three coverage-map concepts quietly light up. Thursday: a reserved build — the rate-limiter is yours, important and finishable, agent on mute unless you call. Friday morning: solo flight, scheduled weeks ago; the agent is absent and you ship a small change alone. It feels like flying because it is.

At no point were you examined. The system's confidence that you understand it was earned the same way a colleague's would be: by working beside you.

---

# Part 2 — Technical specification

## 2.1 Architectural position

The entire workflow is a **profile + plugin-layer construct. Zero new core components.** It passes the "why does it have to be in the core?" test by failing it: every mechanism below composes from the locked twelve (Kanban state machine contract, message bus, contract manager, human escalation interface, agent message type contracts, call logger, LLM provider interface, security module, behavioural baseline interface). Stages are Kanban columns; gates are guarded transitions requiring an escalation-interface approval token; per-stage task profiles bound cost via the call logger (D2).

Determinism rule (R24 inheritance): all gating, grading, crediting, scheduling, and routing logic is coded and deterministic. LLM calls appear only inside template-filling for digests, scaffolds, and probe surface text — never in pass/fail decisions.

## 2.2 Component inventory (plugin layer)

| # | Component | Function |
|---|-----------|----------|
| W1 | Workflow profile | Declares stages, gate placement, task profiles per stage |
| W2 | Gate engine | Guarded Kanban transitions; emits/validates approval tokens |
| W3 | Digest generator | Instruction-first artifacts; coherence + fading rules |
| W4 | Hunt harness | Sandboxed execution of human-authored breaking tests against agent output; deterministic coverage crediting; stake escalation |
| W5 | Probe ladder | Fallback Socratic probes; execution-graded; staircase logic |
| W6 | Coverage map | Concept inventory per component; links artifacts ↔ concepts ↔ humans |
| W7 | Calibration ledger | Per-person confidence-vs-outcome record (BKT-style update rule; Phase-4 tuner candidate); governance enforced at storage layer |
| W8 | Mastery policy | Project-owner-governed configuration object (§2.4) |
| W9 | Insight Artifact type | Typed first-class artifact; schema §2.5 |
| W10 | Interest router | Deterministic signals → human-routed problems at calibrated challenge |
| W11 | Withdrawal scheduler | Spaced solo-flight sessions; agent-absence enforcement |
| W12 | Rotation scheduler | Role assignment over typed handoff contracts |
| W13 | Rationale ledger | ADR-shaped decision records, agent-authored |

## 2.3 Requirements (CG numbering; v-next scope)

**Conversation core**
- CG-1. Every gate SHALL present a digest before any challenge (instruction-first).
- CG-2. Digest enrichment SHALL be admitted only when mapped to an in-play coverage-map concept (coherence constraint).
- CG-3. Digest richness SHALL fade with the reader's calibration score; richer form available on request.
- CG-4. All pass/fail, crediting, and scheduling decisions SHALL be deterministic; LLM output SHALL NOT grade anything.

**The Hunt**
- CG-5. The hunt harness SHALL execute human-authored tests against agent output in the standard sandbox.
- CG-6. Coverage credit SHALL be computed deterministically from the concepts a hunt-test exercises (instrumented execution trace ∩ coverage map), regardless of whether the test passes or breaks the target.
- CG-7. A breaking test SHALL (i) open a defect, (ii) credit coverage, (iii) crystallise into the regression suite on fix.
- CG-8. On surviving a hunt, the agent SHALL offer escalated-stakes variants ("break it again") pitched by the calibration ledger.
- CG-9. No points, scores, leaderboards, or rewards SHALL be attached to hunt statistics.

**Build & Own**
- CG-10. The mastery policy SHALL define a reserved-rung quota: a minimum fraction of graduated, criticality-tagged work assigned to humans.
- CG-11. Reserved builds SHALL be selected as important (criticality-tagged) AND completable (within the builder's calibrated ZPD); scaffold-on-request SHALL be available.
- CG-12. Agent absorption of 100% of graduated work SHALL be a policy violation surfaced to the project owner.

**Scheduled Withdrawal**
- CG-13. The withdrawal scheduler SHALL plan spaced solo-flight sessions per person from the calibration ledger (spacing algorithm: expanding interval).
- CG-14. During a solo flight the agent SHALL be unavailable for the flagged task scope except via explicit human abort (logged, never penalised).
- CG-15. Solo-flight outcomes SHALL update the calibration ledger as practice events, not assessments.

**Role Rotation**
- CG-16. Rotation SHALL assign specifier/designer/developer/tester roles to human and agent over the existing typed handoff contracts.
- CG-17. Rotation cadence and eligible roles SHALL be mastery-policy fields; rotation SHALL respect criticality tags (e.g., human-only specifier for safety-critical items if so configured).

**Fallback probes**
- CG-18. Probe ladder behaviour as specified in D8–D9: execution-graded prediction probes; guided worked-example scaffolds; scaffolded items do not count toward mastery; staircase difficulty; fading with calibration.
- CG-19. Probes SHALL trigger only for coverage-map areas dark after hunt/build/solo credit, per mastery-policy mode (strict / sampled-K / hybrid).
- CG-20. A human prediction that is wrong while the system behaviour is anomalous vs the behavioural baseline SHALL raise a design-defect signal.

**Ledgers and governance**
- CG-21. Calibration ledgers SHALL be private-by-default to the individual; team views SHALL expose only per-concept aggregate redundancy.
- CG-22. The storage layer SHALL enforce: no appraisal export, no per-person ranking queries, retention limits, user export and delete.
- CG-23. Ledger purpose SHALL be declared as developmental in the policy object; attaching performance targets to ledger data SHALL be unsupported by API design.
- CG-24. Gate approval tokens SHALL carry a blame-allocation notice: passage ≠ liability transfer; incident tooling SHALL link defects to system-level review templates.

**Interest routing & insight**
- CG-25. Interest signals SHALL be deterministic: agent retry/failure clusters, novelty vs behavioural baseline, cross-module anomalies, contract-boundary ambiguities.
- CG-26. Routed problems SHALL be pitched into the recipient's flow channel using the calibration ledger; humans MAY decline without record.
- CG-27. Insight Artifacts SHALL be typed, linkable from coverage-map concepts, rationale entries, and code; authorship is human; capture labor is agent's.

**Audit**
- CG-28. All gate, hunt, probe, withdrawal, and rotation events SHALL be logged via the call logger for audit, under CG-21/22 access rules.

## 2.4 Mastery policy schema (sketch)

```
mastery_policy {
  mode: strict | sampled(K) | hybrid
  criticality_tags: [tag]            # agent proposes, human confirms
  assignment: single | divided | redundant(R)   # redundant: Phase 2
  reserved_rung_quota: fraction      # CG-10
  withdrawal_cadence: spacing_params # CG-13
  rotation: { cadence, eligible_roles, criticality_overrides }  # CG-17
  hunt: { stake_escalation: bool, max_ladder_depth }
  ledger_governance: { retention_days, aggregate_only_team_views: true (locked) }
  owner: project_owner_id            # D11; changes pass a lightweight gate
}
```

## 2.5 Insight Artifact schema (sketch)

```
insight_artifact {
  id, author (human), created_at
  abstraction: text                  # the novel explanation itself
  born_of: hunt_id | build_id | route_id | gate_id | solo_flight_id
  concepts: [coverage_map_concept]
  links: [code_ref | rationale_ref | test_ref | contract_ref]
  status: living | superseded(by)
}
```

## 2.6 Evaluation plan (open questions carried honestly)

The adversarial review left two verdicts OPEN; this spec is not evidence-based until a pre-registered pilot addresses them:

1. **Probe/hunt validity (CH4).** Do coverage-credit scores correlate with independent comprehension measures? Criterion task: AI-blackout maintenance performance (the Explanation Gate paradigm's own measure, F5). Pre-register the correlation threshold.
2. **Economics (CH7).** Instrument gate time cost, defect and rework rates, suite growth from hunt-tests, and governance-acceptability survey results. Pre-register abandonment criteria: if gate overhead exceeds the configured budget for N consecutive sprints without defect-rate improvement, the profile self-reports failure to the project owner.
3. **Equity watch (Part C gaps).** Pilot instruments must disaggregate decline-rates and hunt participation to detect learned-avoidance patterns; probe and digest formats receive accessibility review.

## 2.7 Phase placement (car park alignment)

| Construct | Phase |
|-----------|-------|
| Gate engine, digests (coherence + fading), probe fallback, rationale ledger | v-next (this addendum's core) |
| Hunt harness, Build & Own quotas, withdrawal scheduler, rotation scheduler, Insight Artifacts, interest router | v-next, behind profile flags |
| Connection Weaving (convening interrelated developers), redundant assignment R>1, team transactive-memory views | Phase 2 |
| Threat-intel-fed teaching digests (immune-system integration) | Phase 3 |
| BKT-style tuner for calibration updates | Phase 4 |
| User-Gardener Continuum (EUD + developer validation gates) | Phase 5+ |

## 2.8 Traceability

CG-1..4 ← D15.1–3, F22, CH1–CH3 · CG-5..9 ← D17.1, F33, F26, CH5 · CG-10..12 ← D13, D17.2, F32, F23–F25 · CG-13..15 ← D17.3, F5, F9 · CG-16..17 ← D17.4, F7, F33 · CG-18..20 ← D8–D9, F15 · CG-21..24 ← D15.4–5, F30, F31, CH5–CH6 · CG-25..27 ← D14, F26–F27, V3 · CG-28 ← D2. Every F resolves to a logged quote with full URL in audit logs 001–002.

---

*End of addendum v0.1 draft. Standing disconfirmation note (D15.6): the next review of this document must begin with a counter-evidence pass; the pre-registered pilot (§2.6) is what would change our mind.* 🌿
