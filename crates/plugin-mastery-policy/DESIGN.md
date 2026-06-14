# W8 — Mastery policy (`plugin-mastery-policy`)

A typed, project-owner-governed configuration object for the Conversation
workflow layer, implementing SoftDevSpec **§2.4** (row **W8** of §2.2). It is a
pure data + validation crate: serde load, deterministic `validate()`, no I/O.

## Responsibilities

* Carry every §2.4 field in a typed schema (`mode`, `criticality_tags`,
  `assignment`, `reserved_rung_quota`, `withdrawal_cadence`, `rotation`,
  `hunt`, `ledger_governance`, `owner`).
* Enforce the constitutional-governance invariants it owns:
  * **CG-10** — `reserved_rung_quota` is a fraction in `[0.0, 1.0]`.
  * **CG-17** — rotation cadence / eligible roles / criticality overrides are
    first-class fields.
  * **CG-23** — `ledger_governance.aggregate_only_team_views` is **locked
    true**: per-person team views (a vector for performance targets) are
    inexpressible. The field has no public setter, defaults true, and its
    custom `Deserialize` rejects a `false` in the source document.
* Reuse the core actor identity: `owner: wyrtloom_core::types::ActorId`.

`assignment: redundant(R)` is **accepted but flagged** — redundant assignment
(R>1) is Phase-2 (§2.7), so `validate()` returns
`PolicyError::RedundantAssignmentPhase2`.

## Schema

```mermaid
classDiagram
    class MasteryPolicy {
        +Mode mode
        +Vec~String~ criticality_tags
        +Assignment assignment
        +f64 reserved_rung_quota  «CG-10 ∈[0,1]»
        +SpacingParams withdrawal_cadence
        +Rotation rotation
        +Hunt hunt
        +LedgerGovernance ledger_governance
        +ActorId owner  «D11»
        +from_json(json) Result
        +validate() Result
    }
    class Mode {
        <<enum>>
        Strict
        Sampled(k)
        Hybrid
    }
    class Assignment {
        <<enum>>
        Single
        Divided
        Redundant(r)  «Phase-2»
    }
    class SpacingParams {
        +u32 initial_interval_days
        +f64 expansion_factor
        +u32 max_interval_days
    }
    class Rotation {
        +u32 cadence_days
        +Vec~Role~ eligible_roles
        +Vec~CriticalityOverride~ criticality_overrides
    }
    class CriticalityOverride {
        +String tag
        +Vec~Role~ human_only_roles
    }
    class Hunt {
        +bool stake_escalation
        +u32 max_ladder_depth
    }
    class LedgerGovernance {
        +u32 retention_days
        -bool aggregate_only_team_views  «LOCKED true, CG-23»
    }
    MasteryPolicy --> Mode
    MasteryPolicy --> Assignment
    MasteryPolicy --> SpacingParams
    MasteryPolicy --> Rotation
    MasteryPolicy --> Hunt
    MasteryPolicy --> LedgerGovernance
    Rotation --> CriticalityOverride
```

## Validation decision flow

```mermaid
flowchart TD
    A[from_json] --> B[serde deserialize]
    B -->|aggregate_only=false in doc| R1[Reject: AggregateLockViolated CG-23]
    B -->|ok| C{quota finite & in 0..1?}
    C -->|no| R2[QuotaOutOfRange CG-10]
    C -->|yes| D{aggregate_only true?}
    D -->|no| R3[AggregateLockViolated CG-23]
    D -->|yes| E{owner non-empty?}
    E -->|no| R4[MissingOwner D11]
    E -->|yes| F{assignment redundant?}
    F -->|yes| R5[RedundantAssignmentPhase2 §2.7]
    F -->|no| G{counts > 0? ladder/cadence/sampled-k}
    G -->|no| R6[NonPositive]
    G -->|yes| OK[Ok]
```

The CG-23 lock is enforced at **two** boundaries: the custom `Deserialize` (so
malicious or stale JSON never produces an unlocked policy) and `validate()`
(the authoritative gate for programmatically constructed policies).

## Phase notes

* `redundant(R)` assignment — Phase-2; accepted by the schema, flagged by
  `validate()`.
* Team transactive-memory views — Phase-2; the locked aggregate-only field is
  the forward-compatible guard so that, when introduced, only aggregate views
  are ever expressible (CG-23).
