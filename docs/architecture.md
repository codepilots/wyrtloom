# Wyrtloom Architecture

> Developer-facing architecture reference for the Wyrtloom ecosystem (v0.1, "The Seed").
> For exact trait signatures, supporting types, error enums, and contract ids/versions,
> see the companion [`contracts.md`](./contracts.md).

Wyrtloom is built as a **minimal Rust core kernel** plus **everything else as swappable
plugins behind versioned contracts, each in its own repo**. The core is a trellis, not a
cage: it standardises the connectors (the contracts) and the root of trust, and nothing
else. The opinion that drives every boundary decision is captured in the three design
lenses (§3).

---

## 1. The core/plugin model

### 1.1 What lives in the core kernel

The core (`crates/core`, crate `wyrtloom-core`) contains only the things that *cannot* be
a plugin, plus the *interface contracts* that the rest of the ecosystem must agree on. As
of v0.1 the core kernel is:

| Core piece | Module | Why it is core |
|---|---|---|
| **Security & Trust module** | `security.rs` | It is the thing that verifies plugins; it cannot itself be one (Bootstrap lens). |
| **Plugin loader / manifest / capability model** | `plugin.rs` | The bootstrap mechanism that loads everything else. |
| **Sandbox interface** | `sandbox.rs` (`SandboxRuntime` trait) | The *contract*; the wasmtime runtime is a core-controlled plugin loaded before any untrusted code. |
| **Message-bus primitive** | `bus.rs` (`BootstrapBus` + `MessageBus` trait) | A minimal synchronous bus must exist before a bus *plugin* can announce "loaded". |
| **Kanban state-machine contract** | `kanban.rs` (`KanbanBoard` trait + legal-transition table) | The entire ecosystem depends on the states/transitions/locking being identical across installations. |
| **Canonical encoder** | `canon.rs` (`CanonicalEncoder`) | Several components must produce byte-identical signing input across process/crate boundaries. |
| **Shared types & cost-model schema** | `types.rs`, `provider.rs` (`Usage`, `Money`, `ModelDescriptor`) | So all callers and the future ML tuner read usage uniformly regardless of provider. |
| **Versioned contract surface** | every other core module | The *interfaces* (`LlmProvider`, `PersistenceProvider`, `UserDirectory`, `ClientAuthScheme`, `CallLogger`, `HumanEscalation`, …) live in core; the *implementations* are plugins. |

The module list is the crate root `crates/core/src/lib.rs`:

```rust
pub mod agent;        pub mod bootstrap;   pub mod bus;
pub mod canon;        pub mod client_auth; pub mod escalation;
pub mod kanban;       pub mod logger;      pub mod persistence;
pub mod plugin;       pub mod profile;     pub mod provider;
pub mod sandbox;      pub mod security;    pub mod storage;
pub mod types;        pub mod users;       pub mod util;
```

### 1.2 What is a plugin

A contract is a Rust trait (`Send + Sync`) plus its supporting types, error enum, and a
`wyrtloom.<name>` contract id with a SemVer. An *implementation* is a plugin crate that
implements the trait. Plugins are loaded behind a manifest (`PluginManifest`) declaring a
name, a SemVer, a class (`Safe`/`Unsafe`), the capabilities they need, and the contracts
they implement with their required versions.

Consumers (the pipeline, a dashboard API server, …) depend on the **trait object**
(`Arc<dyn KanbanBoard>`, `Arc<dyn LlmProvider>`, …), never on a concrete plugin. That is
what makes implementations swappable.

### 1.3 The corollary: one repo per swappable implementation

> *Any reusable, swappable capability — including persistence itself — SHALL be expressed
> as a versioned core contract whose implementation ships as a separate plugin in its own
> repository; consumers depend on the contract, never on a concrete plugin.* (Specification §7.2)

Persistence is itself a contract (`wyrtloom.persistence`): the core has no built-in
database. User management (`wyrtloom.users`) and client authentication
(`wyrtloom.client_auth`) follow the same rule, layered *on top of* the persistence
contract rather than embedding storage. This keeps the backing store swappable (SQLite
now, anything later) without touching the consumers.

---

## 2. The Kanban as source of truth and the task pipeline

### 2.1 Kanban is the single source of truth

Task state lives on a Kanban board, not in chatter between agents. The board records what
needs doing, who is doing it, and what is stuck. The contract (`KanbanBoard` in
`kanban.rs`) fixes:

- **States:** `Backlog → Todo → Ready → Running → Blocked → Done → Archived`.
- **Legal transitions:** enforced by `is_legal_transition(from, to)` — an illegal
  transition is rejected with `KanbanError::IllegalTransition`.
- **Locking:** `claim` gives a task to exactly one worker; a second claim fails atomically
  with `KanbanError::AlreadyClaimed`.
- **Dependencies:** `Todo → Ready` is gated on all `depends_on` tasks being `Done`
  (`KanbanError::DependenciesNotDone`).
- **Blocking:** `block` requires a `BlockReason` with a target (`BlockedBy::Human` or
  `BlockedBy::Dependency`).
- **Audit:** every transition appends a `StateChange { from, to, actor, at, reason }`.

Storage is a plugin (`plugin-kanban-sqlite`); the contract is core.

### 2.2 The `parse → plan → execute → verify` pipeline

The runner (`src/pipeline.rs`, `Pipeline::run`) does deterministic work first and calls the
model only at genuine decision points ("pre-digestion before LLM"):

1. **parse** — create the task on the board and drive it `backlog → todo → ready → claim →
   running`, all through the `KanbanBoard` contract.
2. **plan** — build a profile-scoped prompt (`system` + `user` `Message`s) and a
   `GenerationRequest` carrying the output-token budget.
3. **execute** — call `LlmProvider::generate`; record a `CallLog` for the call (completed,
   failed, or partial — never silently dropped).
4. **verify** — parse the model's **structured JSON** output (`{"status":"done"|"blocked",…}`).
   Unparseable output is treated as blocked, not assumed successful (hardening 008). On
   success the task transitions to `Done`; on block it escalates to a human via
   `HumanEscalation`.

The pipeline composes only trait objects (`Arc<dyn KanbanBoard>`, `Arc<dyn LlmProvider>`,
`Arc<dyn CallLogger>`, `Arc<dyn HumanEscalation>`), so each capability is swappable.

---

## 3. The three design lenses

Every candidate for the core is tested against three questions. These lenses are part of
the specification and must be applied to any future proposal to expand the core.

1. **The Bootstrap lens** — *Can this exist before the plugin loader runs?* If something
   must already be running for a component to load, the component (or its minimal seed)
   belongs in core. The message bus is the canonical case: you cannot load a bus *plugin*
   without something already able to carry the "loaded" signal, so `BootstrapBus` is core.

2. **The Ecosystem lens** — *If this interface varied between installations, would plugins
   stop being portable?* If yes, the **interface contract** must live in core and be
   versioned carefully — even though the **implementation** is a swappable plugin. (USB
   standardises the connector, not the device; POSIX standardises the filesystem
   interface, not the filesystem.) The `canon::CanonicalEncoder` exists for exactly this
   reason: a signature must verify byte-for-byte across the client signer, the
   `ClientAuthScheme` plugin, and the API server, so the shared encoding is a core
   primitive rather than something each plugin reinvents.

3. **The Comprehension lens** (added by SoftDevSpec §1.6, D5) — *Does this build or erode
   the human's theory of the system?* Comprehension debt is treated as a first-class
   failure mode: a feature that ships understanding-as-a-by-product is preferred over one
   that grows a system no living person holds a theory of.

**Corollary (Ecosystem lens):** *reusable capability ⇒ core contract + own-repo plugin;
persistence is itself a contract.* See §1.3.

---

## 4. The bootstrap sequence

The core initialises in a strict, fixed order (Specification §8, implemented in
`bootstrap.rs` `Bootstrapper::run`). **Security comes first and verifies each subsequent
stage; untrusted code never loads until the gate is standing; SAFE/sandboxed plugins load
last, inside the sandbox.**

```
1.  Security & Trust Module initialises   (root of trust; self_check first)
2.  Plugin Loader initialises             (CoreContractVersions established)
3.  Sandbox Runtime loads                 (core-controlled; verified)
4.  Message Bus Primitive starts          (BootstrapBus)
5.  Kanban State Machine starts
6.  LLM Provider Interface registers
7.  Call Logger + Human Escalation interfaces register
8.  Agent Message Contracts register
9.  Trusted (Unsafe) plugins load         (in capability order)
10. SAFE / sandboxed plugins load         (inside the sandbox)
```

A failure at any stage halts bootstrap with a logged, human-readable `BootstrapError`. The
system never proceeds in a partially-secured state.

What `Bootstrapper::run` actually does, in order:

1. `SecurityModule::new()` then `self_check()` — refuses to proceed if its own integrity
   check fails (e.g. an all-zero RNG-failed key). This is the *SAFE-before-unsafe* anchor:
   nothing else runs until the root of trust verifies itself.
2. Build `CoreContractVersions::v0_1()` — the floor versions the loader checks against.
3. Construct the `BootstrapBus`.
4. For every registered manifest:
   - `PluginManifest::validate_name` — name must match `[a-z0-9_-]{1,64}` (rejects
     `../evil`, escape sequences, uppercase, over-length).
   - contract-version check — each declared `(contract_id, required)` must be
     `is_compatible(...)` with the core floor, else
     `LoadError::IncompatibleContractVersion`.
   - SAFE-with-capabilities check — a `Safe` plugin declaring any capability is rejected
     (`LoadError::SafePluginRequestedCapability`).
   - `SecurityModule::verify(manifest)` — capability allow-listing against the policy;
     rejection is honoured.
5. Publish a `wyrtloom.boot` "complete" event on the bus.

---

## 5. The repo / dependency map

Each swappable capability is a core *contract* with its implementation in its **own
repository**. The in-tree `crates/` mirror the default v0.1 implementations.

| Contract id | Core trait (`crates/core/src/…`) | Default implementation plugin(s) |
|---|---|---|
| `wyrtloom.kanban` | `kanban::KanbanBoard` | `plugin-kanban-sqlite` |
| `wyrtloom.provider` | `provider::LlmProvider` | `plugin-provider-ollama` (default); `wyrtloom-provider-nous` |
| `wyrtloom.persistence` | `persistence::PersistenceProvider` | `wyrtloom-store-sqlite` |
| `wyrtloom.users` | `users::UserDirectory` | `wyrtloom-users` (argon2 over persistence) |
| `wyrtloom.client_auth` | `client_auth::ClientAuthScheme` | `wyrtloom-clientauth-tofu` (TOFU + asymmetric keys) |
| `wyrtloom.logger` | `logger::CallLogger` | `plugin-logger-sqlite` |
| `wyrtloom.sandbox` | `sandbox::SandboxRuntime` | `plugin-sandbox-wasmtime` |
| `wyrtloom.bus` | `bus::MessageBus` | `plugin-bus-tokio` (in-process Tokio channels) |
| `wyrtloom.escalation` | `escalation::HumanEscalation` | `plugin-escalation-cli` |
| *(core, not a plugin)* | `security::SecurityModule` / `SecurityPolicy` | — |
| *(core, not a plugin)* | `plugin::PluginManifest` / `PluginRegistry` / `Capability` | — |
| *(core, not a plugin)* | `canon::CanonicalEncoder` | — |

### 5.1 Path-dep + git-fallback convention

The workspace `Cargo.toml` wires the in-tree default plugins as **path dependencies** so
the monorepo builds standalone:

```toml
[workspace.dependencies]
wyrtloom-core = { path = "crates/core" }
# …
[dependencies]
plugin-kanban-sqlite   = { path = "crates/plugin-kanban-sqlite" }
plugin-provider-ollama = { path = "crates/plugin-provider-ollama" }
# …
```

Because every implementation also ships in its own repo, the convention is **path-dep with
git-fallback**: an integrator depends on the contract crate (`wyrtloom-core`) plus the
plugin, taking the plugin either by `path = "…"` (vendored / in-tree) or by `git = "…"`
(its own repo). The consumer code is identical — it only ever names the contract trait — so
swapping the source of an implementation, or the implementation itself, requires no code
change.

---

## 6. Contract versioning (SemVer)

All contracts use semantic versioning (`types::SemVer`). Compatibility is:

```rust
pub fn is_compatible_with(&self, required: &SemVer) -> bool {
    self.major == required.major && self.minor >= required.minor
}
```

i.e. **same major, and the provided minor must be ≥ the required minor.** Backward
compatibility is sacred: optional parameters may be added, required ones may never be
removed, and no breaking change ships without a major bump.

### 6.1 Floor-vs-declared: the kanban `0.1.0` floor / `0.2.0` list example

The loader keeps a **floor** version per contract in `CoreContractVersions::v0_1()`. A
plugin **declares** the version it provides. The two are reconciled by `is_compatible`.

The `wyrtloom.kanban` contract is the worked example:

- The core floor stays **`0.1.0`**. `KanbanBoard::list(&TaskQuery)` was added as an
  *additive, defaulted* method, so any `0.1.0` plugin still satisfies the trait (the
  default returns `KanbanError::Storage("enumeration not supported…")` rather than
  silently empty).
- A list-capable storage plugin (e.g. `plugin-kanban-sqlite`) **declares `0.2.0`** and
  overrides `list`. `0.2.0` is compatible with the `0.1.0` floor (same major, higher
  minor), so it loads.

In `src/main.rs` the kanban plugin registers exactly this:

```rust
PluginManifest {
    name: "plugin-kanban-sqlite".into(),
    version: SemVer::new(0, 2, 0),
    // …
    // Declares 0.2.0 — provides the additive `KanbanBoard::list` (read-through-trait).
    implements: vec![("wyrtloom.kanban".into(), SemVer::new(0, 2, 0))],
}
```

A plugin declaring a *different major* (e.g. `1.0.0`) against a `0.x` floor is rejected
with `LoadError::IncompatibleContractVersion`; a plugin declaring a *lower minor than the
floor* is likewise incompatible.

---

## 7. Where to go next

- **[`contracts.md`](./contracts.md)** — every core contract with its exact trait
  signatures, supporting types, error enum, contract id + version, the security invariants
  implementors must uphold, and the plugin(s) that implement it.
- `Specification` §7–§10 and Appendix A — the normative specification and full interface
  appendix.
- `SoftDevSpec.md` — the Comprehension-First development workflow and the third (Comprehension) lens.
