# Wyrtloom Contract Reference (v0.1)

> Reference for **every core contract**: its real trait signature, supporting types, error
> enum, the `wyrtloom.<name>` contract id + version, the invariants implementors MUST
> uphold, and the plugin(s) that implement it.
>
> Signatures are quoted verbatim from `crates/core/src/*.rs`. For the architectural model,
> the three lenses, the bootstrap sequence, the repo map, and SemVer floor-vs-declared
> rules, see [`architecture.md`](./architecture.md).

## Shared types (`types.rs`)

```rust
pub type TaskId    = Uuid;
pub type ActorId   = String;
pub type ModelId   = String;
pub type ProfileId = String;
pub type ContractId = String;
pub type Topic     = String;
pub type Bytes     = Vec<u8>;

pub struct Timestamp(pub DateTime<Utc>);            // Timestamp::now()

pub struct SemVer { pub major: u32, pub minor: u32, pub patch: u32 }
impl SemVer {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self;
    // same major AND provided minor >= required minor
    pub fn is_compatible_with(&self, required: &SemVer) -> bool;
}

/// Money stored as integer microdollars to avoid floating-point drift.
pub struct Money { pub amount_microdollars: i64, pub currency: String }
impl Money {
    pub fn usd(dollars: f64) -> Self;   // rounds to nearest microdollar (finding 017)
    pub fn as_dollars(&self) -> f64;
    pub fn zero() -> Self;
}
```

The contract ids and their v0.1 floor versions come from
`plugin::CoreContractVersions::v0_1()`:

| Contract id | Floor version |
|---|---|
| `wyrtloom.kanban` | `0.1.0` |
| `wyrtloom.provider` | `0.1.0` |
| `wyrtloom.sandbox` | `0.1.0` |
| `wyrtloom.logger` | `0.1.0` |
| `wyrtloom.escalation` | `0.1.0` |
| `wyrtloom.bus` | `0.1.0` |
| `wyrtloom.persistence` | `0.1.0` |
| `wyrtloom.users` | `0.1.0` |
| `wyrtloom.client_auth` | `0.1.0` |

---

## 1. `KanbanBoard` — `wyrtloom.kanban`

- **Contract id / version:** `wyrtloom.kanban` — floor `0.1.0`; `plugin-kanban-sqlite`
  **declares `0.2.0`** (adds the defaulted `list`).
- **Source:** `kanban.rs`
- **Implemented by:** `plugin-kanban-sqlite`

### Trait

```rust
pub trait KanbanBoard: Send + Sync {
    fn create(&self, task: NewTask) -> Result<TaskId, KanbanError>;
    fn transition(
        &self,
        id: TaskId,
        to: TaskState,
        actor: ActorId,
        reason: Option<String>,
    ) -> Result<(), KanbanError>;
    fn claim(&self, id: TaskId, worker: ActorId) -> Result<(), KanbanError>;
    fn get(&self, id: TaskId) -> Result<Task, KanbanError>;
    fn block(
        &self,
        id: TaskId,
        actor: ActorId,
        reason: BlockReason,
    ) -> Result<(), KanbanError>;

    /// Enumerate tasks matching `query` (added in contract v0.2.0).
    /// Defaulted so existing implementations remain source-compatible; a board
    /// that cannot enumerate returns `Storage(...)` rather than silently empty.
    fn list(&self, query: &TaskQuery) -> Result<Vec<Task>, KanbanError> {
        let _ = query;
        Err(KanbanError::Storage("enumeration not supported by this board".into()))
    }
}
```

### Supporting types

```rust
pub enum TaskState { Backlog, Todo, Ready, Running, Blocked, Done, Archived }

pub struct Task {
    pub id: TaskId,
    pub title: String,
    pub state: TaskState,
    pub actor: Option<ActorId>,
    pub depends_on: Vec<TaskId>,
    pub block_reason: Option<BlockReason>,
    pub history: Vec<StateChange>,
    pub created_at: Timestamp,
}

pub struct NewTask { pub title: String, pub actor: ActorId, pub depends_on: Vec<TaskId> }

pub struct BlockReason { pub reason: String, pub blocked_by: BlockedBy }
pub enum BlockedBy { Human(ActorId), Dependency(TaskId) }

pub struct StateChange { pub from: TaskState, pub to: TaskState,
                         pub actor: ActorId, pub at: Timestamp, pub reason: Option<String> }

/// Read-side filter; `Default` selects every task.
pub struct TaskQuery {
    pub states: Option<Vec<TaskState>>,
    pub actor: Option<ActorId>,
    pub limit: Option<usize>,
}

/// Free function — the canonical transition table.
pub fn is_legal_transition(from: &TaskState, to: &TaskState) -> bool;
```

Legal transitions (from `is_legal_transition`): `Backlog→Todo`, `Todo→Ready`,
`Todo→Backlog`, `Ready→Running`, `Ready→Backlog`, `Running→Done`, `Running→Blocked`,
`Running→Todo`, `Blocked→Running`, `Blocked→Todo`, `Blocked→Done`, `Done→Archived`.

### Error enum

```rust
pub enum KanbanError {
    IllegalTransition { from: TaskState, to: TaskState },
    DependenciesNotDone,
    AlreadyClaimed,
    BlockReasonRequired,
    NotFound(TaskId),
    Storage(String),
}
```

### Implementors MUST

- Permit **only legal transitions**; reject others with `IllegalTransition`.
- Promote `Todo → Ready` only when all `depends_on` are `Done`, else `DependenciesNotDone`.
- Make `claim` **atomic**: a running task is held by exactly one worker; a second claim
  fails with `AlreadyClaimed`.
- Require a `BlockReason` (with a `BlockedBy` target) to enter `Blocked`.
- Record every transition as a `StateChange` (actor + timestamp) — the audit trail.
- If they override `list`, honour `TaskQuery` filters; if they cannot enumerate, return
  `Storage(...)` (the default) rather than an empty vec.

---

## 2. `LlmProvider` — `wyrtloom.provider`

- **Contract id / version:** `wyrtloom.provider` — `0.1.0`
- **Source:** `provider.rs`
- **Implemented by:** `plugin-provider-ollama` (default, local), `wyrtloom-provider-nous`

### Trait

```rust
pub trait LlmProvider: Send + Sync {
    fn generate(&self, req: GenerationRequest) -> Result<GenerationResponse, ProviderError>;
    fn models(&self) -> Vec<ModelDescriptor>;
}
```

### Supporting types

```rust
pub enum MessageRole { System, User, Assistant }
pub struct Message { pub role: MessageRole, pub content: String }
// helpers: Message::system(_), Message::user(_), Message::assistant(_)

pub struct GenerationRequest {
    pub messages: Vec<Message>,
    pub max_output_tokens: u32,   // output-token budget — provider MUST respect
    pub model: ModelId,
}

pub enum ContentBlock { Text(String) }          // ContentBlock::as_text()
pub struct GenerationResponse { pub content: Vec<ContentBlock>, pub usage: Usage }
// GenerationResponse::full_text() concatenates text blocks

/// Cost-model schema — lives in core so all callers + the future ML tuner read uniformly.
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost: Option<Money>,     // None when the provider supplies no pricing
}

pub struct ModelDescriptor {
    pub id: ModelId,
    pub description: Option<String>,
    pub cost_per_input_token: Option<Money>,
    pub cost_per_output_token: Option<Money>,
}
```

### Error enum

```rust
pub enum ProviderError {
    RateLimited,
    Unauthorized,
    BudgetExceeded,
    Transport(String),
    Provider(String),
}
```

### Implementors MUST

- Respect the supplied `max_output_tokens` budget.
- Return a `Usage` conforming to the core cost-model schema even when cost is unknown
  (`cost` may be `None`; token counts may not be omitted).
- Surface failures through the **typed** `ProviderError` variants — never opaque panics.

---

## 3. `PersistenceProvider` — `wyrtloom.persistence`

- **Contract id / version:** `wyrtloom.persistence` — `0.1.0`
- **Source:** `persistence.rs`
- **Implemented by:** `wyrtloom-store-sqlite`

A storage-agnostic document store: named collections of JSON documents keyed by string id,
with a small declared-index query surface. `UserDirectory` and `ClientAuthScheme` are built
*on top of* this contract rather than embedding a database.

### Trait

```rust
pub trait PersistenceProvider: Send + Sync {
    fn ensure_collection(&self, spec: &CollectionSpec) -> Result<(), StoreError>;
    fn put(&self, collection: &str, record: Record) -> Result<(), StoreError>;
    fn get(&self, collection: &str, id: &str) -> Result<Record, StoreError>;
    fn query(&self, collection: &str, query: &Query) -> Result<Vec<Record>, StoreError>;
    fn delete(&self, collection: &str, id: &str) -> Result<(), StoreError>;

    /// Atomically insert only if `record.id` is absent. Ok(true) if inserted,
    /// Ok(false) if it already existed. Implementations MUST make this atomic —
    /// it backs single-use tokens. The default is a NON-atomic get-then-put fallback.
    fn put_if_absent(&self, collection: &str, record: Record) -> Result<bool, StoreError> {
        match self.get(collection, &record.id) {
            Ok(_) => Ok(false),
            Err(StoreError::NotFound(_)) => { self.put(collection, record)?; Ok(true) }
            Err(e) => Err(e),
        }
    }
}
```

### Supporting types

```rust
pub struct CollectionSpec { pub name: String, pub indexed_fields: Vec<String> }

/// Record's Debug omits `doc` (it may hold password hashes / keys): only the id
/// is printed, with `<redacted>` for the document.
pub struct Record { pub id: String, pub doc: serde_json::Value }

pub enum Query {
    All,
    ById(String),
    /// `field` MUST be one of the collection's declared `indexed_fields`.
    ByField { field: String, value: serde_json::Value },
}

/// Validate a storage identifier: lowercase `[a-z][a-z0-9_]{0,63}`, 1..=64 chars.
pub fn is_valid_identifier(name: &str) -> bool;
```

### Error enum

```rust
pub enum StoreError {
    CollectionNotFound(String),
    NotFound(String),
    InvalidIdentifier(String),
    FieldNotIndexed(String),
    Storage(String),
}
```

### Implementors MUST (security invariants)

- **Validate identifiers.** Collection names and indexed-field names are storage
  *identifiers* (un-parameterizable in SQL); validate them with `is_valid_identifier` and
  reject with `InvalidIdentifier`. (This rule is intentionally stricter than the
  plugin-name rule — a `-` is fine in a plugin name but not as a bare SQL identifier, and a
  leading letter is required.)
- **Allow-list `Query::ByField` fields** against the collection's declared
  `indexed_fields`; reject others with `FieldNotIndexed`.
- **Bind document values, never interpolate them.**
- **Make `put_if_absent` atomic.** It backs single-use tokens; the trait default is an
  explicitly non-atomic get-then-put fallback that real stores MUST override (the default
  is not safe for cross-process single-use).
- Keep `Record`'s Debug redaction intact — documents may carry secrets.

---

## 4. `UserDirectory` — `wyrtloom.users`

- **Contract id / version:** `wyrtloom.users` — `0.1.0`
- **Source:** `users.rs`
- **Implemented by:** `wyrtloom-users` (argon2 over a `PersistenceProvider`)

Core has no built-in notion of human users; consumers that need authenticated users (e.g.
the dashboard API server) depend on this contract.

### Trait

```rust
pub trait UserDirectory: Send + Sync {
    /// Verify a username/password and return the user. Implementations MUST use a
    /// constant-time hash verify and SHOULD run the hash even for unknown users
    /// (uniform timing) to avoid an enumeration oracle.
    fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError>;
    fn create(&self, new: NewUser) -> Result<ActorId, AuthError>;
    fn get(&self, id: &str) -> Result<User, AuthError>;
    fn list(&self) -> Result<Vec<User>, AuthError>;
}
```

### Supporting types

```rust
pub enum Role { Viewer, Operator, Admin }

pub struct User {
    pub id: ActorId,             // reuses ActorId so user actions thread through audit/kanban
    pub roles: Vec<Role>,
    pub active: bool,            // disabled users must be rejected at auth AND each request
    pub created_at: Timestamp,
}
// User::has_role(role)

/// NewUser's Debug redacts the plaintext `password`.
pub struct NewUser { pub username: ActorId, pub password: String, pub roles: Vec<Role> }
```

### Error enum

```rust
pub enum AuthError {
    InvalidCredential,
    Disabled,
    AlreadyExists,
    NotFound,
    Storage(String),
}
```

### Implementors MUST (security invariants)

- **Hash before storage** — the plaintext password is only in transit to the
  implementation, which MUST hash it (argon2id) before persisting.
- Use a **constant-time hash verify**, and SHOULD run the hash even for unknown users so
  timing does not become an enumeration oracle.
- Reject disabled users (`active == false`) at authentication and on every request.
- Keep `NewUser`'s Debug redaction intact.

Roles are intentionally coarse: the directory verifies *identity*; per-request
authorization, session lifetime, and revocation are the caller's responsibility.

---

## 5. `ClientAuthScheme` — `wyrtloom.client_auth`

- **Contract id / version:** `wyrtloom.client_auth` — `0.1.0`
- **Source:** `client_auth.rs`
- **Implemented by:** `wyrtloom-clientauth-tofu` (trust-on-first-use + asymmetric keys)

Verifies the *client application* (web SPA, mobile app, CLI) — distinct from the human
user. The reference scheme is TOFU: a client makes first contact with a single-use
bootstrap API key and presents a **public key**; the server pins it and thereafter verifies
each request by public-key signature.

### Trait

```rust
pub trait ClientAuthScheme: Send + Sync {
    /// Enroll a client on first contact (validate bootstrap key, pin the public key).
    fn enroll(&self, req: EnrollmentRequest) -> Result<ClientCredential, ClientAuthError>;
    /// Verify a subsequent request's authentication material.
    fn verify(&self, presented: &PresentedClientAuth) -> Result<ClientIdentity, ClientAuthError>;
}
```

### Shared canonicalisation (in the contract, not a plugin)

```rust
pub type ClientId = String;
pub const CLIENT_AUTH_DOMAIN: &str = "wyrtloom-client-auth-v1";

/// Build the canonical bytes a client signs and the server verifies. Lives in the
/// contract so the client signer, the scheme plugin, and the API server produce
/// byte-identical input.
pub fn canonical_request(
    method: &str, path: &str, body_sha256: &[u8],
    client_id: &str, timestamp: i64, nonce: &str,
) -> Vec<u8>;
```

`canonical_request` uses `CanonicalEncoder::new(CLIENT_AUTH_DOMAIN)` and length-prefixes
each field, so a signature binds to exactly this method/path/body/client/time/nonce with no
field-boundary ambiguity.

### Supporting types

```rust
/// Debug redacts the bootstrap `api_key`.
pub struct EnrollmentRequest { pub api_key: String, pub client_name: String, pub public_key: Vec<u8> }

/// Carries NO secret material — only the public identity the server pins (TOFU).
pub struct ClientCredential { pub client_id: ClientId, pub fingerprint: String, pub enrolled_at: Timestamp }

/// Debug redacts `signature`.
pub struct PresentedClientAuth {
    pub client_id: ClientId,
    pub canonical_request: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: i64,        // verifier enforces a small skew window
    pub nonce: String,         // verifier rejects replays within the skew window
}

pub struct ClientIdentity { pub client_id: ClientId }
```

### Error enum

```rust
pub enum ClientAuthError {
    BadApiKey, UnknownClient, BadSignature, Replay,
    PinMismatch, Invalid(String), Storage(String),
}
```

### Implementors MUST (security invariants)

- **Store only public material** — the public key + fingerprint, never a recoverable
  secret (`ClientCredential` exposes exactly `client_id`/`fingerprint`/`enrolled_at`).
- Treat the bootstrap `api_key` as **single-use** (back it with `put_if_absent`); reject
  reuse with `BadApiKey`.
- Verify the signature over the **shared** `canonical_request` bytes so the signature binds
  to the exact request.
- Enforce the **TOFU pin** on subsequent requests (`PinMismatch` on a key change) and
  **anti-replay** via the timestamp skew window + nonce (`Replay`).
- Keep the `EnrollmentRequest`/`PresentedClientAuth` Debug redactions intact.

---

## 6. `CallLogger` — `wyrtloom.logger`

- **Contract id / version:** `wyrtloom.logger` — `0.1.0`
- **Source:** `logger.rs`
- **Implemented by:** `plugin-logger-sqlite`

### Trait

```rust
pub trait CallLogger: Send + Sync {
    fn record(&self, entry: CallLog) -> Result<(), LogError>;

    /// Implementations that do not retain readable history return an empty vec.
    fn all_logs(&self) -> Result<Vec<CallLog>, LogError> { Ok(Vec::new()) }
}
```

### Supporting types

```rust
pub enum CallOutcome { Completed, Failed(String), Partial(String) }

pub struct CallLog {
    pub task: TaskId,
    pub profile: ProfileId,
    pub provider: String,
    pub model: ModelId,
    pub usage: Usage,            // the cost-model schema from provider.rs
    pub outcome: CallOutcome,
    pub at: Timestamp,
}
```

### Error enum

```rust
pub enum LogError { Storage(String) }
```

### Implementors MUST

- Log **every** LLM call — completed, failed, *and* partial calls must be recorded, never
  silently dropped (this is the raw material for the future ML tuner).

---

## 7. `SandboxRuntime` — `wyrtloom.sandbox`

- **Contract id / version:** `wyrtloom.sandbox` — `0.1.0`
- **Source:** `sandbox.rs`
- **Implemented by:** `plugin-sandbox-wasmtime`

The runtime is a **core-controlled** plugin: loaded before any untrusted code (bootstrap
stage 3) and never replaceable by untrusted code.

### Trait

```rust
pub trait SandboxRuntime: Send + Sync {
    fn execute(
        &self,
        module: SafeModule,
        input: Bytes,
        limits: ResourceLimits,
    ) -> Result<Bytes, SandboxError>;
}
```

### Supporting types

```rust
pub struct ResourceLimits { pub max_memory_bytes: u64, pub max_wallclock_ms: u64 }
// Default: 16 MiB, 5_000 ms

/// Opaque handle to a compiled safe WASM module. `content_hash` is SHA-256(wasm_bytes),
/// computed once at construction (SafeModule::new) for cache keying.
pub struct SafeModule { pub wasm_bytes: Bytes, pub content_hash: [u8; 32] }
```

### Error enum

```rust
pub enum SandboxError {
    MemoryExceeded,
    Timeout,
    HostAccessAttempted(Capability),   // sandboxed code tried to reach a host capability
    Trap(String),
    Compile(String),
}
```

### Implementors MUST

- Enforce `ResourceLimits` (memory + wallclock) and fail with `MemoryExceeded` / `Timeout`.
- Deny all host access: a module attempting a host import/capability is isolated with
  `HostAccessAttempted(Capability)` rather than being granted it.

---

## 8. `MessageBus` — `wyrtloom.bus`

- **Contract id / version:** `wyrtloom.bus` — `0.1.0`
- **Source:** `bus.rs`
- **Implemented by:** `plugin-bus-tokio` (in-process Tokio channels)

### Trait + bootstrap primitive

```rust
pub trait MessageBus: Send + Sync {
    fn publish(&self, event: Event) -> Result<(), BusError>;
    fn subscribe(&self, topic: Topic) -> tokio::sync::broadcast::Receiver<Event>;
}

/// Minimal synchronous bus that exists BEFORE any plugin loads — solves the
/// chicken-and-egg: you cannot load a bus *plugin* until something can carry the
/// "loaded" signal. Implements MessageBus over a tokio broadcast channel.
pub struct BootstrapBus { /* … */ }
impl BootstrapBus { pub fn new() -> Self; }
```

### Supporting types + error enum

```rust
pub struct Event { pub topic: Topic, pub payload: serde_json::Value }
// Event::new(topic, payload)

pub enum BusError { PublishFailed(String), NoSubscribers(String) }
```

### Implementors MUST

- Deliver an `Event` to subscribers of its `topic`. `BootstrapBus::publish` deliberately
  succeeds with no subscribers (expected during early bootstrap before anything subscribes).

---

## 9. `HumanEscalation` — `wyrtloom.escalation`

- **Contract id / version:** `wyrtloom.escalation` — `0.1.0`
- **Source:** `escalation.rs`
- **Implemented by:** `plugin-escalation-cli`

### Trait

```rust
pub trait HumanEscalation: Send + Sync {
    fn escalate(&self, e: Escalation) -> Result<HumanResponse, EscalationError>;
}
```

### Supporting types + error enum

```rust
pub struct ActionOption { pub id: String, pub label: String, pub description: Option<String> }

pub struct Escalation {
    pub task: TaskId,
    pub prompt: String,
    /// Suggested actions (Phase-2 buttons). Free-text and stop are ALWAYS implicit.
    pub options: Vec<ActionOption>,
}

pub enum HumanResponse {
    Chose(String),     // ActionOption.id
    FreeText(String),
    Stop,
}

pub enum EscalationError { Interrupted, Io(String) }
```

### Implementors MUST

- Always offer **free-text and stop**, even when `options` is empty. The shape is designed
  so a Phase-2 graphical UI (options→buttons, free-text→field, stop→button) needs no
  interface change.

---

## 10. Core, not plugins

These live in core and have no plugin implementation — they are the kernel itself.

### 10.1 `SecurityModule` / `SecurityPolicy` (`security.rs`)

The root of trust. Initialises first (bootstrap stage 1) and verifies each subsequent
stage. Not a trait — a concrete core type.

```rust
pub struct SecurityModule { /* … */ }
impl SecurityModule {
    pub fn new() -> Self;                                      // permissive policy, no file
    pub fn with_policy(policy: SecurityPolicy) -> Self;
    pub fn with_key(key: [u8; 32], policy: SecurityPolicy) -> Self;  // durable, persisted key
    pub fn with_audit_file(self, path: &str) -> Result<Self, SecurityError>;

    pub fn self_check(&self) -> Result<(), SecurityError>;     // runs first; rejects all-zero key
    pub fn verify(&self, manifest: &PluginManifest) -> Result<(), SecurityError>;
    pub fn stamp(&self, content: &[u8]) -> Stamp;              // HMAC-SHA256 bound to content
    pub fn is_valid(&self, stamp: &Stamp, content: &[u8]) -> bool;  // constant-time compare
    pub fn invalidate(&self, stamp: Stamp);
    pub fn record_decision(&self, granted: bool, detail: String);   // sanitised, into chain
    pub fn audit_log_snapshot(&self) -> Vec<SecurityDecision>;
    pub fn verify_chain(&self) -> Result<(), SecurityError>;   // keyed hash-chain integrity
}

pub struct SecurityPolicy {
    pub file_read_prefixes: Vec<String>,     // empty = deny all; component-boundary match
    pub file_write_prefixes: Vec<String>,
    pub network_allowlist: Vec<String>,      // exact or dotted-suffix match
    pub allow_shell: bool,                   // deny unless explicitly true
    pub allow_git: bool,
}
impl SecurityPolicy { pub fn permissive() -> Self; pub fn deny_all() -> Self; }

pub enum SecurityError { IntegrityFailure(String), CapabilityDenied(Capability), SafePluginViolation }
```

Key invariants this enforces:

- `self_check` runs before anything else and refuses an all-zero (RNG-failed) key.
- A **`Safe` plugin declaring any capability is rejected** (`SafePluginViolation`).
- Capabilities are checked **deny-by-default** against the policy; path prefixes match at a
  component boundary (so `/etc` does not grant `/etc-evil`) and reject `..` traversal;
  network matches exact or dotted-suffix (so `localhost` does not match `evillocalhost`).
- Stamps are HMAC-SHA256 bound to message content, compared in **constant time**, with a
  revocation set; sub-keys are domain-separated (session vs audit).
- Audit entries form a **keyed hash-chain**; persisted audit files are opened 0600 via the
  open fd (no TOCTOU), bounded against OOM, and **verified on open** (a tampered file is
  rejected). Raw MACs and free-text detail are redacted / sanitised before logging.

### 10.2 Plugin model (`plugin.rs`)

```rust
pub enum PluginClass { Safe, Unsafe }

pub enum Capability {
    FileRead(String), FileWrite(String), Network(String), Shell, Git,
}

pub struct PluginManifest {
    pub name: String,
    pub version: SemVer,
    pub class: PluginClass,
    pub capabilities: Vec<Capability>,
    pub implements: Vec<(ContractId, SemVer)>,   // (contract id, required core version)
}
impl PluginManifest {
    /// name must match [a-z0-9_-]{1,64}
    pub fn validate_name(name: &str) -> Result<(), String>;
}

pub struct PluginRegistry { /* … */ }
impl PluginRegistry {
    pub fn register<F>(&self, manifest: PluginManifest, factory: F) where /* … */;
    pub fn manifests(&self) -> Vec<PluginManifest>;
    pub fn take_factories(&self) -> Vec<(PluginManifest, PluginFactory)>;
}

pub struct CoreContractVersions(pub HashMap<ContractId, SemVer>);
impl CoreContractVersions {
    pub fn v0_1() -> Self;                                          // the floor table
    pub fn is_compatible(&self, contract: &str, plugin_version: &SemVer) -> bool;
}

pub enum LoadError {
    ManifestInvalid(String),
    IncompatibleContractVersion { contract: String, required: SemVer, provided: SemVer },
    SecurityRejected(String),
    SafePluginRequestedCapability,
}
```

### 10.3 `canon::CanonicalEncoder` (`canon.rs`)

A length-prefixed, domain-separated byte encoder so independent components produce
**byte-identical** signing input across process/crate boundaries (used by
`client_auth::canonical_request` and the gate engine).

```rust
pub struct CanonicalEncoder { /* … */ }
impl CanonicalEncoder {
    pub fn new(domain: &str) -> Self;             // domain tag is itself length-prefixed
    pub fn field(self, bytes: &[u8]) -> Self;     // positional, length-prefixed
    pub fn str_field(self, s: &str) -> Self;
    pub fn tagged(self, tag: &str, bytes: &[u8]) -> Self;
    pub fn finish(self) -> Vec<u8>;
}
```

Every field is written as an 8-byte big-endian length followed by its bytes, so no field
boundary can shift without changing the output (`actor="a",task="bX"` and
`actor="ab",task="X"` encode differently), and different domains never collide.

---

## See also

- [`architecture.md`](./architecture.md) — core/plugin model, the three lenses, bootstrap
  sequence, repo/dependency map, the `parse→plan→execute→verify` pipeline, and SemVer
  floor-vs-declared rules.
- `Specification` Appendix A — the normative interface appendix.
