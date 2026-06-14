# Writing a Wyrtloom plugin

This guide describes how to author a Wyrtloom plugin **in its own repository**, the
way the reference out-of-tree plugins do (`wyrtloom-store-sqlite`, `wyrtloom-users`,
`wyrtloom-clientauth-tofu`, `wyrtloom-provider-nous`). It is grounded in the real
code of those crates and of `wyrtloom-core`.

A Wyrtloom plugin is an ordinary Rust crate that implements one of the **core
contract traits** defined in `wyrtloom-core` and ships a **manifest** describing
its identity, class, and capabilities. Plugins never redefine core types — they
depend on `wyrtloom-core` and implement its traits.

---

## 1. Pick the core contract you implement

Every plugin implements exactly one trait from `wyrtloom_core`. The current
contracts and their floor versions (from `CoreContractVersions::v0_1()`):

| Contract id            | Trait (`wyrtloom_core::…`)              | Floor | Reference plugin |
|------------------------|------------------------------------------|-------|------------------|
| `wyrtloom.persistence` | `persistence::PersistenceProvider`       | 0.1.0 | `wyrtloom-store-sqlite` |
| `wyrtloom.users`       | `users::UserDirectory`                   | 0.1.0 | `wyrtloom-users` |
| `wyrtloom.client_auth` | `client_auth::ClientAuthScheme`          | 0.1.0 | `wyrtloom-clientauth-tofu` |
| `wyrtloom.provider`    | `provider::LlmProvider`                  | 0.1.0 | `wyrtloom-provider-nous`, in-tree `plugin-provider-ollama` |
| `wyrtloom.kanban`      | `kanban::KanbanBoard`                    | 0.1.0 | in-tree `plugin-kanban-sqlite` (declares 0.2.0) |
| `wyrtloom.logger`      | `logger::CallLogger`                     | 0.1.0 | in-tree `plugin-logger-sqlite` |
| `wyrtloom.sandbox`     | `sandbox::SandboxRuntime`                | 0.1.0 | in-tree `plugin-sandbox-wasmtime` |
| `wyrtloom.escalation`  | `escalation::HumanEscalation`            | 0.1.0 | in-tree `plugin-escalation-cli` |
| `wyrtloom.bus`         | `bus::MessageBus`                        | 0.1.0 | in-tree `plugin-bus-tokio` |

The trait you implement defines your whole public surface. For example a storage
plugin implements:

```rust
pub trait PersistenceProvider: Send + Sync {
    fn ensure_collection(&self, spec: &CollectionSpec) -> Result<(), StoreError>;
    fn put(&self, collection: &str, record: Record) -> Result<(), StoreError>;
    fn get(&self, collection: &str, id: &str) -> Result<Record, StoreError>;
    fn query(&self, collection: &str, query: &Query) -> Result<Vec<Record>, StoreError>;
    fn delete(&self, collection: &str, id: &str) -> Result<(), StoreError>;
    // Default impl is a NON-atomic get-then-put fallback; real stores override it
    // with a single atomic statement (see §4).
    fn put_if_absent(&self, collection: &str, record: Record) -> Result<bool, StoreError>;
}
```

A version above the floor must stay **minor-compatible** (same major, minor ≥
required) — that is exactly how `plugin-kanban-sqlite` declares `0.2.0` against a
`0.1.0` floor: it only *adds* a method (`KanbanBoard::list`). See
`SemVer::is_compatible_with` and `CoreContractVersions::is_compatible`.

---

## 2. Cargo conventions

Reference `wyrtloom-core` by a **sibling path dependency**, with a commented
**git fallback** for out-of-tree builds. Pin a `rev` in the git form. This is the
exact pattern in every reference plugin:

```toml
[package]
name = "my-wyrtloom-plugin"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
description = "…one line…"

[dependencies]
# Local development depends on a sibling checkout of the Wyrtloom monorepo.
wyrtloom-core = { path = "../wyrtloom/crates/core" }
# Portable alternative (use instead of the path dep for out-of-tree builds — pin a rev):
# wyrtloom-core = { git = "https://github.com/codepilots/wyrtloom.git", rev = "<sha>" }

# … only the deps your contract actually needs …
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror  = "1"

[dev-dependencies]
# Storage-backed plugins test against the real SQLite store, not a mock.
wyrtloom-store-sqlite = { path = "../wyrtloom-store-sqlite" }
```

Notes:

- **In-tree** plugins (under `crates/plugin-*` in the monorepo) use
  workspace-inherited deps instead — `wyrtloom-core = { workspace = true }`,
  `rusqlite = { workspace = true }`, etc. — because they are workspace members
  (see the root `Cargo.toml` `[workspace.dependencies]`). **Out-of-tree** plugins
  pin explicit versions because they are not in the workspace.
- Keep your dependency set minimal and contract-shaped. A provider plugin that
  makes HTTPS calls should use rustls so it builds with **no system OpenSSL /
  pkg-config** (`wyrtloom-provider-nous` does this):

  ```toml
  reqwest = { version = "0.12", default-features = false,
              features = ["json", "blocking", "rustls-tls"] }
  url = "2"
  ```

  (The in-tree `plugin-provider-ollama` uses the workspace `reqwest` with default
  features, which pulls native-tls and therefore requires pkg-config/OpenSSL at
  build time — see `docs/development.md`. New plugins should prefer rustls.)

---

## 3. Reuse core types — never redefine them

Your plugin **must** use the structs/enums/aliases from `wyrtloom_core::types`
and from your contract module. Do not define your own `TaskId`, `Role`,
`StoreError`, `CollectionSpec`, `Record`, `Query`, `Money`, `SemVer`, etc.

```rust
use wyrtloom_core::persistence::{
    is_valid_identifier, CollectionSpec, PersistenceProvider, Query, Record, StoreError,
};
use wyrtloom_core::storage::validate_db_path;
```

Core aliases you will see across contracts:
`TaskId = Uuid`, `ActorId = String`, `ModelId = String`, `ContractId = String`,
`Topic = String`, plus `Timestamp`, `SemVer`, `Money`. Redefining any of these
breaks interop and is rejected in review.

---

## 4. The SQLite-plugin pattern

Storage-backed plugins follow the shape established by `wyrtloom-store-sqlite`.
Reproduce it rather than inventing your own:

**Hold the connection behind a `Mutex`, and map a poisoned lock to a `Storage`
error instead of panicking.** A thread that panics while holding the lock then
degrades into a clean error for every other caller rather than cascading panics:

```rust
use std::sync::Mutex;
use rusqlite::Connection;

pub struct SqliteStore {
    conn: Mutex<Connection>,
    // …in-memory allow-list / spec cache as needed…
}

fn lock<T>(m: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, StoreError> {
    m.lock().map_err(|_| StoreError::Storage("lock poisoned".into()))
}
```

**Provide `open`, `in_memory`, and `init_schema`.** `open(":memory:")` opens an
in-memory DB; any other path is validated against traversal with the core helper
**before** it touches the filesystem. Set WAL + a busy timeout so two processes
can share the file safely:

```rust
impl SqliteStore {
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()
                .map_err(|_| StoreError::Storage("open in-memory failed".into()))?
        } else {
            // Reuse the audited core helper — do NOT roll your own traversal check.
            validate_db_path(path)
                .map_err(|e| StoreError::Storage(format!("invalid path: {e}")))?;
            Connection::open(path)
                .map_err(|_| StoreError::Storage("open database failed".into()))?
        };
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .map_err(|_| StoreError::Storage("configure pragmas failed".into()))?;
        let store = Self { conn: Mutex::new(conn) /* … */ };
        store.init_schema()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self, StoreError> { Self::open(":memory:") }
}
```

**Parameterized SQL only.** Every *value* is bound with `?n` / `params![…]` —
never string-interpolated. The only thing that may be interpolated is a SQL
**identifier** (table/column name) that you have first validated (see §6). Values
round-trip verbatim even when they contain `'); DROP TABLE …`.

**Integrity errors are errors, not panics.** A malformed row read back from disk
(e.g. a corrupted JSON document, or a catalog row whose JSON no longer parses)
returns `StoreError::Storage("integrity error: …")`. Never `unwrap()` on data
that came off disk. Do not silently coerce a corrupt catalog to an empty/lenient
state — fail loud, so a previously-valid query cannot start silently returning
the wrong thing after a reopen.

**Atomic single-use via the DB, not get-then-put.** When you need
insert-if-absent semantics (single-use tokens, TOFU pins), override
`put_if_absent` with one atomic statement so there is no TOCTOU window:

```rust
conn.execute(
    &format!("INSERT INTO \"{name}\" (id, doc) VALUES (?1, ?2) ON CONFLICT(id) DO NOTHING"),
    params![record.id, doc],
)?;
Ok(conn.changes() == 1) // 1 = inserted (id was absent), 0 = already present
```

Under WAL this is atomic across connections/processes — which is what makes a
bootstrap key genuinely single-use even with concurrent enrollments.

Note that the **other** storage-backed contracts (`UserDirectory`,
`ClientAuthScheme`) do **not** open SQLite themselves. They hold an
`Arc<dyn PersistenceProvider>` and speak only the document/collection contract
(`get`/`put`/`put_if_absent`/`query`), so SQL-injection safety is delegated to
the store. Prefer that layering: write storage logic against
`PersistenceProvider`, and let `wyrtloom-store-sqlite` own the SQL.

---

## 5. The manifest and capabilities

Every plugin ships a `PluginManifest`:

```rust
pub struct PluginManifest {
    pub name: String,                      // validated [a-z0-9_-]{1,64}
    pub version: SemVer,
    pub class: PluginClass,                // Safe | Unsafe
    pub capabilities: Vec<Capability>,
    pub implements: Vec<(ContractId, SemVer)>, // (contract id, required core version)
}

pub enum Capability {
    FileRead(String),   // path prefix
    FileWrite(String),  // path prefix
    Network(String),    // host
    Shell,
    Git,
}
```

**Capability rule (enforced at bootstrap):**

- A **SAFE** plugin declares **NO capabilities** — `capabilities: vec![]`. A Safe
  plugin that lists any capability is rejected with
  `LoadError::SafePluginRequestedCapability` (the bootstrap sequence asserts
  `class == Safe && capabilities.is_empty()`).
- An **UNSAFE** plugin declares exactly the capabilities it needs:
  `Capability::FileWrite(".")` for a SQLite store that writes its DB,
  `Capability::Network("localhost")` for a local provider, `Shell`, `Git`, etc.

Real manifests from the in-tree boot sequence (`src/main.rs`):

```rust
// SQLite kanban: writes a DB file → Unsafe + FileWrite. Declares 0.2.0.
PluginManifest {
    name: "plugin-kanban-sqlite".into(),
    version: SemVer::new(0, 2, 0),
    class: PluginClass::Unsafe,
    capabilities: vec![Capability::FileWrite(".".into())],
    implements: vec![("wyrtloom.kanban".into(), SemVer::new(0, 2, 0))],
}

// Wasmtime sandbox: pure compute, no host reach → Safe + NO capabilities.
PluginManifest {
    name: "plugin-sandbox-wasmtime".into(),
    version: SemVer::new(0, 1, 0),
    class: PluginClass::Safe,
    capabilities: vec![],
    implements: vec![("wyrtloom.sandbox".into(), SemVer::new(0, 1, 0))],
}

// Local LLM provider: talks to localhost → Unsafe + Network.
PluginManifest {
    name: "plugin-provider-ollama".into(),
    version: SemVer::new(0, 1, 0),
    class: PluginClass::Unsafe,
    capabilities: vec![Capability::Network("localhost".into())],
    implements: vec![("wyrtloom.provider".into(), SemVer::new(0, 1, 0))],
}
```

At bootstrap each manifest is validated (name charset), contract-version-checked
(`is_compatible`), Safe/capability-checked, and security-verified before the
system comes up.

---

## 6. Security requirements every plugin must meet

These are non-negotiable and are enforced in review and by the reference crates'
tests. Apply the ones relevant to your contract.

- **Validate identifiers before building dynamic SQL.** If you ever interpolate a
  table or column name, gate it through `wyrtloom_core::persistence::is_valid_identifier`
  (pattern `[a-z][a-z0-9_]{0,63}` — leading lowercase letter, then `[a-z0-9_]`,
  max 64). Validate **every** identifier before *any* SQL runs, so one bad name
  aborts the whole operation with `StoreError::InvalidIdentifier` and leaves no
  partial schema. Defence-in-depth: also allow-list a queryable field against the
  collection's declared `indexed_fields`.
- **Parameterize all values.** Bind with `?n`; never interpolate a value.
- **Store no recoverable secrets.** Persist only public material. A user
  directory stores an argon2id PHC hash, never a password. A client-auth scheme
  stores a public key / its fingerprint, never private key material. (The
  reference crates have tests that assert the persisted records contain no
  secrets.)
- **Redact `Debug` on secret-bearing types.** Any struct that carries a
  credential, signature, password, or MAC must implement `Debug` by hand and
  print `<redacted>` for that field. Core already does this for
  `EnrollmentRequest.api_key`, `PresentedClientAuth.signature`, `NewUser.password`,
  `Record.doc`, and `Stamp`. Your secret types must too:

  ```rust
  impl std::fmt::Debug for StoredUser {
      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
          f.debug_struct("StoredUser")
              .field("username", &self.username)
              .field("password_hash", &"<redacted>")
              // …
              .finish()
      }
  }
  ```

- **`strip_control` untrusted output (providers).** Any text that comes back from
  an external model/service and might reach a terminal or a prompt must be run
  through `wyrtloom_core::util::strip_control` before you return it — this removes
  ANSI/terminal-injection sequences and Trojan-Source bidi/format codepoints.
  Re-export it rather than vendoring a copy:

  ```rust
  pub use wyrtloom_core::util::strip_control;
  // …
  let clean = strip_control(&content);
  Ok(GenerationResponse { content: vec![ContentBlock::Text(clean)], usage })
  ```

- **SSRF-safe URL handling (providers).** Parse the base URL with the `url`
  crate (do **not** prefix-match strings); reject userinfo (`user:pass@`); allow
  `https://` and only `http://localhost` / `http://127.0.0.1`; never echo the raw
  URL in an error (it may contain a password — redact to scheme + host). Cap the
  response body (stream with `Read::take`, e.g. 8 MiB) so a hostile endpoint
  cannot exhaust memory. Disable redirects and set a timeout; map transport
  errors to opaque messages that do not leak the host. This is exactly what
  `wyrtloom-provider-nous::validate_base_url` / `read_bounded_body` do.

- **Crypto-scheme requirements (client-auth).** Verify the **canonical** request
  bytes from `wyrtloom_core::client_auth::canonical_request` — never re-implement
  the encoding. Support ed25519 (32-byte key) and ECDSA P-256 (65-byte SEC1,
  leading `0x04`), detecting by key length. **Enforce low-s** for P-256 (reject a
  high-s signature) to remove ECDSA malleability — e.g. `signature.normalize_s().is_some()`
  ⇒ reject. Compare bootstrap keys in constant time (`subtle::ConstantTimeEq`).
  Use saturating arithmetic on attacker-controlled timestamps. Keep a bounded
  replay/nonce cache.

---

## 7. Test-first: contract tests

Author the plugin **test-first**, against the **real** dependency, not a mock:

- A storage plugin's tests open `SqliteStore::in_memory()` (and a temp file for
  reopen/concurrency cases) and exercise the full `PersistenceProvider` contract
  plus a dedicated **security** test block (injection in collection/field names,
  malicious values stored literally, integrity error on corrupt JSON, path
  traversal rejected, `put_if_absent` atomic under concurrency). See the `tests`
  module in `wyrtloom-store-sqlite/src/lib.rs` for the canonical set.
- Plugins that build on `PersistenceProvider` (`wyrtloom-users`,
  `wyrtloom-clientauth-tofu`) add `wyrtloom-store-sqlite` as a **dev-dependency**
  and test against it, so behaviour is verified end-to-end through the real store.
- Provider plugins keep wire logic in pure helpers (`build_chat_body`,
  `parse_chat_response`, `validate_base_url`, …) so they can be unit-tested
  offline with no network and no dev-dependency on a store.

Run: `cargo test` in your plugin repo (see `docs/development.md`).

---

## 8. Registering a plugin

Today, plugins are registered **programmatically** in the host's `main.rs` via
the `Bootstrapper`:

```rust
let mut bootstrapper = wyrtloom_core::bootstrap::Bootstrapper::new();

bootstrapper.register_plugin(
    PluginManifest {
        name: "my-wyrtloom-plugin".into(),
        version: SemVer::new(0, 1, 0),
        class: PluginClass::Unsafe,
        capabilities: vec![Capability::FileWrite(".".into())],
        implements: vec![("wyrtloom.persistence".into(), SemVer::new(0, 1, 0))],
    },
    || std::sync::Arc::new(()), // factory: Fn() -> Arc<dyn Any + Send + Sync>
);

let sys = bootstrapper.run()?; // validates names, versions, Safe/capability, security
```

`register_plugin(manifest, factory)` records the manifest and a type-erased
factory (`Fn() -> Arc<dyn Any + Send + Sync>`). `Bootstrapper::run()` runs the
fixed bootstrap sequence: Security module first, then for every manifest it
validates the name charset, checks contract-version compatibility, rejects a Safe
plugin that declares capabilities, and security-verifies the manifest. Any
failure halts boot with a logged `BootstrapError`. The concrete implementations
are then instantiated (e.g. `SqliteKanbanBoard::open(...)`) and wired into the
pipeline behind `Arc<dyn Trait>`.

A declarative **`wyrtloom-config`** path (load manifests/instances from config
rather than hand-wiring `main.rs`) is the intended evolution of this step; until
it lands, register programmatically as above.

---

## 9. Worked mini-example skeleton

A minimal out-of-tree persistence plugin, in its own repo:

`Cargo.toml`
```toml
[package]
name = "wyrtloom-store-memo"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
description = "In-memory PersistenceProvider for tests and ephemeral runs"

[dependencies]
wyrtloom-core = { path = "../wyrtloom/crates/core" }
# wyrtloom-core = { git = "https://github.com/codepilots/wyrtloom.git", rev = "<sha>" }
serde_json = "1"
```

`src/lib.rs`
```rust
//! In-memory document store implementing `wyrtloom.persistence`.
//!
//! # Security
//! Collection names and `Query::ByField` fields are validated with
//! `is_valid_identifier` and allow-listed against declared `indexed_fields`,
//! mirroring the SQLite store, so callers cannot probe undeclared fields.

use std::collections::HashMap;
use std::sync::Mutex;

use wyrtloom_core::persistence::{
    is_valid_identifier, CollectionSpec, PersistenceProvider, Query, Record, StoreError,
};

#[derive(Default)]
struct Inner {
    specs: HashMap<String, Vec<String>>,       // collection -> indexed fields
    data: HashMap<String, HashMap<String, serde_json::Value>>, // collection -> id -> doc
}

pub struct MemoStore {
    inner: Mutex<Inner>,
}

impl MemoStore {
    pub fn in_memory() -> Self {
        Self { inner: Mutex::new(Inner::default()) }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>, StoreError> {
        self.inner.lock().map_err(|_| StoreError::Storage("lock poisoned".into()))
    }

    fn checked(name: &str) -> Result<&str, StoreError> {
        if is_valid_identifier(name) { Ok(name) }
        else { Err(StoreError::InvalidIdentifier(name.to_string())) }
    }
}

impl PersistenceProvider for MemoStore {
    fn ensure_collection(&self, spec: &CollectionSpec) -> Result<(), StoreError> {
        let name = Self::checked(&spec.name)?;
        for f in &spec.indexed_fields {
            if !is_valid_identifier(f) {
                return Err(StoreError::InvalidIdentifier(f.clone()));
            }
        }
        let mut g = self.lock()?;
        g.specs.entry(name.to_string()).or_insert_with(|| spec.indexed_fields.clone());
        g.data.entry(name.to_string()).or_default();
        Ok(())
    }

    fn put(&self, collection: &str, record: Record) -> Result<(), StoreError> {
        let name = Self::checked(collection)?;
        let mut g = self.lock()?;
        let coll = g.data.get_mut(name)
            .ok_or_else(|| StoreError::CollectionNotFound(name.to_string()))?;
        coll.insert(record.id, record.doc);
        Ok(())
    }

    fn get(&self, collection: &str, id: &str) -> Result<Record, StoreError> {
        let name = Self::checked(collection)?;
        let g = self.lock()?;
        let coll = g.data.get(name)
            .ok_or_else(|| StoreError::CollectionNotFound(name.to_string()))?;
        coll.get(id)
            .map(|doc| Record { id: id.to_string(), doc: doc.clone() })
            .ok_or_else(|| StoreError::NotFound(id.to_string()))
    }

    fn query(&self, collection: &str, query: &Query) -> Result<Vec<Record>, StoreError> {
        let name = Self::checked(collection)?;
        let g = self.lock()?;
        let declared = g.specs.get(name)
            .ok_or_else(|| StoreError::CollectionNotFound(name.to_string()))?;
        let coll = &g.data[name];
        let recs = |f: &dyn Fn(&str, &serde_json::Value) -> bool| {
            coll.iter().filter(|(id, doc)| f(id, doc))
                .map(|(id, doc)| Record { id: id.clone(), doc: doc.clone() })
                .collect::<Vec<_>>()
        };
        Ok(match query {
            Query::All => recs(&|_, _| true),
            Query::ById(want) => recs(&|id, _| id == want),
            Query::ByField { field, value } => {
                if !is_valid_identifier(field) {
                    return Err(StoreError::InvalidIdentifier(field.clone()));
                }
                if !declared.iter().any(|d| d == field) {
                    return Err(StoreError::FieldNotIndexed(field.clone()));
                }
                recs(&|_, doc| doc.get(field) == Some(value))
            }
        })
    }

    fn delete(&self, collection: &str, id: &str) -> Result<(), StoreError> {
        let name = Self::checked(collection)?;
        let mut g = self.lock()?;
        let coll = g.data.get_mut(name)
            .ok_or_else(|| StoreError::CollectionNotFound(name.to_string()))?;
        coll.remove(id); // absent → no-op
        Ok(())
    }
}
```

Then add contract + security tests (`#[cfg(test)]`), and register the manifest
in the host's `main.rs` as in §8 with
`implements: vec![("wyrtloom.persistence".into(), SemVer::new(0, 1, 0))]`,
`class: PluginClass::Safe` and `capabilities: vec![]` (a pure in-memory store
touches nothing, so it is Safe with no capabilities).
