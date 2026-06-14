# Development guide

This guide covers building, testing, and contributing to the Wyrtloom ecosystem:
the core monorepo (`wyrtloom`), the out-of-tree plugin repos, the dashboard API,
and the dashboard web SPA.

---

## 1. Repository layout and how the repos relate

The ecosystem is split across several repos that build together via Cargo **path
dependencies** with a commented **git fallback**:

```
wyrtloom/                      # core monorepo (this repo)
├── crates/core               # wyrtloom-core: the contract traits + types + security
├── crates/plugin-*           # in-tree reference plugins (workspace members)
├── src/                      # the `wyrtloom` host binary (main.rs, pipeline.rs)
└── Cargo.toml                # [workspace] with [workspace.dependencies]

wyrtloom-store-sqlite/         # out-of-tree: PersistenceProvider over SQLite
wyrtloom-users/                # out-of-tree: UserDirectory (argon2id) over a store
wyrtloom-clientauth-tofu/      # out-of-tree: ClientAuthScheme (TOFU, ed25519 + P-256)
wyrtloom-provider-nous/        # out-of-tree: LlmProvider for the Nous Portal
wyrtloom-dashboard-api/        # the frontend-agnostic HTTP API (axum)
wyrtloom-dashboard-web/        # the React + Vite SPA (one client of the API)
```

**Core is the contract.** `wyrtloom-core` defines every trait
(`PersistenceProvider`, `UserDirectory`, `ClientAuthScheme`, `LlmProvider`,
`KanbanBoard`, `CallLogger`, `SandboxRuntime`, `HumanEscalation`, `MessageBus`),
the shared types (`TaskId`, `Role`, `Money`, `SemVer`, `Timestamp`, …), the
canonical client-auth encoding (`client_auth::canonical_request`), and the
security module. Everything else implements those traits.

**Path dep + git fallback.** In-tree plugins are workspace members and inherit
deps (`wyrtloom-core = { workspace = true }`). Out-of-tree plugins reference core
by a sibling path with a commented, rev-pinned git fallback:

```toml
wyrtloom-core = { path = "../wyrtloom/crates/core" }
# wyrtloom-core = { git = "https://github.com/codepilots/wyrtloom.git", rev = "<sha>" }
```

So to build an out-of-tree plugin locally you need the `wyrtloom` monorepo
checked out **as a sibling directory** of it. For CI / out-of-tree consumers,
switch to the git form and pin a `rev`.

---

## 2. Toolchain

### Rust

Use the pinned stable toolchain from the hermes profile. Put its `cargo`/`rustc`
on `PATH` for the session:

```bash
export PATH="/home/autumn/.hermes/profiles/coder/home/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"
cargo --version   # cargo 1.96.0
```

All crates are `edition = "2021"`.

### TLS / pkg-config (provider plugins only)

The provider plugins make HTTPS calls, and their TLS choice determines whether
you need system libraries:

- **`plugin-provider-ollama`** (in-tree) uses the workspace `reqwest` with
  **default features**, which pulls **native-tls**. Building it therefore needs
  **`pkg-config` + OpenSSL** installed on the host. If you build the whole
  workspace and don't have OpenSSL, install pkg-config/OpenSSL dev packages, or
  build a specific crate that doesn't need it.
- **`wyrtloom-provider-nous`** (out-of-tree) and any new provider plugin use
  **rustls** (`reqwest` with `default-features = false`,
  `features = ["json", "blocking", "rustls-tls"]`), so they build with **no
  system OpenSSL / pkg-config**. Prefer rustls for new network plugins.

Crates with no network surface (the store, users, client-auth, the core) need no
system libraries — `rusqlite` is built with the `bundled` feature, so SQLite is
compiled in and there is no system-SQLite dependency.

### Node (web SPA)

The SPA targets **Node 22** with Vite + Vitest + React 19:

```bash
node --version    # v22.x
```

---

## 3. Building and testing per repo

Always have the Rust toolchain on `PATH` (§2) first.

### Core monorepo

```bash
cd wyrtloom

# A single crate (fast, avoids pulling the OpenSSL-dependent provider):
cargo test -p wyrtloom-core
cargo test -p plugin-kanban-sqlite

# The whole workspace (needs pkg-config/OpenSSL for the ollama provider):
cargo test --workspace

# Build + run the host binary:
cargo run            # boots the security module, verifies plugins, runs the demo pipeline
```

### Out-of-tree plugin repos

Each is its own crate; run from inside the repo (it resolves `wyrtloom-core` via
the sibling `../wyrtloom` path dep):

```bash
cd wyrtloom-store-sqlite   && cargo test
cd wyrtloom-users          && cargo test
cd wyrtloom-clientauth-tofu && cargo test
cd wyrtloom-provider-nous  && cargo test   # rustls — no system TLS needed
```

The storage-backed plugins (`users`, `clientauth-tofu`) carry
`wyrtloom-store-sqlite` as a **dev-dependency** and test against the real store,
so their tests exercise the full path end-to-end.

### Dashboard API

```bash
cd wyrtloom-dashboard-api
cargo test
cargo run    # see the crate's main.rs for provisioning (issues a single-use
             # bootstrap key for the first client's POST /api/enroll)
```

### Dashboard web SPA

```bash
cd wyrtloom-dashboard-web
npm install
npm run build          # tsc -b && vite build  (type-check + production build)
npm test               # vitest run
# or:
npx vitest             # watch mode while developing
```

The crypto interop tests (`src/crypto/canonical.test.ts`,
`src/crypto/query-signing.test.ts`) lock the signing format against the server's
golden vector — run them whenever you touch `canonical.ts`, `clientKey.ts`, or the
API client's URL building.

---

## 4. Conventions

### Test-first / contract tests

Write tests **before** the implementation, and test against the **real**
dependency, not a mock:

- A plugin is tested against the contract trait it implements, with a dedicated
  **security** test block alongside the functional tests (injection attempts,
  malformed/corrupt-on-disk data, traversal, replay/atomicity, timing). See the
  `tests` module in `wyrtloom-store-sqlite/src/lib.rs` for the canonical example
  (functional round-trips + a full set of injection/integrity/concurrency tests).
- Plugins layered on a store test through `wyrtloom-store-sqlite` (a
  dev-dependency), not a fake store.
- Provider/wire logic is factored into pure helpers
  (`build_chat_body`, `parse_chat_response`, `validate_base_url`,
  `read_bounded_body`, …) so it is unit-testable offline with no network.
- The signing format is guarded by an interop **golden vector** shared between the
  TS client and the Rust server — never change the canonical encoding without
  updating both sides and the vector.

### Code review + security audit

The repos are developed with explicit **code-review** and **security-audit**
passes; the `CHANGELOG.md` files record numbered findings (e.g. "finding 018 –
all kanban operations return Result; panics replaced by error handling", "finding
020 – manifest name character-set validation") and the `SECURITY.md` files state
each component's threat model, what is in/out of scope, and operational gotchas.
When you change behaviour:

- Re-read the relevant `SECURITY.md` and keep your change inside its threat model
  (or update the model deliberately).
- Preserve the established security invariants: parameterized SQL + validated
  identifiers, integrity-errors-not-panics, redacting `Debug` on secret types,
  `strip_control` on untrusted output, SSRF-safe URL parsing, constant-time
  secret comparison, low-s P-256, fail-closed on uncertainty.
- Add a test that demonstrates the fix/feature, and note the change in
  `CHANGELOG.md`.

See `docs/writing-a-plugin.md` for the per-plugin security requirements and
`docs/client-authoring.md` for the client-auth/signing contract.

### Commit / PR conventions

- The repos are Apache-2.0 (`LICENSE`), version `0.1.0`.
- Keep status/todo docs and `CHANGELOG.md` current as part of finishing a change
  in the same session; never leave the repo with failing tests or half-applied
  changes. Run the relevant `cargo test` / `vitest` before reporting a result.
- Commit or push only when asked. When a branch is ready, open a PR with `gh pr
  create` and a clear title and body summarising the change and any security
  considerations.
