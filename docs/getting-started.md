# Getting started with Wyrtloom

This is the user/operator entry point for the Wyrtloom ecosystem. It explains
what Wyrtloom is, how the repositories fit together, how to build the core, and
how to run the v0.1 demo. From here:

- [configuration.md](https://github.com/codepilots/wyrtloom-config/blob/main/docs/configuration.md) — the `wyrtloom.toml` reference.
- [deployment.md](https://github.com/codepilots/wyrtloom-dashboard-api/blob/main/docs/deployment.md) — operating the dashboard API + web SPA.
- [dashboard-user-guide.md](https://github.com/codepilots/wyrtloom-dashboard-web/blob/main/docs/dashboard-user-guide.md) — using the dashboard as an
  end user.

## What Wyrtloom is

Wyrtloom is a **token-efficient, security-first multi-agent framework**. Its
guiding belief is that the language model is the most expensive consultant in the
building, so it is called only when no cheaper, deterministic mechanism will do.
Three principles shape everything:

- **Minimal core, everything else a plugin.** The Rust core is the smallest
  kernel that can bootstrap the system and guarantee a stable, portable
  ecosystem. Every capability — LLM providers, storage, sandbox runtime, the
  message bus, escalation UIs — is a plugin behind a versioned interface
  contract. Each swappable implementation ships in **its own repository**.
- **Interfaces are sacred; implementations are free.** Contracts are versioned
  with semantic versioning from the first commit. The shape of a message, a
  capability declaration, or a task handoff is a public promise; what sits behind
  it can be swapped.
- **Security is a first-class citizen.** Security is not a plugin you add later —
  it is the root of trust that initialises first, verifies the loader and sandbox
  before they run, enforces capability grants, and stamps every security decision
  into a tamper-evident audit log.

The **Kanban board is the single source of truth** for task state. Tasks move
through `backlog → todo → ready → running → blocked → done → archived`, and the
board — not chatter between agents — is how everyone knows the state of the
world. This is borrowed from Hermes Agent and is deliberately chosen to remove
the wasteful back-and-forth that inflates multi-agent token costs.

Plugins come in two classes:

- **SAFE** plugins run fully sandboxed in WebAssembly (wasmtime) and declare no
  system capabilities. A SAFE plugin that requests any capability is rejected at
  load.
- **UNSAFE** plugins need real system access (file I/O, network, shell, git) and
  must declare each required capability up front, in the manner of an app
  requesting permissions.

The full vision and the v0.1 technical specification live in the root
[`Specification`](../Specification) document.

## The repo map

Wyrtloom is a multi-repo ecosystem. The core kernel and the v0.1 demo plugins
live in the `wyrtloom` repository (a Cargo workspace); the dashboard and the
swappable service-side implementations live in sibling repositories.

### Core repository — `wyrtloom`

A Cargo workspace whose members are listed in the root
[`Cargo.toml`](../Cargo.toml):

- `crates/core` (`wyrtloom-core`) — the kernel: the security/trust module, plugin
  loader + manifest, sandbox interface, message-bus primitive, Kanban state
  machine, and the interface contracts for the LLM provider, call logger, human
  escalation, persistence, users, and client auth.
- `crates/plugin-kanban-sqlite` — SQLite-backed Kanban board (`wyrtloom.kanban`).
- `crates/plugin-provider-ollama` — local Ollama LLM provider
  (`wyrtloom.provider`).
- `crates/plugin-sandbox-wasmtime` — the wasmtime WASM sandbox runtime
  (`wyrtloom.sandbox`), core-controlled.
- `crates/plugin-logger-sqlite` — SQLite call logger (`wyrtloom.logger`).
- `crates/plugin-escalation-cli` — CLI human escalation (`wyrtloom.escalation`).
- `crates/plugin-bus-tokio` — in-process Tokio message bus (`wyrtloom.bus`).
- `crates/plugin-workflow-profile` and the other `plugin-*` crates — additional
  workflow/profile and ladder/ledger plugins.
- The root crate `wyrtloom` (`src/main.rs`) — the **v0.1 demo binary** that wires
  the plugins together and runs the bootstrap + pipeline + sandbox demos.

### Satellite repositories (siblings of `wyrtloom`)

These are checked out alongside `wyrtloom` (e.g. `../wyrtloom-config`):

- **`wyrtloom-config`** — the reusable `wyrtloom.toml` schema + loader. Turns the
  config file into the typed core domain objects (`SecurityPolicy`,
  `PluginManifest`, `Capability`). See [configuration.md](https://github.com/codepilots/wyrtloom-config/blob/main/docs/configuration.md).
- **`wyrtloom-store-sqlite`** — the SQLite persistence provider
  (`wyrtloom.persistence`): users, clients, and session revocations.
- **`wyrtloom-users`** — the argon2 user directory (`wyrtloom.users`).
- **`wyrtloom-clientauth-tofu`** — the trust-on-first-use ed25519/P-256 client
  authentication scheme (`wyrtloom.client_auth`).
- **`wyrtloom-provider-nous`** — a hosted Nous Research LLM provider plugin
  (`wyrtloom.provider`), an alternative to the local Ollama provider; reads
  `NOUS_API_KEY`.
- **`wyrtloom-dashboard-api`** — the secure, frontend-agnostic axum HTTP API that
  composes the storage / user / client-auth / kanban / config / logger crates
  behind a default-deny, RBAC-gated router. See [deployment.md](https://github.com/codepilots/wyrtloom-dashboard-api/blob/main/docs/deployment.md).
- **`wyrtloom-dashboard-web`** — the React + Vite + TypeScript single-page
  dashboard, one client of the API. See
  [dashboard-user-guide.md](https://github.com/codepilots/wyrtloom-dashboard-web/blob/main/docs/dashboard-user-guide.md).

## Building the core

The Rust toolchain is not on the default `PATH` in this environment. Put it on
`PATH` first:

```sh
export PATH="/home/autumn/.hermes/profiles/coder/home/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"
```

Then build and test the workspace from the `wyrtloom` repo root:

```sh
cargo build
cargo test
```

### A note on `pkg-config` (the Ollama provider)

`plugin-provider-ollama` depends on `reqwest` with its default features, which
pull in native TLS. Building it therefore needs the **system `pkg-config` and
TLS development headers** (e.g. `pkg-config` + `libssl-dev` on Debian/Ubuntu) to
be installed, or the build will fail while compiling the TLS backend. If you only
want the dashboard side of the ecosystem, the hosted provider crate
`wyrtloom-provider-nous` is configured with rustls and needs no system OpenSSL /
`pkg-config`.

## Running the v0.1 demo

The root `wyrtloom` binary is "v0.1 — The Seed." It boots the system through the
defined sequence, then runs a sandbox-isolation demo and a single-task pipeline:

```sh
cargo run
```

You will see, in order:

1. The bootstrap sequence — security self-check first, then every plugin
   verified against the security gate, with the number of recorded security
   decisions printed.
2. A **sandbox isolation demo** — a SAFE WASM module runs successfully, while a
   module that tries to import a host function (`read_file`) is isolated and
   fails closed.
3. A **task pipeline demo** — a task is created on the Kanban board and run
   through the `parse → plan → execute → verify` pipeline, calling the LLM
   provider at the decision point and logging the call (tokens + cost).

Useful environment variables for the demo (all optional):

- `WYRTLOOM_KANBAN_DB` — path to a SQLite file for the Kanban board, so a
  separate process (e.g. the dashboard) can observe the same board. Defaults to
  in-memory.
- `WYRTLOOM_LOGGER_DB` — path to a SQLite file for the call logger. Defaults to
  in-memory.
- `WYRTLOOM_INTERACTIVE` — when set, the pipeline uses the interactive CLI human
  escalation instead of the scripted "stop" escalation.
- `WYRTLOOM_DEBUG` — when set, the pipeline echoes model-derived content (off by
  default so model output is not dumped to logs).

The Ollama provider talks to a local Ollama instance on `localhost`; without one
running, the pipeline still demonstrates the bootstrap, security, and sandbox
flow.

## The dashboard

The demo binary is a CLI. For a graphical, multi-user, RBAC-controlled view of
the Kanban board, plugins, logs, and the audit chain, run the **dashboard**: the
`wyrtloom-dashboard-api` service plus the `wyrtloom-dashboard-web` SPA. Point the
dashboard's `--kanban-db` (and optionally `--logger-db`) at the same SQLite files
you passed to the demo via `WYRTLOOM_KANBAN_DB` / `WYRTLOOM_LOGGER_DB` to observe
live board state.

- Operators: see [deployment.md](https://github.com/codepilots/wyrtloom-dashboard-api/blob/main/docs/deployment.md) to build, provision, and run it.
- End users: see [dashboard-user-guide.md](https://github.com/codepilots/wyrtloom-dashboard-web/blob/main/docs/dashboard-user-guide.md).
