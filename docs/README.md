# Wyrtloom documentation

Wyrtloom is a token-efficient, security-first multi-agent framework: a minimal Rust
**core kernel** plus swappable **plugins behind versioned contracts**, each plugin in
its own repository. These hub docs cover the cross-cutting, ecosystem-level material;
each component documents itself in its own repo (linked below).

## Start here

- **[getting-started.md](getting-started.md)** — what Wyrtloom is, the repo map, building the
  workspace, and running the v0.1 demo.

## Architecture & contracts (developers)

- **[architecture.md](architecture.md)** — the core/plugin model, the three design lenses
  (Bootstrap · Ecosystem · Comprehension), the bootstrap sequence, the repo/dependency map,
  and contract versioning.
- **[contracts.md](contracts.md)** — reference for every core contract (`KanbanBoard`,
  `LlmProvider`, `PersistenceProvider`, `UserDirectory`, `ClientAuthScheme`, `CallLogger`,
  `SandboxRuntime`, `MessageBus`, `HumanEscalation`) with signatures, invariants, and which
  plugin implements each.
- **[writing-a-plugin.md](writing-a-plugin.md)** — how to author a plugin in its own repo
  (conventions, the SQLite pattern, the manifest/capability model, security requirements,
  a worked skeleton).
- **[development.md](development.md)** — toolchain, repo layout, per-repo build/test, and the
  test-first / code-review / security-audit conventions.

## Security

- **[security-overview.md](security-overview.md)** — ecosystem security model that ties
  together each repo's own `SECURITY.md` (threat model, two-layer auth, the SecurityModule
  root of trust, capability model, known limitations).
- Core security model: [`../SECURITY.md`](../SECURITY.md).

## Component documentation (each lives in its own repo)

Per the one-repo-per-implementation rule, each plugin and the dashboard document themselves:

| Component | Repo | Docs |
|-----------|------|------|
| Dashboard API (deploy, HTTP API, client authoring) | `wyrtloom-dashboard-api` | [deployment](https://github.com/codepilots/wyrtloom-dashboard-api/blob/main/docs/deployment.md) · [api-reference](https://github.com/codepilots/wyrtloom-dashboard-api/blob/main/docs/api-reference.md) · [client-authoring](https://github.com/codepilots/wyrtloom-dashboard-api/blob/main/docs/client-authoring.md) |
| Dashboard web SPA (user guide) | `wyrtloom-dashboard-web` | [dashboard-user-guide](https://github.com/codepilots/wyrtloom-dashboard-web/blob/main/docs/dashboard-user-guide.md) |
| Config loader (`wyrtloom.toml`) | `wyrtloom-config` | [configuration](https://github.com/codepilots/wyrtloom-config/blob/main/docs/configuration.md) · [README](https://github.com/codepilots/wyrtloom-config) |
| Persistence (document store) | `wyrtloom-store-sqlite` | [README](https://github.com/codepilots/wyrtloom-store-sqlite) · [SECURITY](https://github.com/codepilots/wyrtloom-store-sqlite/blob/main/SECURITY.md) |
| User directory (argon2 + RBAC) | `wyrtloom-users` | [README](https://github.com/codepilots/wyrtloom-users) · [SECURITY](https://github.com/codepilots/wyrtloom-users/blob/main/SECURITY.md) |
| Client auth (TOFU ed25519/P-256) | `wyrtloom-clientauth-tofu` | [README](https://github.com/codepilots/wyrtloom-clientauth-tofu) · [SECURITY](https://github.com/codepilots/wyrtloom-clientauth-tofu/blob/main/SECURITY.md) |
| LLM provider (Nous Portal) | `wyrtloom-provider-nous` | [README](https://github.com/codepilots/wyrtloom-provider-nous) · [SECURITY](https://github.com/codepilots/wyrtloom-provider-nous/blob/main/SECURITY.md) |

In-tree v0.1 plugins (Ollama provider, SQLite kanban/logger, wasmtime sandbox, tokio bus, CLI
escalation) and the W1–W13 "Conversation" plugins live under `crates/` here, each with its own
`README`/`DESIGN.md`.

## Specifications

- [`../Specification`](../Specification) — the full v0.1 spec (contracts, roadmap, security model).
- [`../SoftDevSpec.md`](../SoftDevSpec.md) — the comprehension-first development addendum (W1–W13).
