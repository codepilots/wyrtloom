# Wyrtloom

A token-efficient, security-first multi-agent framework: a minimal Rust **core kernel**
plus swappable **plugins behind versioned contracts**, each plugin in its own repository.
Kanban is the single source of truth; the language model is called only when no cheaper
mechanism will do.

## Documentation

Full documentation is in **[`docs/`](docs/)** — start with
**[getting-started](docs/getting-started.md)**, then
[architecture](docs/architecture.md), [contracts](docs/contracts.md),
[writing-a-plugin](docs/writing-a-plugin.md), and the
[security overview](docs/security-overview.md). Each plugin and the dashboard document
themselves in their own repos (linked from the [docs index](docs/README.md)).

## Build & run

```bash
cargo build
cargo run        # bootstrap → sandbox-isolation demo → task pipeline demo
```

See [docs/development.md](docs/development.md) for the toolchain and per-repo build/test.

## Security

The system has been through two adversarial security-audit rounds. See
[`SECURITY.md`](SECURITY.md) (core) and [docs/security-overview.md](docs/security-overview.md)
(ecosystem). License: Apache-2.0.
