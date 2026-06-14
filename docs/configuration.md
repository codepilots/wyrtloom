# Configuration reference — `wyrtloom.toml`

Wyrtloom is configured by a single `wyrtloom.toml` file, parsed by the
`wyrtloom-config` crate into the strongly-typed core domain objects. The
dashboard API reads and writes exactly this file (via `GET`/`PUT /api/config`,
Admin-only) and uses its `[security]` table as the runtime `SecurityPolicy`.

See also: [deployment.md](deployment.md) for how the API loads this file, and
[getting-started.md](getting-started.md) for the ecosystem overview.

## File shape

A `wyrtloom.toml` has two parts: one `[security]` table and zero or more
`[[plugin]]` entries.

### `[security]` → `SecurityPolicy`

| Key | Type | Meaning |
|-----|------|---------|
| `file_read_prefixes` | array of strings | Path prefixes plugins may read under. |
| `file_write_prefixes` | array of strings | Path prefixes plugins may write under. |
| `network_allowlist` | array of strings | Hosts plugins may reach. |
| `allow_shell` | bool | Whether shell execution is permitted. |
| `allow_git` | bool | Whether git operations are permitted. |

All keys are optional and default to empty / `false`, i.e. the **default policy
is fully deny**. Path prefixes are screened for `..` traversal during validation
(network hosts are not — they are hosts, not paths).

### `[[plugin]]` → `PluginEntry`

Each `[[plugin]]` entry pairs a core `PluginManifest` with an `enabled` flag and a
free-form `settings` table.

| Key | Type | Required | Meaning |
|-----|------|----------|---------|
| `name` | string | yes | Plugin name; must match `[a-z0-9_-]{1,64}`. |
| `version` | string | yes | Canonical `MAJOR.MINOR.PATCH` (no signs, no leading zeros). |
| `class` | string | yes | `"safe"` or `"unsafe"`. |
| `enabled` | bool | no (default `true`) | Whether the operator has enabled this plugin. |
| `implements` | array of `{ contract, version }` | no | Interface contracts the plugin provides, with versions. |
| `capabilities` | array of capability tables | no | System capabilities the plugin needs (must be empty for `safe`). |
| `[plugin.settings]` | table | no | Free-form per-plugin settings (e.g. `db_path`, `base_url`). |

#### Capabilities

Each capability is a table with a `kind` and, for file/network kinds, a `target`:

| `kind` | `target` | Core `Capability` |
|--------|----------|-------------------|
| `file_read` | path (required) | `FileRead(path)` |
| `file_write` | path (required) | `FileWrite(path)` |
| `network` | host (required) | `Network(host)` |
| `shell` | — | `Shell` |
| `git` | — | `Git` |

## Validation rules

Parsing is strict, and validation is a separate, deterministic step
(`wyrtloom_config::validate`). The PUT-config endpoint runs **both** parse and
validate before saving.

Strict parsing (`deny_unknown_fields`):

- Unknown keys in the `[security]`, `[[plugin]]`, top-level, `implements`, or
  capability tables are a **hard parse error** — a typo'd, security-relevant key
  (e.g. `allow_shel`) fails rather than silently falling back to a default. The
  `[plugin.settings]` table is the **only** free-form region.
- `version` strings must be canonical `MAJOR.MINOR.PATCH` decimals — no signs, no
  whitespace, no leading zeros (a plain `0` component is fine).
- `class` must be exactly `"safe"` or `"unsafe"`; capability `kind` must be one of
  the five known kinds.

Validation (`validate()`), checked in order:

1. **Name well-formed** — every plugin name matches `[a-z0-9_-]{1,64}`.
2. **SAFE ⇒ no capabilities** — a `safe` plugin that declares any capability is
   rejected (a safe plugin that needs system access is a contradiction).
3. **Traversal screening** — file-capability paths, **every** string value in a
   plugin's `settings` table (at any depth, including nested tables and arrays),
   and the `[security]` file prefixes are all rejected if they contain a `..`
   component. (`network_allowlist` hosts are intentionally left unscreened.)
4. **Contract-version compatibility** — every declared `implements` contract
   version must be compatible with the core's `CoreContractVersions::v0_1()`. A
   major bump or an unknown contract is rejected; a minor that is too low for what
   the core requires is reported specifically.

Errors are opaque (`ConfigError`) and do not leak internal filesystem or parser
detail.

## Environment variables

The config file is the primary mechanism, but several environment variables
affect the demo binary, the dashboard, and the providers:

| Variable | Used by | Purpose |
|----------|---------|---------|
| `WYRTLOOM_KANBAN_DB` | `wyrtloom` demo (`src/main.rs`) | Path to a SQLite Kanban DB; in-memory if unset. |
| `WYRTLOOM_LOGGER_DB` | `wyrtloom` demo | Path to a SQLite call-logger DB; in-memory if unset. |
| `WYRTLOOM_ADMIN_PASSWORD` | dashboard API `--create-admin` | Password for the admin being provisioned. Set **inline**, do not export. |
| `WYRTLOOM_DEBUG` | `wyrtloom` demo pipeline | When set, echoes model-derived content (off by default). |
| `NOUS_API_KEY` | `wyrtloom-provider-nous` | Bearer token for the hosted Nous Research provider. |

(The dashboard API takes its database paths from CLI flags — `--kanban-db`,
`--store`, `--logger-db` — rather than the `WYRTLOOM_*_DB` variables, which are
specific to the demo binary. See [deployment.md](deployment.md).)

## A complete, annotated example

```toml
# wyrtloom.toml — example configuration.

# ── Security policy ────────────────────────────────────────────────────────
# The [security] table becomes the runtime SecurityPolicy. Omitted keys default
# to deny (empty lists / false), so list ONLY what plugins are allowed to do.
[security]
# Path prefixes plugins may read under. Screened for `..` traversal.
file_read_prefixes  = ["/var/lib/wyrtloom", "/tmp"]
# Path prefixes plugins may write under.
file_write_prefixes = ["/var/lib/wyrtloom"]
# Hosts plugins may reach (hosts, not paths — not traversal-screened).
network_allowlist   = ["localhost"]
# Coarse switches for shell / git access.
allow_shell = false
allow_git   = true

# ── An UNSAFE plugin: the SQLite Kanban board ──────────────────────────────
[[plugin]]
name    = "kanban-sqlite"      # [a-z0-9_-]{1,64}
version = "0.2.0"              # canonical MAJOR.MINOR.PATCH
class   = "unsafe"             # needs real file access
enabled = true                # defaults to true if omitted
# Contracts this plugin provides; versions must be core-compatible.
implements = [
    { contract = "wyrtloom.kanban", version = "0.2.0" },
]
# Declared capabilities (must be empty for `safe` plugins).
capabilities = [
    { kind = "file_read",  target = "/var/lib/wyrtloom" },
    { kind = "file_write", target = "/var/lib/wyrtloom" },
]

# Free-form settings — the ONLY region that accepts arbitrary keys. Every
# string value here is still screened for `..` traversal.
[plugin.settings]
db_path = "/var/lib/wyrtloom/kanban.db"

# ── An UNSAFE provider plugin reaching the network ─────────────────────────
[[plugin]]
name    = "provider-ollama"
version = "0.1.0"
class   = "unsafe"
enabled = true
implements = [
    { contract = "wyrtloom.provider", version = "0.1.0" },
]
capabilities = [
    { kind = "network", target = "localhost" },
]

[plugin.settings]
base_url = "http://localhost:11434"

# ── A SAFE plugin: no capabilities permitted ───────────────────────────────
[[plugin]]
name    = "workflow-profile"
version = "0.1.0"
class   = "safe"              # safe => MUST declare no capabilities
enabled = false               # disabled in this example
implements = [
    { contract = "wyrtloom.provider", version = "0.1.0" },
]
```
