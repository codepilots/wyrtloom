# Dashboard user guide

This guide is for **end users** of the Wyrtloom web dashboard
(`wyrtloom-dashboard-web`) — the React single-page app that talks to the
`wyrtloom-dashboard-api` service. It walks through first-run enrollment, login,
each view, the role model, and how authentication errors are handled.

For standing the dashboard up, see [deployment.md](deployment.md). For the
ecosystem overview, see [getting-started.md](getting-started.md).

## First run: client enrollment

Before the app can talk to the API at all, this browser must enroll itself as a
signing client. This happens **once per device**.

On first run you will see an **Enroll** screen. Your operator will give you a
**single-use bootstrap key** (issued out-of-band; see [deployment.md](deployment.md)).
Paste it in. The app then:

- generates a **non-extractable** WebCrypto ECDSA P-256 keypair and stores it in
  the browser's IndexedDB (the private key can never be read back, even by a
  script);
- `POST`s its public key plus your bootstrap key to `/api/enroll`;
- receives a `client_id` and uses the keypair to **sign every later request**.

The bootstrap key is used once and is never persisted by the app. After
enrollment the Enroll screen does not appear again on this device. If you switch
devices or clear browser storage, you will need a fresh bootstrap key from your
operator.

## Login

After enrollment, sign in with your **username and password** (`POST /api/login`).
On success the API returns a short-lived bearer **session token** (default TTL
30 minutes), which the app holds **in memory only** — it is never written to
`localStorage`, `sessionStorage`, or cookies, so it does not survive a page
reload. Reloading the page means logging in again.

`POST /api/logout` revokes the token server-side and drops it locally.

## The role model

Access is governed by three **non-hierarchical** roles. Holding a higher role
does **not** imply the lower ones — each is granted explicitly. (A provisioned
admin is given all three.)

| Role | Can do |
|------|--------|
| **Viewer** | Read the board and individual tasks; view plugins; log out. |
| **Operator** | Everything a Viewer can, **plus** create / transition / claim / block tasks. |
| **Admin** | View and edit config; view logs; view the audit chain. |

The top navigation only exposes the views your role can use, and write actions
are hidden when you lack the Operator role. These UI affordances are **advisory**
only — the API independently re-fetches your current roles and enforces RBAC on
**every** request, so changing a role or disabling an account takes effect on the
very next request regardless of an outstanding token.

## The Board

The Board is the heart of the dashboard: the seven Kanban columns, in order:

```
Backlog → Todo → Ready → Running → Blocked → Done → Archived
```

Task cards show the title, the actor, a dependency count, and any block reason.
A detail drawer shows the task's full **history** (every state change with actor
and timestamp).

Operators can act on tasks:

- **Create** a new task (with optional dependencies on other tasks).
- **Transition** a task to a new state (only legal transitions are accepted; an
  illegal one is rejected).
- **Claim** a task — a task in `Running` is claimed by exactly one worker; a
  second claim fails.
- **Block** a task — blocking requires a reason.

Viewers see the board read-only; write affordances are hidden, and any server
`403` is surfaced clearly.

## Config (Admin)

The Config view shows a structured, read-only summary of the security policy
(`file_read_prefixes`, `file_write_prefixes`, `network_allowlist`, `allow_shell`,
`allow_git`) plus an editable **raw-TOML** form, backed by `GET`/`PUT /api/config`.
The form has client-side sanity checks, but the **server re-parses and validates
authoritatively** before saving — an invalid config is rejected with a generic
error (internal detail is logged server-side, never echoed). See
[configuration.md](configuration.md) for the schema and validation rules.

## Plugins

The Plugins view is a manifest/capability table listing each configured plugin's
name, version, class (`Safe`/`Unsafe`), enabled flag, and declared capabilities.
It is available to **Viewers** and above (read-only).

## Logs (Admin)

The Logs view shows the call-logger entries — every LLM call recorded with its
provider, model, token counts, cost, task, outcome, and timestamp — as a table.
If the API was started without a `--logger-db`, this list is empty.

## Audit (Admin)

The Audit view shows the tamper-evident audit entries plus a **`chain_verified`**
status returned by the API's `verify_chain`. A verified chain means the audit log
has not been tampered with in place since it was written. Every authenticated
request and security decision is stamped into this chain.

## Authentication errors

Two HTTP statuses are handled globally by the app:

- **`401` (session expired / not authenticated)** — the in-memory token is
  dropped and you are routed back to **Login** with a notice. Sign in again.
- **`403` (not authorized)** — your roles do not permit this action. An inline
  "not authorized" message is shown; the rest of the app keeps working. Ask your
  operator if you believe you should have access (roles can be changed
  server-side and take effect on your next request).
