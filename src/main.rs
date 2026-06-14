mod pipeline;

use std::sync::Arc;

use plugin_escalation_cli::{CliEscalation, ScriptedEscalation};
use plugin_kanban_sqlite::SqliteKanbanBoard;
use plugin_logger_sqlite::SqliteCallLogger;
use plugin_provider_ollama::OllamaProvider;
use plugin_sandbox_wasmtime::WasmtimeSandbox;
use wyrtloom_core::bootstrap::Bootstrapper;
use wyrtloom_core::plugin::{Capability, PluginClass, PluginManifest};
use wyrtloom_core::profile::TaskProfile;
use wyrtloom_core::sandbox::{ResourceLimits, SafeModule, SandboxRuntime};
use wyrtloom_core::types::SemVer;

use pipeline::{Pipeline, PipelineOutcome};

/// Open the kanban board on disk when `env_var` is set to a path, else in-memory.
fn open_kanban(env_var: &str) -> anyhow::Result<SqliteKanbanBoard> {
    match std::env::var(env_var) {
        Ok(path) if !path.is_empty() => {
            println!("[boot] kanban DB: {path}");
            Ok(SqliteKanbanBoard::open(&path)?)
        }
        _ => Ok(SqliteKanbanBoard::in_memory()?),
    }
}

/// Open the call logger on disk when `env_var` is set to a path, else in-memory.
fn open_logger(env_var: &str) -> anyhow::Result<SqliteCallLogger> {
    match std::env::var(env_var) {
        Ok(path) if !path.is_empty() => {
            println!("[boot] logger DB: {path}");
            Ok(SqliteCallLogger::open(&path)?)
        }
        _ => Ok(SqliteCallLogger::in_memory()?),
    }
}

fn main() -> anyhow::Result<()> {
    println!("🌿 Wyrtloom v0.1 — The Seed");
    println!("================================\n");

    // ── Stage 1-8: Bootstrap sequence ────────────────────────────────────────
    let mut bootstrapper = Bootstrapper::new();

    bootstrapper.register_plugin(
        PluginManifest {
            name: "plugin-kanban-sqlite".into(),
            version: SemVer::new(0, 2, 0),
            class: PluginClass::Unsafe,
            capabilities: vec![Capability::FileWrite(".".into())],
            // Declares 0.2.0 — provides the additive `KanbanBoard::list` (read-through-trait).
            implements: vec![("wyrtloom.kanban".into(), SemVer::new(0, 2, 0))],
        },
        || Arc::new(()),
    );
    bootstrapper.register_plugin(
        PluginManifest {
            name: "plugin-provider-ollama".into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Unsafe,
            capabilities: vec![Capability::Network("localhost".into())],
            implements: vec![("wyrtloom.provider".into(), SemVer::new(0, 1, 0))],
        },
        || Arc::new(()),
    );
    bootstrapper.register_plugin(
        PluginManifest {
            name: "plugin-sandbox-wasmtime".into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Safe,
            capabilities: vec![],
            implements: vec![("wyrtloom.sandbox".into(), SemVer::new(0, 1, 0))],
        },
        || Arc::new(()),
    );
    bootstrapper.register_plugin(
        PluginManifest {
            name: "plugin-logger-sqlite".into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Unsafe,
            capabilities: vec![Capability::FileWrite(".".into())],
            implements: vec![("wyrtloom.logger".into(), SemVer::new(0, 1, 0))],
        },
        || Arc::new(()),
    );
    bootstrapper.register_plugin(
        PluginManifest {
            name: "plugin-escalation-cli".into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Safe,
            capabilities: vec![],
            implements: vec![("wyrtloom.escalation".into(), SemVer::new(0, 1, 0))],
        },
        || Arc::new(()),
    );
    bootstrapper.register_plugin(
        PluginManifest {
            name: "plugin-bus-tokio".into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Safe,
            capabilities: vec![],
            implements: vec![("wyrtloom.bus".into(), SemVer::new(0, 1, 0))],
        },
        || Arc::new(()),
    );

    let sys = bootstrapper.run().map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("[boot] Security + all plugins verified ✓");

    let audit = sys.security.audit_log_snapshot();
    println!("[boot] {} security decisions recorded", audit.len());

    // ── Instantiate plugin implementations ────────────────────────────────────
    // Persist to an on-disk DB when WYRTLOOM_KANBAN_DB / WYRTLOOM_LOGGER_DB are set,
    // so a separate process (e.g. the dashboard) can observe the board; otherwise
    // stay in-memory as before.
    let kanban   = Arc::new(open_kanban("WYRTLOOM_KANBAN_DB")?);
    // OllamaProvider::new() is now fallible — URL validated at construction.
    let provider = Arc::new(OllamaProvider::default_local());
    let logger   = Arc::new(open_logger("WYRTLOOM_LOGGER_DB")?);
    // WasmtimeSandbox::new() is explicitly fallible; no Default impl (finding 019).
    let sandbox  = WasmtimeSandbox::new()?;

    println!("[boot] All plugins instantiated ✓");

    // ── Demo: sandbox isolation test ──────────────────────────────────────────
    println!("\n--- Sandbox isolation demo ---");
    let wat_ok = r#"
(module
  (memory (export "memory") 1)
  (func (export "run") (param i32 i32) (result i64) i64.const 0)
)
"#;
    let wasm_bytes = wat::parse_str(wat_ok)?;
    let result = sandbox.execute(SafeModule::new(wasm_bytes), vec![], ResourceLimits::default());
    println!("[sandbox] SAFE module executed, result ok = {}", result.is_ok());

    let bad_wat = r#"
(module
  (import "env" "read_file" (func (param i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "run") (param i32 i32) (result i64) i64.const 0)
)
"#;
    let bad_wasm = wat::parse_str(bad_wat)?;
    let isolation_result = sandbox.execute(
        SafeModule::new(bad_wasm), vec![], ResourceLimits::default(),
    );
    println!(
        "[sandbox] Module with host import isolated = {}",
        isolation_result.is_err()
    );

    // ── Demo: task pipeline ────────────────────────────────────────────────────
    println!("\n--- Task pipeline demo ---");

    let escalation: Arc<dyn wyrtloom_core::escalation::HumanEscalation> =
        if std::env::var("WYRTLOOM_INTERACTIVE").is_ok() {
            Arc::new(CliEscalation::new())
        } else {
            Arc::new(ScriptedEscalation::stop())
        };

    let pipeline = Pipeline {
        kanban:    kanban.clone(),
        provider:  provider.clone(),
        logger:    logger.clone(),
        escalation,
        profile:   TaskProfile::default_v01(),
        agent_id:  "agent:wyrtloom-v01".into(),
    };

    let prompt = r#"What is 2 + 2? Answer with {"status":"done","result":"4"}"#;
    println!("[pipeline] Running task: {}", prompt);

    match pipeline.run("arithmetic-demo", prompt) {
        PipelineOutcome::Done { task_id, result } => {
            println!("[pipeline] Task {} DONE: {}", task_id, result);
        }
        PipelineOutcome::Stopped { task_id } => {
            println!("[pipeline] Task {} STOPPED by human", task_id);
        }
        PipelineOutcome::Blocked { task_id, reason } => {
            println!("[pipeline] Task {} BLOCKED: {}", task_id, reason);
        }
    }

    println!("\n[logger] SQLite call logger recording every LLM call with tokens + cost.");
    println!("\n🌿 Wyrtloom v0.1 boot complete.");
    Ok(())
}
