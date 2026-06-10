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

fn main() -> anyhow::Result<()> {
    println!("🌿 Wyrtloom v0.1 — The Seed");
    println!("================================\n");

    // ── Stage 1-8: Bootstrap sequence ────────────────────────────────────────
    let mut bootstrapper = Bootstrapper::new();

    bootstrapper.register_plugin(
        PluginManifest {
            name: "plugin-kanban-sqlite".into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Unsafe,
            capabilities: vec![Capability::FileWrite(".".into())],
            implements: vec![("wyrtloom.kanban".into(), SemVer::new(0, 1, 0))],
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
    // Comprehension-first workflow (SoftDevSpec.md addendum): a pure
    // plugin-layer construct that composes the locked core contracts —
    // it implements no core contract of its own and needs no capability.
    bootstrapper.register_plugin(
        PluginManifest {
            name: "plugin-workflow-conversation".into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Safe,
            capabilities: vec![],
            implements: vec![],
        },
        || Arc::new(()),
    );
    bootstrapper.register_plugin(
        PluginManifest {
            name: "plugin-workflow-sqlite".into(),
            version: SemVer::new(0, 1, 0),
            class: PluginClass::Unsafe,
            capabilities: vec![Capability::FileWrite(".".into())],
            implements: vec![],
        },
        || Arc::new(()),
    );

    let sys = bootstrapper.run().map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("[boot] Security + all plugins verified ✓");

    let audit = sys.security.audit_log_snapshot();
    println!("[boot] {} security decisions recorded", audit.len());

    // ── Instantiate plugin implementations ────────────────────────────────────
    let kanban   = Arc::new(SqliteKanbanBoard::in_memory()?);
    // OllamaProvider::new() is now fallible — URL validated at construction.
    let provider = Arc::new(OllamaProvider::default_local());
    let logger   = Arc::new(SqliteCallLogger::in_memory()?);
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
        gating:    None,
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

    // ── Demo: comprehension-first workflow (SoftDevSpec addendum) ─────────────
    println!("\n--- Comprehension workflow demo ---");
    {
        use plugin_escalation_cli::ScriptedEscalation;
        use plugin_workflow_conversation::audit::WorkflowAudit;
        use plugin_workflow_conversation::coverage::{Concept, CoverageMap, CreditSource};
        use plugin_workflow_conversation::gate::GateEngine;
        use plugin_workflow_conversation::workflow::WorkflowProfile;
        use plugin_workflow_sqlite::SqliteWorkflowStore;
        use pipeline::GatedWorkflow;

        let mut profile = WorkflowProfile::conversation_v01("human:cli".into());
        profile.gates[0].concepts_in_play.push(Concept {
            id: "arithmetic-contract".into(),
            component: "pipeline".into(),
            summary: "the demo task's input/output contract".into(),
        });
        profile.validate().map_err(|e| anyhow::anyhow!("{}", e))?;
        println!("[workflow] Profile '{}' validated: {} stages, {} gates", profile.id,
                 profile.stages.len(), profile.gates.len());

        // The same pipeline, now gated: Ready→Running and Running→Done pass
        // through the gate engine — digest first, then the human's approval.
        let gated_pipeline = Pipeline {
            kanban:    kanban.clone(),
            provider:  provider.clone(),
            logger:    logger.clone(),
            escalation: Arc::new(ScriptedEscalation::stop()),
            profile:   TaskProfile::default_v01(),
            agent_id:  "agent:wyrtloom-v01".into(),
            gating: Some(GatedWorkflow {
                engine: GateEngine {
                    kanban: kanban.clone(),
                    escalation: Arc::new(ScriptedEscalation::chose("approve")),
                    audit: WorkflowAudit::new(logger.clone()),
                },
                profile,
                reader: "human:cli".into(),
                // No calibration history yet → richest digest form.
                reader_calibration: 0.0,
            }),
        };

        match gated_pipeline.run("gated-arithmetic-demo", prompt) {
            PipelineOutcome::Done { task_id, result } => {
                println!("[workflow] Gated task {} DONE: {}", task_id, result);
            }
            PipelineOutcome::Stopped { task_id } => {
                println!("[workflow] Gated task {} STOPPED (gate or block)", task_id);
            }
            PipelineOutcome::Blocked { task_id, reason } => {
                println!("[workflow] Gated task {} BLOCKED: {}", task_id, reason);
            }
        }

        // Workflow state persists through the SQLite store.
        let store = SqliteWorkflowStore::in_memory()?;
        let mut coverage = CoverageMap::new();
        coverage.add_concept(Concept {
            id: "arithmetic-contract".into(),
            component: "pipeline".into(),
            summary: "the demo task's input/output contract".into(),
        });
        coverage.credit_from_trace(
            &"human:cli".to_string(),
            &["arithmetic-contract".into()],
            CreditSource::Build(uuid::Uuid::new_v4()),
            wyrtloom_core::types::Timestamp::now(),
        );
        store.save_coverage("demo", &coverage)?;
        let reloaded = store.load_coverage("demo")?.expect("saved state must reload");
        println!(
            "[workflow] Coverage persisted and reloaded ✓ (redundancy on demo concept: {})",
            reloaded.redundancy("arithmetic-contract")
        );
    }

    println!("\n🌿 Wyrtloom v0.1 boot complete.");
    Ok(())
}
