use wasmtime::{Config, Engine, Linker, Module, Store};
use wyrtloom_core::sandbox::{ResourceLimits, SafeModule, SandboxError, SandboxRuntime};
use wyrtloom_core::types::Bytes;

pub struct WasmtimeSandbox {
    engine: Engine,
}

impl WasmtimeSandbox {
    pub fn new() -> Result<Self, SandboxError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine =
            Engine::new(&config).map_err(|e| SandboxError::Compile(e.to_string()))?;
        Ok(Self { engine })
    }
}

impl Default for WasmtimeSandbox {
    fn default() -> Self {
        Self::new().expect("failed to create wasmtime engine")
    }
}

impl SandboxRuntime for WasmtimeSandbox {
    fn execute(
        &self,
        module: SafeModule,
        input: Bytes,
        limits: ResourceLimits,
    ) -> Result<Bytes, SandboxError> {
        // Compile — catches invalid WASM bytes.
        let compiled = Module::new(&self.engine, &module.wasm_bytes)
            .map_err(|e| SandboxError::Compile(e.to_string()))?;

        let mut store = Store::new(&self.engine, ());

        // Fuel-based compute limit (~1 fuel per instruction).
        let fuel = limits.max_wallclock_ms.saturating_mul(10_000);
        store
            .set_fuel(fuel)
            .map_err(|e| SandboxError::Trap(format!("fuel setup: {}", e)))?;

        // No host imports — enforces the isolation boundary.
        // A SAFE plugin cannot call anything in the host process.
        let linker: Linker<()> = Linker::new(&self.engine);

        let instance = linker
            .instantiate(&mut store, &compiled)
            .map_err(|e| SandboxError::Trap(e.to_string()))?;

        // Write input into WASM linear memory at offset 0.
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| SandboxError::Trap("module must export 'memory'".into()))?;

        let input_len = input.len() as i32;
        if !input.is_empty() {
            memory
                .write(&mut store, 0, &input)
                .map_err(|e| SandboxError::Trap(e.to_string()))?;
        }

        // Call `run(input_ptr: i32, input_len: i32) -> i64`.
        // Packed return: high 32 bits = output_ptr, low 32 bits = output_len.
        let run = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "run")
            .map_err(|e| SandboxError::Trap(format!("module must export 'run': {}", e)))?;

        let result = run
            .call(&mut store, (0, input_len))
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("all fuel") || msg.contains("fuel") {
                    SandboxError::Timeout
                } else {
                    SandboxError::Trap(msg)
                }
            })?;

        let output_ptr = ((result >> 32) & 0xFFFF_FFFF) as usize;
        let output_len = (result & 0xFFFF_FFFF) as usize;

        if output_len == 0 {
            return Ok(vec![]);
        }

        let mem_size = memory.data_size(&store);
        if output_ptr + output_len > mem_size {
            return Err(SandboxError::Trap("output pointer out of bounds".into()));
        }

        let output = memory.data(&store)[output_ptr..output_ptr + output_len].to_vec();
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wyrtloom_core::sandbox::ResourceLimits;

    fn sandbox() -> WasmtimeSandbox {
        WasmtimeSandbox::new().unwrap()
    }

    #[test]
    fn executes_safe_module_returning_empty_output() {
        let sb = sandbox();
        let wasm = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        let out = sb
            .execute(SafeModule { wasm_bytes: wasm }, vec![], ResourceLimits::default())
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn trap_returns_trap_error() {
        let sb = sandbox();
        let wasm = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64) unreachable)
            )"#,
        )
        .unwrap();
        let err = sb
            .execute(SafeModule { wasm_bytes: wasm }, vec![], ResourceLimits::default())
            .unwrap_err();
        assert!(matches!(err, SandboxError::Trap(_)));
    }

    #[test]
    fn invalid_wasm_bytes_give_compile_error() {
        let sb = sandbox();
        let err = sb
            .execute(
                SafeModule { wasm_bytes: b"not wasm at all".to_vec() },
                vec![],
                ResourceLimits::default(),
            )
            .unwrap_err();
        assert!(matches!(err, SandboxError::Compile(_)));
    }

    /// Key isolation contract: a SAFE module cannot import host functions.
    /// The linker exposes nothing, so instantiation fails before any code runs.
    #[test]
    fn module_with_host_import_fails_at_instantiation() {
        let sb = sandbox();
        let wasm = wat::parse_str(
            r#"(module
              (import "env" "read_file" (func (param i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        let err = sb
            .execute(SafeModule { wasm_bytes: wasm }, vec![], ResourceLimits::default())
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::Trap(_)),
            "expected Trap for missing import, got: {:?}",
            err
        );
    }
}
