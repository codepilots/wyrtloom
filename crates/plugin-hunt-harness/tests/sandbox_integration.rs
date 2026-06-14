//! Core integration test (required by W4 brief).
//!
//! Executes trivial WASM modules through the REAL wasmtime sandbox
//! (`plugin-sandbox-wasmtime::WasmtimeSandbox`) and asserts:
//!   * a passing AND a breaking hunt-test both credit coverage deterministically
//!     (CG-6), and
//!   * a break opens a defect record (CG-7).

use std::collections::BTreeSet;

use plugin_hunt_harness::{ConceptId, CoverageMap, HuntHarness, HuntTest, Verdict};
use plugin_sandbox_wasmtime::WasmtimeSandbox;
use uuid::Uuid;

/// A SAFE module whose `run` returns a 1-byte buffer `[1]` — read by the
/// harness as "assertion held" → Survived.
fn surviving_module() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (memory (export "memory") 1)
          (func (export "run") (param i32 i32) (result i64)
            ;; write byte 1 at offset 0, return ptr=0,len=1 packed as (ptr<<32)|len
            (i32.store8 (i32.const 0) (i32.const 1))
            (i64.const 1)))"#,
    )
    .unwrap()
}

/// A SAFE module that traps (`unreachable`) — read by the harness as a break.
fn breaking_module() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (memory (export "memory") 1)
          (func (export "run") (param i32 i32) (result i64) unreachable))"#,
    )
    .unwrap()
}

fn coverage_map() -> CoverageMap {
    CoverageMap::new([
        ConceptId::from("parser.unicode"),
        ConceptId::from("parser.bounds"),
    ])
}

fn exercised() -> Vec<ConceptId> {
    vec![ConceptId::from("parser.unicode"), ConceptId::from("not.mapped")]
}

#[test]
fn passing_hunt_credits_coverage_deterministically() {
    let sandbox = WasmtimeSandbox::new().unwrap();
    let harness = HuntHarness::new(&sandbox, coverage_map());

    let test = HuntTest::new(
        "h-pass",
        "ana",
        Uuid::new_v4(),
        surviving_module(),
        exercised(),
    );

    let o1 = harness.run(&test, vec![]).unwrap();
    let o2 = harness.run(&test, vec![]).unwrap();

    assert_eq!(o1.verdict, Verdict::Survived);
    // CG-6: only the in-map concept is credited, and it is deterministic.
    let want: BTreeSet<ConceptId> = [ConceptId::from("parser.unicode")].into_iter().collect();
    assert_eq!(o1.credited, want);
    assert_eq!(o1.credited, o2.credited, "crediting must be deterministic (CG-6)");
    // A surviving hunt opens no defect.
    assert!(o1.defect.is_none());
}

#[test]
fn breaking_hunt_credits_coverage_and_opens_defect() {
    let sandbox = WasmtimeSandbox::new().unwrap();
    let harness = HuntHarness::new(&sandbox, coverage_map());

    let test = HuntTest::new(
        "h-break",
        "ana",
        Uuid::new_v4(),
        breaking_module(),
        exercised(),
    );

    let outcome = harness.run(&test, vec![]).unwrap();

    assert_eq!(outcome.verdict, Verdict::Broke);

    // CG-6: SAME deterministic credit as the passing case — crediting is
    // independent of pass/break.
    let want: BTreeSet<ConceptId> = [ConceptId::from("parser.unicode")].into_iter().collect();
    assert_eq!(outcome.credited, want);

    // CG-7: a break opens a defect record, credits coverage, and flags
    // crystallisation on fix.
    let defect = outcome.defect.expect("a break must open a defect (CG-7 i)");
    assert_eq!(defect.hunt_test_id, "h-break");
    assert_eq!(defect.credited, want, "defect carries credited coverage (CG-7 ii)");
    assert!(defect.crystallise_on_fix, "test must crystallise on fix (CG-7 iii)");
}

#[test]
fn pass_and_break_credit_identically() {
    // The crux of CG-6: regardless of whether the hunt passes or breaks the
    // target, the SAME concepts are credited.
    let sandbox = WasmtimeSandbox::new().unwrap();
    let harness = HuntHarness::new(&sandbox, coverage_map());

    let pass = HuntTest::new("hp", "ana", Uuid::new_v4(), surviving_module(), exercised());
    let brk = HuntTest::new("hb", "ana", Uuid::new_v4(), breaking_module(), exercised());

    let po = harness.run(&pass, vec![]).unwrap();
    let bo = harness.run(&brk, vec![]).unwrap();

    assert_eq!(po.verdict, Verdict::Survived);
    assert_eq!(bo.verdict, Verdict::Broke);
    assert_eq!(po.credited, bo.credited, "credit identical across pass/break (CG-6)");
}
