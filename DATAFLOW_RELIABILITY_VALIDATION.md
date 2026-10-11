# ReVa — Dataflow Reliability Foundation Validation

**Status: FROZEN — 2026-10-11 (engineering scope only).**
**Development branch:** `feat/dataflow-reliability-foundation`, based on frozen
Slice 5A branch `feat/call-boundary-evidence`.
**Upstream pin:** `cyberkaida/reverse-engineering-assistant` at
`01a154a8edf233b02a0e7707e2ff5933893c6d53`;
original `DataFlowToolProvider.java` Git blob
`4966146539a743029ace1a505b4a8c7fa9a7cccd`.

This freeze concerns **deterministic, bounded, explicit-completeness
intraprocedural SSA tracing**. It is not a merge, production installation,
security proof, or implementation of interprocedural Slice 5B.

## Source-confirmed original defect

Pinned upstream ReVa used Ghidra
`DecompilerUtils.getBackwardSliceToPCodeOps` and
`getForwardSliceToPCodeOps` to materialize full slices in hash sets,
then returned at most 500 P-code operations chosen by unordered iteration.
The response did not distinguish complete from truncated results.
Ghidra 12.1.3 source confirms that these utilities traverse SSA def/use
links and stop at CALL/CALLIND boundaries.

## Frozen implementation

The new `BoundedDataFlowSlice` uses an explicit, deterministic worklist
instead of materializing a full slice before imposing resource caps.

- Sorts seed Varnodes, backward P-code inputs, forward P-code descendants,
  and final P-code operations. Deduplicates visited varnodes and operations.
- Preserves the original `trace-data-flow-forward` and
  `trace-data-flow-backward` names.
- Returns `complete`, `truncated`, `truncationReason`,
  `operationLimit`, `visitedVarnodeCount`, `scannedEdgeCount`,
  `terminatorsComplete`, and a static-slice semantics statement.
- Treats operations and terminators from incomplete slices as **partial
  evidence**; their absence is never proof of absence.
- Stops propagation at CALL/CALLIND and does **not** cross a function
  boundary or perform memory-alias analysis.

| Budget | Hard limit |
|---|---:|
| Returned P-code operations | 500 |
| Visited SSA varnodes | 10,000 |
| Queued varnodes | 10,000 |
| Descendant fanout per varnode | 10,000 |
| Inputs per P-code operation | 10,000 |
| Total scanned def/use edges | 100,000 |

Hitting a budget reports a typed truncation reason. A slice containing
exactly 500 operations can be complete when traversal has exhausted all
relevant work.

The `apply_dataflow_reliability.py` applicator verifies the pinned
upstream blob before patching only
`src/main/java/reva/tools/dataflow/DataFlowToolProvider.java`.
It adds the new dataflow helper and test files, and refuses unexpected
upstream or missing frozen Slice 1–5A registrations.
It does not install an extension or alter the live Codex MCP server.

## Fedora acceptance evidence

**Full isolated verification (user-reported):**
`verify_static_analysis_expansion.sh` completed successfully on Fedora
with Ghidra 12.1.3. The supplied terminal output reported:

- Gradle: **BUILD SUCCESSFUL**.
- Disposable Ghidra/PyGhidra CPython 3.13.15 setup completed.
- MCP transport: **3/3 PASS** (4.89 seconds).
- Previously frozen Slice 5A compiled ELF regression:
  **2/2 PASS**, `-O0` and `-O2` (10.41 seconds).
- Bounded dataflow compiled ELF regression:
  **2/2 PASS**, `-O0` and `-O2` (10.89 seconds).
- Final workflow marker:
  `Static-analysis expansion (Slices 1-5A + 5B prerequisite)
  verification completed.`
- The verification script uses `set -euo pipefail`; successful
  completion supports that the preceding Java/Ghidra tests and
  extension packaging also succeeded.

**Post-pass adversarial tests (user-reported):**
After the full run, three additional Ghidra integration tests were
committed, without changing the production helper or upstream patch:

1. A cyclic SSA graph terminates in both directions without duplicate
   operations.
2. Excessive forward descendant fanout yields an explicit incomplete
   result without sampling arbitrary descendants.
3. A backward SSA graph exceeding the 100,000-edge budget yields
   `edge_scan_budget` and bounded work.

The targeted Gradle integration run completed with:
`BUILD SUCCESSFUL in 23s`,
`11 actionable tasks: 2 executed, 9 up-to-date`.

**Source scope check:** GitHub comparison against frozen
`feat/call-boundary-evidence` showed no changes to existing
Slice 1–5A production provider files. The reliability changes are
separate dataflow-owned code, a guarded upstream patch application
script, tests, verifier updates, and documentation.

These are user-provided terminal results, not a third-party audit.
The reported tests establish the named acceptance cases, not universal
correctness on arbitrary Ghidra graphs, binaries, architectures, or
calling conventions.

## Freeze decision and invariants

**ACCEPTED/FROZEN** for the narrowly defined dataflow reliability
foundation. Preserve the completion and ordering contract, finite
work budgets, and CALL/CALLIND traversal boundaries. Reopen only for
demonstrated correctness, safety, performance, or compatibility defects,
with targeted regression evidence.

**Not claimed:** global memory-alias soundness, inferred runtime execution,
interprocedural equivalence, recognition of every indirect target,
cross-binary portability, or full analysis of a trace marked truncated.

**Next scope:** A future one-hop Slice 5B may combine frozen call-boundary
evidence with bounded local SSA slices, but must be independently
designed and tested. A safe one-hop join requires explicit source/target
identity, argument-to-formal uncertainty, partial-slice propagation,
recursion/thunk handling, and evidence of utility on real reverse
engineering tasks. No such join is implemented or frozen here.
