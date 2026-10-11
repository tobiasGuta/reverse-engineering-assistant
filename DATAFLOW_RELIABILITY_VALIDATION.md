# ReVa — Dataflow Reliability Foundation (before Slice 5B)

**Status: DEVELOPMENT; first full Fedora/Ghidra verification passed, with additional adversarial graph tests pending.**
**Parent branch:** `feat/call-boundary-evidence` (frozen Slice 5A).
**Upstream pin:** `cyberkaida/reverse-engineering-assistant` commit
`01a154a8edf233b02a0e7707e2ff5933893c6d53`; original
`DataFlowToolProvider.java` Git blob
`4966146539a743029ace1a505b4a8c7fa9a7cccd`.

## Source-confirmed defect

The pinned upstream DataFlowToolProvider calls Ghidra 12.1.3
`DecompilerUtils.getBackwardSliceToPCodeOps` and
`getForwardSliceToPCodeOps` independently for every varnode at a given
instruction, obtains entire SSA slices in unbounded hash sets, and then
selects 500 operations by hash-set iteration order. Its response has
no completion status. On large graphs the selection can therefore be
incomplete, nondeterministic, and indistinguishable from a full slice.

The Ghidra helper's actual source was inspected at tag
`Ghidra_12.1.3_build`: it traverses SSA def/use edges and treats CALL
and CALLIND operations as traversal boundaries.

## Implemented remedy

- New `BoundedDataFlowSlice` performs an explicit worklist traversal
  instead of building full Ghidra slices before imposing a cap.
- Sorts seed Varnodes and each forward descendant list; output operations
  are ordered by Ghidra `SequenceNumber`. Backward input traversal
  is also ordered. Identity-based visited sets prevent cycles.
- Caps unique returned operations at **500**, visited varnodes at
  **10,000**, queued varnodes at **10,000**, per-varnode descendants
  at **10,000**, P-code inputs per operation at **10,000**, and total traversed\n  def/use edges at **100,000**.
- Crossing any limit marks the result **truncated** with a reason.
  Exactly 500 operations is not automatically marked truncated; only
  genuinely unprocessed graph work produces a partial status.
- Preserves the original tool names and adds `complete`, `truncated`,
  `truncationReason`, `operationLimit`, `visitedVarnodeCount`,
  `terminatorsComplete`, and a static-slice semantics notice.
  Terminators found in incomplete slices remain explicitly partial.
- Backward and forward traversal both stop propagation beyond CALL
  and CALLIND operations. No memory alias solver, runtime execution,
  or interprocedural propagation is introduced.

## Installation and regression boundaries

`apply_dataflow_reliability.py` only patches the pinned upstream
`src/main/java/reva/tools/dataflow/DataFlowToolProvider.java`, with
explicit old-code anchors, and adds new dataflow-owned helper and test
files. It rejects unexpected upstream blobs or missing frozen Slice
1–5A provider registrations. It does not install anything into Ghidra
or commit into the source checkout.

Added tests:
- Ghidra SSA graph tests for exact budget, budget overflow, repeated
  deterministic output, descendant-order reversal, seed-order reversal,
  and CALL barriers.
- Offline applicator negative controls for wrong upstream SHA and
  missing frozen-slice registrations.
- Real native O0/O2 compiled ELF tests through an isolated MCP stdio
  transport; verify completion metadata and repeated output ordering.
  Fixtures are never executed and their bytes are hash-checked.

## First Fedora verification: passed

The user ran the isolated `verify_static_analysis_expansion.sh` workflow on
the existing Fedora/Ghidra 12.1.3 development checkout and supplied its
completion transcript:

- Gradle completed with **BUILD SUCCESSFUL in 6s** for the reported packaging
  segment (8 actionable tasks: 2 executed, 6 up-to-date).
- Disposable Ghidra test copy and CPython 3.13.15 environment initialized.
- Existing MCP transport: **3/3 passed** (4.89s).
- Frozen Slice 5A compiled ELF O0/O2 regression: **2/2 passed** (10.41s).
- New bounded dataflow compiled ELF O0/O2 regression: **2/2 passed** (10.89s).
- Script reported `Static-analysis expansion (Slices 1-5A + 5B prerequisite)
  verification completed.` This confirms earlier Java/Ghidra test steps
  completed successfully under the script's `set -euo pipefail` behavior.

The transcript supports that specific test environment and scenarios; it
does not establish complete correctness for all binaries.

## Post-pass review and new tests

Source audit found that we had tested exact/overflow operation caps and
determinism, but had not directly exercised a cyclic def/use graph or the
per-varnode and global edge budgets. Additional synthetic Ghidra regressions
have now been committed to test:

- A cyclic SSA graph terminates without repeated operations in both
  directions.
- An oversized forward descendant fanout returns an explicit incomplete
  result instead of selecting unordered partial descendants.
- More than 100,000 backward SSA edges triggers `edge_scan_budget` with
  bounded work, even when repeated inputs lead to only a few distinct
  operations.

**These newly added tests have not run on Fedora.** No production helper or
upstream provider-patching code was modified after the successful full
verification. A targeted Ghidra integration run suffices to validate the new
tests, subject to rerunning the full workflow if production code changes.

## Remaining acceptance criteria

1. Pull the new graph tests and refresh only the dataflow-owned test file.
2. Run `BoundedDataFlowSliceIntegrationTest` under the Ghidra 12.1.3 Gradle
   wrapper. If it fails, investigate and fix with evidence; do not weaken
   correctness tests merely to obtain a green build.
3. Confirm the upstream patch is restricted to the SHA-pinned
   `DataFlowToolProvider.java` and no frozen Slice 1–5A providers changed.
4. Review API limitations and preserve the explicit incomplete-result
   semantics before deciding on an engineering freeze.

**NO-GO for interprocedural Slice 5B** until this foundation passes and
the need for a conservative one-hop join is demonstrated using real
reverse-engineering evidence. A 500-operation budget is a resource
safety choice, not a guarantee that every function has been analyzed
completely.
