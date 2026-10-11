# ReVa — Dataflow Reliability Foundation (before Slice 5B)

**Status: DEVELOPMENT; Fedora/Ghidra acceptance not yet run.**
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
  at **10,000**, and P-code inputs per operation at **10,000**.
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

## Acceptance criteria (pending execution)

1. Offline applicator tests pass.
2. Guarded patch applies successfully to the existing upstream checkout
   without modifying frozen Slices 1–5A providers.
3. Java compilation and bounded SSA graph integration tests pass.
4. Existing Slices 1–5A regressions and the new ELF O0/O2 MCP tests pass
   against the scratch Ghidra installation.
5. Explicit truncation and deterministic ordering are confirmed, not
   inferred only from a successful build.
6. An adversarial review of traversal limits, cycles, P-code sequence
   identity, and response semantics yields no unfixed correctness defects.

**NO-GO for interprocedural Slice 5B** until this foundation passes and
the need for a conservative one-hop join is demonstrated using real
reverse-engineering evidence. A 500-operation budget is a resource
safety choice, not a guarantee that every function has been analyzed
completely.
