# Slice 5B — One-Hop Call-Argument Value Flow

**Status: IMPLEMENTED IN DEVELOPMENT; Java/Ghidra integration passed, native ELF prototype-ambiguity regression updated and awaiting Fedora verification. NOT FROZEN.**
**Base:** `feat/dataflow-reliability-foundation`, after its narrowly scoped
engineering freeze. The existing frozen Slices 1–5A and bounded
intraprocedural dataflow implementation must remain unchanged.

## Why this slice exists

Today the call-boundary tool reports arguments and callee signature evidence,
while the bounded dataflow tools trace SSA def/use relationships **inside**
one function. Analysts still have to manually correlate the two sides.
This slice may reduce that repetition, but only for calls where the
correlation is unambiguous enough to **propose a candidate link**.
Neither shared source names nor a matching integer position proves
runtime value equivalence.

## Proposed first read-only MCP contract

`trace-call-argument-one-hop(programPath, callsite, argumentIndex, maxOperations)`

- `callsite` must resolve to a genuine machine CALL instruction in a
  known caller function, with exactly **one** Ghidra High P-code CALL
  operation at that instruction. Reject or mark unavailable otherwise.
- `argumentIndex` is zero-based in the decompiler's observed High
  P-code CALL argument list. Reject negative/out-of-range values.
- `maxOperations` is a *per-side* bound, default 128 and hard cap 500.
  Enforce finite overall analysis, decompilation, varnode, and edge budgets.
- Only a *direct, internal, non-thunk* target with a resolvable callee
  and available caller/callee HighFunction models is eligible.
- Reject candidate joining when variadic, custom calling/storage,
  unknown calling convention, auto parameters, forced-indirect parameters,
  parameter count mismatch, argument truncation, or unverified decompiler
  prototype information creates uncertainty.
- The selected caller argument must come from the actual High P-code
  call input, **not** reconstructed decompiled C expressions.
- The candidate callee formal must come from
  `FunctionPrototype.getParam(index)` and the corresponding
  `HighSymbol.getHighVariable()` / SSA Varnode instances in the
  independently decompiled callee, not a matching variable name.

## Separate evidence, no fabricated continuous path

The response should have two distinct graphs:

```
caller (high P-code)                          callee (high P-code)
 selected CALL input                           formal HighParam
      ^                                             |
 bounded backward slice                       bounded forward slice
      |                                             |
  producer evidence                         consumer evidence
       \                                            /
        ---- static candidate relation only ------
```

The middle connection is **never a verified runtime dataflow edge**.
Return `relationStatus="decompiler_positional_candidate"` and an
explicit `relationSemantics` disclaimer when eligible.
For incomplete/ambiguous cases, return typed status and the evidence
available without inventing a join.

For each side include `complete`, `truncated`, `truncationReason`,
operation count, stable P-code sequence identifiers, provenance
(instruction address and function identity), and a bounded list of
operations. The top-level response must never claim `complete=true`
if any required side is partial, unavailable, or decompilation failed.

## Stop rules

One hop only. Never recursively visit callees, follow function pointers,
resolve a virtual dispatch target speculatively, or use heuristics to
associate memory aliases. Calls encountered during a local slice remain
CALL/CALLIND boundaries. No target execution, Ghidra project mutation,
debugger integration, shell access, or network actions.

## Implementation delivered (verification pending)

1. `OneHopValueFlowToolProvider.java` adds the new MCP command within
   the dataflow package, calling the already frozen `BoundedDataFlowSlice`
   helper without modifying its implementation.
2. `apply_one_hop_value_flow.py` preflights and patches only
   `McpServerManager.java` and the MCP tool-catalog test, and installs
   the Slice 5B-owned provider and tests into the **existing** checkout.
   It refuses unexpected conflicting content.
3. Source evidence includes the actual machine callsite, Ghidra P-code
   sequence, caller/callee addresses, argument index, and HighSymbol /
   HighParam-backed callee formal identity. No variable-name matching
   or cross-SSA synthetic edge is used.
4. Added Java Ghidra tests for direct and indirect calls, variadic/custom
   storage, bad inputs, and truncation propagation. Added compiled native
   ELF `-O0`/`-O2` MCP tests for one- and two-argument direct calls.
   Added offline installer regression tests.
5. The isolated `verify_static_analysis_expansion.sh` workflow runs the
   new Java and ELF regressions alongside frozen Slices 1–5A and the
   bounded intraprocedural dataflow suite.

**Observed Fedora verification:** the guarded installer passed 4/4 offline
tests; Java compilation, Ghidra integration tests (including controlled
truncation), MCP transport, Slice 5A ELF, and bounded dataflow ELF tests
passed. The first native one-hop ELF cases at `-O0` and `-O2` correctly
identified the direct target but returned
`ambiguous_prototype_or_storage` instead of the originally assumed
positional candidate. Ghidra 12.1.3's function API recognizes unknown
calling-convention names as an explicit uncertainty condition. The tool
now reports each such ambiguity and native regressions require that a
rejected relation expose concrete, matching reasons and no invented
callee graph. **Those changes are pending a refreshed Fedora run.**
The synthetic Java Ghidra tests continue to require a positive
candidate for explicitly defined calling-convention fixtures.

## Non-negotiable acceptance tests

- Direct simple call where selected argument has a producer, and a
  corresponding callee parameter has downstream uses: return *two*
  separate, bounded SSA graphs linked as a **candidate**.
- `maxOperations` below actual graph size: typed, truthful truncation
  propagates to the top-level response.
- CALLIND, external function, thunk, unknown prototype, variadic,
  custom storage, auto/forced-indirect parameter, signature mismatch:
  no positional candidate relation.
- Optimized `-O2` and `-O0` real ELF results agree with native
  callsite target and argument count; no runtime claims.
- Multiple High P-code calls at one machine instruction, decompiler
  timeout/failure, missing formal SSA symbol, and recursion:
  typed unavailable/ambiguous result, no guessed mapping.
- Existing Slices 1–5A and dataflow reliability regressions remain green.
- No frozen source providers change and no existing stable MCP server
  configuration is modified.

**Go/no-go:** accept only the above bounded evidence feature first;
do not call it general interprocedural dataflow, and do not freeze unless
real reverse-engineering use cases show actionable value over manually
calling the existing tools.
