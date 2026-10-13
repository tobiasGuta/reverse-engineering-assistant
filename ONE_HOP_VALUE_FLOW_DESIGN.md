# Slice 5B — One-Hop Call-Argument Value Flow

**Status: DEVELOPMENT — full isolated regressions passed 2026-10-12; new positive real-ELF acceptance test committed but NOT YET RUN. NOT FROZEN.**
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

## Implementation delivered and verified in the isolated development environment

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
callee graph. **The refreshed full Fedora verifier passed on 2026-10-12.** The
user-supplied run completed Java build and Ghidra integration
(`BUILD SUCCESSFUL in 1m 8s`), extension packaging
(`BUILD SUCCESSFUL in 6s`), MCP transport (3/3), Slice 5A ELF (2/2),
bounded dataflow ELF (2/2), and the updated Slice 5B native ELF
`-O0`/`-O2` tests (2/2, 9.95 seconds). The script printed the final
one-hop development verification marker. The test suite checks that
ambiguous real-ELF calling conventions do not produce invented callee
graphs; it does **not** necessarily show a positive two-sided native-ELF
candidate. The synthetic Java Ghidra integration tests do require a
positive candidate with an explicitly defined calling convention.

**Positive native-ELF acceptance gate — implemented, pending Fedora:**
The updated two-case O0/O2 native regression starts with the original
ambiguous-auto-analysis observations, then uses upstream ReVa's existing
`set-function-prototype` tool to supply the original C source signature
and, inside the disposable PyGhidra MCP project only, its script tool to
bind Ghidra's imported compiler-spec default calling convention. This is
an explicitly trusted fixture fact, not inferred by the one-hop tool.
After that setup, the regression **requires** a complete
`decompiler_positional_candidate`, distinct caller/callee SSA graphs,
actual callee consumer operations, and independent first/second argument
indices. Unknown-convention cases remain fail-closed. The binary's SHA
is checked before/after, the ELF is never executed, and the normal
Ghidra installation and Codex MCP service remain untouched.

`REVA_VERIFY_ONE_HOP_NATIVE_ONLY=1` on
`verify_static_analysis_expansion.sh` builds the exact extension in a
disposable Ghidra copy and runs **only** the updated O0/O2 one-hop test.
Use this targeted mode since the Java provider and prior complete suites
were unchanged; it is **not** a substitute for the existing full workflow
after production Java changes. The positive gate is **NOT YET PASSED**.
If the new fixture setup does not produce positive evidence, diagnose
the actual Ghidra result rather than modifying the candidate guard.

Keep the development branch distinct from the normal ReVa/Ghidra
installation.

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
