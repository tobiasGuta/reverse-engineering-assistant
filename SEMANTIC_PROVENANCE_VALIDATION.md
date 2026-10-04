# Semantic Provenance Slice 3 — Frozen Validation Record

Date frozen: **2026-10-04**

Branch: `feat/semantic-provenance`

Code head before this documentation commit:

- `8da5963612cb2bf32cf81d390aafcfd237e17b30` — map decompiler display lines to the actual rendered decompilation used by ReVa

Slice 3 is frozen after both synthetic integration coverage and a final live, read-only regression against a real x86-64 ELF. The freeze means the semantic-provenance contracts should not be redesigned or extended without new evidence of a generic correctness, safety, or interoperability defect.

## Scope

Slice 3 adds two read-only MCP tools:

- `get-decompiler-provenance`
- `get-callsite-semantics`

The slice bridges Ghidra decompiler markup to High P-code/SSA facts without treating decompiled C text as an authoritative one-to-one source map.

No native execution, debugger control, shell execution, network activity, arbitrary PyGhidra scripting, binary patching, P-code emulation, or Ghidra database mutation was added.

## Frozen semantic invariants

### Token provenance

`get-decompiler-provenance` may expose facts directly provided by Ghidra's decompiler model:

- token class and text
- exact token address range when one exists
- linked `PcodeOp`
- linked `Varnode`
- linked `HighVariable`
- linked `HighSymbol`
- contextual decompiler line and token index

A token without a direct machine-address link is not promoted into one. Contextual decompiled line text is not represented as a one-to-one machine-code mapping.

Frozen invariant:

> Direct token addresses, P-code links, Varnode links, HighVariable links, and HighSymbol links are Ghidra provenance facts. Decompiled line text is contextual and must not be treated as stronger source-level equivalence.

### Display-line numbering

The first live regression exposed that a fixed or heuristic offset between `ClangLine` numbering and ReVa `get-decompilation` numbering was not a valid generic contract.

The corrected implementation maps materialized `ClangLine` objects against the actual `DecompiledFunction.getC()` rendering used by ReVa. The final live regression verified exact equality between provenance `displayLineNumber` and the visible line number from normal `get-decompilation`.

Frozen invariant:

> `displayLineNumber` is the 1-based line number visible in ReVa `get-decompilation`; callers must not need to apply a +1/-1 correction.

### Call-site statement context

For a High P-code `CALL` / `CALLIND` associated with a decompiler statement, `get-callsite-semantics` preserves:

- statement text
- statement minimum/maximum addresses when available
- non-empty statement display-line context when the statement is rendered on a decompiler line

Frozen invariant:

> Statement lines are derived from materialized token-line context and use the same visible numbering contract as `get-decompilation`.

### Argument provenance

High P-code call inputs after input 0 are reported as call arguments. For each bounded argument the tool may expose:

- the argument `Varnode`
- associated `HighVariable`
- the argument Varnode's immediate defining High P-code operation when one exists
- related decompiler tokens that match either the exact Varnode or the same HighVariable

Frozen invariants:

> `producer` is only the immediate defining High P-code operation; deeper provenance requires an explicit data-flow trace.

> `matchKind = varnode-exact` means the decompiler token exposes the same Varnode object as the call argument. `matchKind = high-variable` means the token and argument share the same HighVariable. Neither is a claim of stronger source-level semantic equivalence.

> High P-code argument order/storage is not silently reinterpreted as ABI register placement. ABI/storage facts remain the responsibility of the dedicated ABI surface.

## Automated verification

The complete local verification harness passed after the final corrections:

- normal Gradle tests
- focused Ghidra integration tests for Slices 1–3
- synthetic token-to-High-P-code provenance coverage
- exact display-line agreement against stock `get-decompilation`
- direct call-target resolution coverage
- statement-line context coverage
- related-token context preservation
- bounded argument provenance coverage
- selector validation
- extension packaging via `buildExtension`
- disposable isolated Ghidra installation
- CPython 3.13 MCP transport tests

The final automated gate completed successfully before the live freeze regression.

## Final live regression

The final regression used only read-only ReVa operations against the open `/grimoire` x86-64 ELF and focused on `print_flag`, including the direct `fclose(local_10)` call at `0x0040120f`.

### Token-level provenance

Validated on the `local_10` argument token:

- token class: `ClangVariableToken`
- visible display line: 18
- contextual line: `fclose(local_10);`
- direct machine-address link: `0x0040120f`
- linked High P-code operation: `CALL`
- linked argument Varnode: stack-space `A_Stack[-0x10]:8`
- immediate defining operation: `MULTIEQUAL`
- linked HighVariable: `local_10`, `FILE *`
- linked HighSymbol: `local_10`, non-parameter, non-global

A declaration occurrence of `local_10` remained syntax-only with no fabricated direct machine address.

### Address-scoped provenance

An address-scoped query at `0x0040120f` returned:

- explicit requested and canonical instruction addresses
- High P-code at that machine address independently of token matches
- both the `CALL` and accompanying `INDIRECT` operation

The response retained the contract warning that decompiled line text is contextual rather than a one-to-one machine mapping.

### Display-line contract

A line-scoped query for display line 18 returned exactly the tokens on that visible line, all reporting `displayLineNumber = 18`.

The final regression therefore confirmed the corrected line-number contract against a real binary after the earlier +1 mismatch had been removed.

### Call-site semantics

The `fclose` call-site regression validated:

- caller: `print_flag`
- machine instruction: direct `CALL 0x00401040`
- High P-code operation: `CALL`
- direct target resolved as `fclose`
- target prototype: `int fclose(FILE * __stream)`
- statement text: `fclose(local_10)`
- statement lines: `[18]`
- one returned argument, not truncated
- argument Varnode: `A_Stack[-0x10]:8`
- HighVariable: `local_10`
- immediate producer: `MULTIEQUAL`
- one related decompiler token with `matchKind = varnode-exact`

A separate ABI query resolved the callee parameter to RDI while the call-site data-flow Varnode remained stack-backed. The two surfaces were not conflated.

### Deeper data-flow boundary

A separate backward data-flow trace recovered the longer SSA chain leading into the call. This confirmed that Slice 3's `producer` field correctly stops at the immediate defining operation rather than pretending to be a recursive source trace.

## Final verdict

- token-level provenance: **PASS**
- visible decompilation line-number agreement: **PASS**
- statement-line context: **PASS**
- related-token context preservation: **PASS**
- call-site target semantics: **PASS**
- argument provenance: **PASS**
- remaining generic API defect found by the final regression: **none**
- Slice 3 freeze readiness: **READY**

## Deferred work

Per-instruction stack-depth analysis remains the next likely static-analysis slice. A read-only debugger observer, objective function querying, richer generic debug-metadata adapters, and bounded P-code emulation remain later candidates. None of those capabilities are part of the frozen Slice 3 contract.
