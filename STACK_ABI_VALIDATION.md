# Stack / ABI Slice 2 — Frozen Validation Record

Date frozen: **2026-10-03**

Branch: `feat/stack-abi-intelligence`

Code head before this documentation commit:

- `ac7f6a6a46fba44d67146f9f6da66b40adbadb25` — normalize unresolved ABI facts and unknown stack-purge values
- `682e68fefc8c6f4589b84d7715ca1c871a0acfcd` — report P-code truncation only when data is actually omitted

Slice 2 is frozen after both synthetic integration coverage and a final live, read-only regression against a real x86-64 ELF. The freeze means the StackFrame/ABI contracts should not be redesigned or extended without new evidence of a generic correctness, safety, or interoperability defect.

## Scope

Slice 2 adds two read-only MCP tools:

- `get-function-stack-frame`
- `get-function-abi`

The existing Slice 1 `get-pcode` tool also received one evidence-driven truncation fix found during Slice 2 validation.

No native execution, shell execution, network activity, arbitrary PyGhidra scripting, binary patching, P-code emulation, or Ghidra database mutation was added.

## Automated verification

The full local verification harness passed after the final corrections:

- normal Gradle tests
- focused Ghidra integration tests
- StackFrame synthetic integration coverage
- resolved ABI / `PrototypeModel` coverage
- unresolved ABI normalization coverage
- known and unknown stack-purge coverage
- P-code complete single-instruction non-truncation coverage
- P-code true `maxOps` truncation coverage
- extension packaging via `buildExtension`
- disposable isolated Ghidra installation
- CPython 3.13 MCP transport tests

The final focused integration run completed successfully, the extension package was built, and the Python MCP transport suite finished with all tests passing.

## Final live regression

The final regression used only read-only ReVa operations against the sole open Ghidra program, a real x86-64 ELF, targeting `main`.

### StackFrame contract

Validated:

- stack offsets are explicitly labeled as Ghidra stack-space offsets
- stack-pointer register, stack/base spaces, frame/local/parameter sizes, growth direction, parameter offset, return-address offset, and provenance are returned
- defined stack variables preserve exact Ghidra `VariableStorage`
- same-coordinate-system byte deltas remain internally consistent
- Ghidra stack offsets are not silently reinterpreted as literal RBP/RSP displacement operands

The live frame demonstrated that Ghidra and machine coordinates can differ while remaining consistent. In the tested frame, a Ghidra stack offset of `-0x58` corresponded to a machine operand at `[RBP-0x50]`, while the return-address slot was Ghidra offset `0` and machine `[RBP+0x8]`. That translation was derived from the inspected machine instructions and is frame-specific; it is not part of the generic StackFrame contract.

### ABI normalization

Validated for an unresolved calling convention:

- `signature.stackPurgeSizeKnown = false`
- `signature.stackPurgeSize = null`
- no `Integer.MAX_VALUE` sentinel escapes as a semantic stack-purge value
- `callingConvention` remains present
- `callingConvention.resolved = false`
- `unavailableReason` is explicit
- unavailable scalar `PrototypeModel` facts remain present as `null`
- bounded storage/list fields remain present as empty arrays with zero counts and non-truncated status
- `stackParameterAlignmentSemantics` remains present even when the numeric value is unavailable
- no unavailable ABI fact is inferred

Frozen semantic invariant:

> `stackParameterAlignment` is the alignment of individual parameters allocated on the stack; it is not a function-entry or call-site stack-pointer alignment guarantee.

### P-code truncation semantics

Validated on a single real instruction that lifts to multiple P-code operations:

- with sufficient `maxOps`: one instruction returned, all operations returned, `truncated = false`
- with `maxOps = 1`: one instruction returned, an operation omitted, `truncated = true`

Frozen truncation invariant:

> `truncated` means requested safety bounds actually caused data to be omitted; reaching the natural end of the requested scope is not truncation.

## Final verdict

- StackFrame contract: **PASS**
- ABI normalization: **PASS**
- P-code truncation semantics: **PASS**
- Ghidra/machine coordinate-system clarity: **PASS**
- remaining generic API defect found by the final regression: **none**
- Slice 2 freeze readiness: **READY**

## Deferred work

Per-instruction stack-depth analysis remains a separate later slice. It should not be folded into the frozen StackFrame/ABI contract unless a concrete use case demonstrates that the simpler Ghidra `StackFrame` / `PrototypeModel` surfaces are insufficient.
