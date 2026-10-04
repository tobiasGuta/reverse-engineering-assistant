# ReVa Static Analysis Expansion — Slices 1–3

This branch contains a **general-purpose, read-only** reverse-engineering expansion for ReVa. It deliberately avoids CTF-, malware-, password-, flag-, Rust-, Go-, DWARF-, or attribution-specific heuristics.

> Repository note: this GitHub repository was created independently rather than as a GitHub fork, so the branch stores the expansion source and guarded application tooling against a pinned upstream revision.

Reviewed against upstream ReVa `main` at commit `01a154a8edf233b02a0e7707e2ff5933893c6d53` on 2026-10-03 and designed for Ghidra 12.1.x.

## Verification status

Slices 1–2 passed end-to-end verification on Fedora with Ghidra 12.1.3, Java 25, Gradle 9.6.1, and an isolated CPython 3.13 PyGhidra/MCP transport environment. Slice 2 also passed a final read-only live regression on a real x86-64 ELF after the live test had exposed and driven corrections for unresolved ABI normalization, unknown stack-purge sentinels, and single-instruction P-code truncation semantics.

**Slice 2 is frozen as of 2026-10-03.** No further Slice 2 contract changes should be made absent new evidence of a generic correctness or safety defect. See `STACK_ABI_VALIDATION.md` for the frozen invariants and validation record.

Slice 3 is implemented on `feat/semantic-provenance` and is **not frozen yet**. It adds a read-only semantic-provenance bridge from decompiler tokens to High P-code/SSA plus a bounded call-site view. Its next gates are automated verification and a live read-only regression on a real binary.

## New MCP tools

### `get-program-overview`

A compact triage surface for program-level facts: executable format/path/hashes, language/compiler metadata, image bounds, pointer size, function/symbol counts, relocation facts, source-map counts, memory blocks, and entry points.

It intentionally **does not** label binaries as PIE/NX/RELRO/etc. Format-specific conclusions stay with the analyst/model; the tool returns evidence.

### `get-function-cfg`

Bounded intraprocedural basic-block graph with block ranges, flow types, outgoing edges, internal/external destinations, and cyclomatic complexity. Intended as a decompiler fallback and exact-branch view.

### `get-pcode`

Bounded raw Sleigh P-code for one instruction, a basic block, or a function. Returns operations and varnodes but **does not execute or emulate** them.

### `list-source-files` / `get-source-mappings`

Generic access to Ghidra's `SourceFileManager`. Works with source mappings imported by supported debug formats; there is no DWARF/PDB-specific logic in the MCP contract.

### `get-function-stack-frame`

Read-only access to Ghidra's `StackFrame` model: frame/local/parameter sizes, parameter and return-address offsets, stack direction, defined stack variables, exact `VariableStorage`, and same-coordinate-system byte deltas. The contract explicitly labels all offsets as **Ghidra stack-space offsets** and warns that they are not literal RBP/RSP displacement operands.

### `get-function-abi`

Read-only access to the function signature, parameter and return storage, compiler stack model, and Ghidra `PrototypeModel` calling-convention facts. The tool preserves Ghidra terminology: `stackParameterAlignment` means alignment of individual parameters allocated on the stack and is **not** presented as function-entry or call-site RSP alignment.

### `get-decompiler-provenance`

Bounded token-level provenance from Ghidra's decompiler markup. Select by machine address, ReVa display line, token text, or a combination and inspect the token's direct address range, linked `PcodeOp`, `Varnode`, `HighVariable`, and `HighSymbol`. The contract explicitly distinguishes contextual decompiler line text from direct semantic links.

### `get-callsite-semantics`

Read-only inspection of one machine call site through High P-code. Returns the CALL/CALLIND operation, resolved direct target when available, decompiler statement context, argument Varnodes, immediate producer operations, and exact/shared-variable token links. It deliberately does **not** infer ABI register placement from the High P-code argument list.

## Safety / architecture

All added tools are read-only. This slice does not add:

- native process execution
- network activity
- shell execution
- arbitrary PyGhidra scripting
- binary patching
- Ghidra database mutation
- P-code emulation
- challenge-specific detectors

Output is explicitly bounded to avoid flooding MCP context.

Provider placement when applied to upstream ReVa:

- `get-program-overview` → `CORE_ANALYSIS`
- CFG, P-code, source metadata, stack frame, ABI, semantic provenance → `ADVANCED_ANALYSIS`

## Apply to a clean upstream checkout

For the normal Fedora workflow, use the guarded bootstrap helper from this branch:

```bash
./bootstrap_local_test.sh
```

It clones upstream ReVa into `/mnt/Development/Tools/ReVa-Static-Analysis`, checks out the reviewed upstream commit, creates a local feature branch, applies the expansion, and runs `git diff --check`. It refuses to overwrite an existing destination and does not install anything into Ghidra.

Manual equivalent:

```bash
git clone https://github.com/cyberkaida/reverse-engineering-assistant.git ReVa-dev
cd ReVa-dev
git checkout 01a154a8edf233b02a0e7707e2ff5933893c6d53
git checkout -b feat/static-analysis-expansion

python3 /path/to/this-repo/apply_static_analysis_expansion.py .

git diff --check
git diff --stat
```

Then run:

```bash
/path/to/this-repo/verify_static_analysis_expansion.sh
```

The verification script never modifies the normal workstation Ghidra installation. It builds the extension, installs it into a disposable isolated Ghidra copy for the Python MCP transport check, and removes that scratch copy automatically.

## Current files

The branch contains:

- six new ReVa provider implementations
- six Ghidra integration test classes
- a guarded application script that wires the providers into upstream ReVa
- a focused verification script
- a generic MCP smoke-test prompt

## Apply Slice 2 to an existing Slice 1 checkout

For the current development checkout that already has Slice 1 applied, use the incremental helper rather than re-running the clean-checkout patcher:

```bash
python3 ./apply_stack_abi_slice.py /mnt/Development/Tools/ReVa-Static-Analysis
```

The helper refuses to overwrite differing Slice 2 files, requires the Slice 1 provider registrations to already exist, and performs no commit or Ghidra installation.

## Apply Slice 3 to an existing Slices 1–2 checkout

For an existing development checkout with frozen Slices 1–2 already applied, use the incremental helper rather than re-running the clean-checkout patcher:

```bash
python3 ./apply_semantic_provenance_slice.py /mnt/Development/Tools/ReVa-Static-Analysis
```

It copies only the new provenance provider/test, performs guarded provider-registration and MCP transport edits, and creates no commit or Ghidra installation. During an evidence-driven Slice 3 correction, re-run it with `--refresh`; that mode replaces only the Slice 3-owned provider/test files and leaves the frozen Slice 1–2 provider files untouched.

## Suggested manual smoke test

Prepare a persistent development-only Ghidra copy without modifying the stable installation:

```bash
./prepare_dev_ghidra.sh
```

Launch the command printed by the script, enable ReVa in that development copy, open a known test binary, and use `SMOKE_TEST_PROMPT.md`. For Slice 3 specifically, use `SEMANTIC_PROVENANCE_SMOKE_TEST_PROMPT.md`. For later rebuilds, use `./prepare_dev_ghidra.sh --refresh`.

## Manual smoke-test refinement

The first live Codex/ReVa smoke test on `crackme01` validated that the new tools are useful and bounded. It also exposed two generic Slice 1 contract issues that were corrected:

- program address bounds are now computed explicitly within Ghidra's default memory space, with the address-space scope reported in the response
- intraprocedural CFG successors are now separated from call references so call targets cannot be mistaken for CFG edges

The first Slice 2 live stack/ABI regression then exposed three generic contract issues that were corrected before freeze:

- unresolved `PrototypeModel` results now preserve a schema-stable `callingConvention` object with explicit unavailable/null facts rather than making fields disappear
- unknown `Function.getStackPurgeSize()` values are normalized through Ghidra's validity API instead of exposing `Integer.MAX_VALUE` as a semantic purge size
- complete single-instruction `get-pcode` responses no longer report `truncated: true`; truncation is reported only when requested bounds actually omit data

After those corrections, the complete automated verification path passed and a second real-binary read-only regression confirmed the StackFrame coordinate contract, ABI normalization, P-code truncation semantics, and machine/Ghidra coordinate reconciliation.

## Deliberately deferred

Good later slices include per-instruction stack-depth analysis, a read-only debugger observer, objective function querying, richer generic debug-metadata adapters, and eventually bounded P-code emulation. Per-instruction stack depth remains the leading candidate after Slice 3 proves stable; it should extend the frozen StackFrame/ABI contract rather than redefine it.
