# ReVa Static Analysis Expansion — Slice 1

This branch contains a **general-purpose, read-only** reverse-engineering expansion for ReVa. It deliberately avoids CTF-, malware-, password-, flag-, Rust-, Go-, DWARF-, or attribution-specific heuristics.

> Repository note: this GitHub repository was created independently rather than as a GitHub fork, so the branch stores the expansion source and guarded application tooling against a pinned upstream revision.

Reviewed against upstream ReVa `main` at commit `01a154a8edf233b02a0e7707e2ff5933893c6d53` on 2026-10-03 and designed for Ghidra 12.1.x.

## Verification status

Slice 1 passed end-to-end verification on Fedora with Ghidra 12.1.3, Java 25, Gradle 9.6.1, and an isolated CPython 3.13 PyGhidra/MCP transport environment. The verified path covers normal Gradle tests, the four focused Ghidra integration tests, `buildExtension`, installation into a disposable Ghidra copy, and MCP `tools/list` registration for all five new tools.

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
- CFG, P-code, source metadata → `ADVANCED_ANALYSIS`

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

- four new ReVa provider implementations
- four Ghidra integration tests
- a guarded application script that wires the providers into upstream ReVa
- a focused verification script
- a generic MCP smoke-test prompt

## Suggested manual smoke test

Prepare a persistent development-only Ghidra copy without modifying the stable installation:

```bash
./prepare_dev_ghidra.sh
```

Launch the command printed by the script, enable ReVa in that development copy, open a known test binary, and use `SMOKE_TEST_PROMPT.md`. For later rebuilds, use `./prepare_dev_ghidra.sh --refresh`.

## Deliberately deferred

Good later slices include richer generic debug-metadata adapters, stack/ABI inspection, objective function querying, and eventually bounded P-code emulation. Those should be added only when they improve reverse engineering broadly rather than solving one specific challenge.
