# ReVa Slice 5A — Call-boundary evidence validation

**Status: FROZEN — 2026-10-11.** Slice 5A's narrow, read-only, candidate-only call-boundary contract is frozen on the `feat/call-boundary-evidence` development branch. This is **not** a merge, production-installation claim, or guarantee on arbitrary architectures/ABIs.

Scope: a single read-only `inspect-call-boundary` observation of one Ghidra
machine call. The tool returns separate caller/callee High P-code models,
parameter and return evidence, candidate positional correspondences, and
explicit unavailable/ambiguous/truncation states. It does **not** establish
runtime value equality, execute a binary, follow an indirect target, or perform
whole-program dataflow.

## Completed checks (reported from Fedora 44 / Ghidra 12.1.3)

The user ran `verify_static_analysis_expansion.sh` on the existing
`ReVa-Static-Analysis` checkout with the Slice 5A patch applied:

- Gradle/Java build, existing Slices 1–4 tests, and Slice 5A Ghidra
  integration tests completed with a successful script exit.
- A development extension was packaged and checked through a disposable
  clone of Ghidra; the stable Ghidra installation was not replaced.
- Python MCP transport: **3/3 PASS** using CPython 3.13.15.
- Initial real native Linux ELF acceptance tests: **2/2 PASS**, compiled
  at `-O0` and `-O2` and inspected through the isolated MCP stdio project.
- Earlier offline guarded-applicator checks: **4/4 PASS**.
- The submitted completion log is terminal output; it is not an archived,
  independently authenticated benchmark record.

**Second reported Fedora run:** the refreshed Slice 5A branch containing R1/R2
corrections completed the entire isolated verifier successfully. MCP transport:
**3/3 passed** (4.65s); real native ELF regression: **2/2 passed** (9.98s),
including the two-argument truncation negative-control assertions at both
`-O0` and `-O2`. The terminal output reported
`Static-analysis expansion (Slices 1-4, 5A) verification completed.`
These results are based on user-supplied terminal output, and support those
specific checks, not all possible compiler or ABI configurations.

## Post-test adversarial review

### R1. Incomplete callee RETURN scan could be described as missing

Previously, when P-code traversal reached its 50,000-operation budget with
zero observed RETURN operations, `returnRelationship` could report
`callee_return_unavailable`, which incorrectly promoted an incomplete scan
to a negative finding.

**Correction:** `incomplete_callee_return_scan` now takes precedence
whenever the scan was truncated. Integration-level classification regressions
exercise truncated/no-output/complete-scan cases.

### R2. Truncated argument list must not appear fully mapped

The initial real ELF fixtures each tested a single-argument direct call.

**Additional regression:** the ELF source now contains a two-argument
callee and a separate caller, referenced from `main`. Each optimized mode
requests `maxArguments=1` at the actual native call site, and must report
`argumentsTruncated=true`, exactly one returned argument, and no candidate
formal index. The machine calls were independently checked with local
`cc` and `objdump` for both `-O0` and `-O2`, and the revised MCP/Ghidra
tests **passed on Fedora** in the second verifier run.

### R3. Variadic and custom variable-storage signatures

A separate source review of Ghidra 12.1.3's `Function` API and decompiler
model confirms that variadic signatures and special parameter storage
require conservative treatment. The Slice 5A implementation already
rejects positional mapping when `hasVarArgs()` or
`hasCustomVariableStorage()` is true, but our initial test suite did not
assert these paths end-to-end.

**Additional tests committed:** synthetic native Ghidra integration cases now
mark the callee variadic and custom-storage, respectively, and verify that
`inspect-call-boundary` retains direct callee identity but sets
`mappingStatus=ambiguous_prototype_or_storage` and emits **no**
`candidateFormalIndex`. **Verified on Fedora:** the updated `CallBoundaryToolProviderIntegrationTest` class completed successfully using Ghidra's Gradle wrapper. The reported `:integrationTest` task finished `BUILD SUCCESSFUL in 24s`, with `11 actionable tasks: 2 executed, 9 up-to-date`. This covers both new prototype guard tests as part of the successful class execution.

### R4. Design limits retained intentionally

- Argument positions are **decompiler-derived candidates**, not proven
  machine ABI equivalence or actual runtime value correspondence.
- Unknown indirect targets, external calls, and thunks do not produce a
  synthetic resolved callee mapping.
- Callee RETURN operations are independent static evidence; even when a
  caller output and a callee RETURN are both present, the tool does not
  assert runtime equivalence.
- Per-call result caps: 128 arguments, 8 High P-code call operations,
  16 returned RETURN sites, and 50,000 scanned callee High P-code operations.
  Truncation is explicit. Each decompilation has a 30-second timeout.
- No arbitrary-depth traversal, dynamic execution, signature rewriting,
  or Ghidra project-database modification is introduced.

## Final acceptance decision (2026-10-11)

**ACCEPTED AND FROZEN — bounded Slice 5A only.**

- Two earlier complete isolated verifier runs, with the later run exercising
  the post-review return-scan classification fix and native `-O0`/`-O2`
  two-argument truncation negative-control tests, were successful.
- The final targeted Ghidra Java integration run completed successfully after
  adding variadic and custom-storage tests. Only those integration tests and
  validation text had changed after the second complete verifier; the
  production provider was identical.
- The GitHub comparison of `feat/static-analysis-expansion` against
  `feat/call-boundary-evidence` confirmed no changes to frozen Slice 1–4
  provider source files.
- The patch remains on a **development branch**. No request to change or
  install the stable Codex/ReVa MCP integration was made.

These facts support a **limited engineering freeze**: the new API and
implementation should not be changed merely to add features. Reopen it only
when new evidence exposes a generic correctness, safety, performance, or
compatibility issue. Keep regression tests and validation notes with fixes.

### Frozen contract and nonclaims

1. `inspect-call-boundary(programPath, callsite, maxArguments)` is read-only.
   It checks for a machine-call instruction and reports Ghidra static models.
2. Direct-call callee identity can be reported if resolvable; unknown
   indirect targets, thunks, and external calls do **not** receive invented
   argument-to-formal correspondences.
3. Argument/formal positions are **candidate-only**, never evidence of
   observed runtime value equality, nor proof of calling-convention storage.
   Variadic, custom-storage, unknown-convention, hidden/forced-indirect, and
   count-mismatch situations must not be asserted as reliable mappings.
4. Caller and callee return models are separate. If the callee return scan
   hits its cap, it reports incomplete coverage rather than proving absence.
5. Arguments and returned evidence are capped: 128 arguments, 8 High P-code
   call operations, 16 return sites, and 50,000 callee scan operations.
   Per-decompilation timeout: 30 seconds; truncation/uncertainty are explicit.
6. Slice 5A adds **no** debugger execution, native code execution, database
   modification, or arbitrary-depth interprocedural propagation.
7. Unsupported or unproven cases remain limitations: complex C++ implicit
   parameters, non-x86-64 platforms, exotic ABIs, aggressive optimizations,
   indirect target recovery, external/thunk normalization, and structural
   equivalence between separate High P-code SSA graphs.

### Next step is not part of the freeze

A future bounded Slice 5B, if justified by actual reverse-engineering work,
must be a separate design and verification effort. In particular, upstream
ReVa's existing intraprocedural dataflow implementation may silently truncate
a 500-operation slice; deterministic traversal and explicit completion
semantics are prerequisites to any trustworthy interprocedural traversal.

**Evidence qualification:** this record relies on user-reported Fedora
terminal transcripts for executed tests. It does not claim a third-party
audit, independent reproduction across operating systems, or soundness for
all Ghidra decompiler output.
