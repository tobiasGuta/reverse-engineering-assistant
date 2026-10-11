# ReVa Slice 5A — Call-boundary evidence validation

**Status: UNFROZEN; post-review ELF verification passed; final prototype-guard regression pending.**

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
`candidateFormalIndex`. These tests **have not yet been run on Fedora**.

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

## Remaining acceptance gates

1. Pull the development branch and refresh **only Slice 5A-owned** files
   in the existing upstream checkout. The existing Slices 1–4 provider files
   must remain unchanged.
2. Since the second complete verifier passed and only Java *integration
   tests and validation documentation* were modified afterward, run
   `gradle integrationTest --tests '*CallBoundaryToolProviderIntegrationTest'`
   against the unchanged Slice 5A provider. This validates the two new
   Ghidra prototype guards plus all existing Slice 5A synthetic cases.
   The already-green native ELF O0/O2 and Python MCP transport acceptance
   remains applicable to the identical provider source. Repeat the full
   isolated verifier if any production/provider code changes during fixes.
3. If a new test fails, diagnose the underlying Ghidra state and fix the
   implementation or fixture only when justified by evidence.
4. Recheck the GitHub base-to-branch comparison and verify the API/ABI
   uncertainty contract. Residual limitations, including C++ auto-parameters,
   unknown indirect targets, external thunks, other architectures, and
   cross-function propagation, must remain explicitly documented.
5. Freeze only after all currently required checks pass and the scope
   is judged reliable for *bounded, candidate-only call-boundary evidence*.

**Release gate:** remain UNFROZEN and unmerged until all required checks
are supported by evidence. Test completion is not, by itself, evidence of
production correctness for arbitrary binaries.
