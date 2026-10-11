# ReVa Slice 5A — Call-boundary evidence validation

**Status: UNFROZEN; further host verification required.**

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

These results apply to the branch revision **before** the post-test review
corrections below. A subsequent green run is required before closure.

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
`cc` and `objdump` for both `-O0` and `-O2`, but the revised MCP/Ghidra
tests **have not yet run on Fedora**.

### R3. Design limits retained intentionally

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

1. Pull the updated Slice 5A branch and refresh **only Slice 5A-owned**
   files into the existing local upstream checkout.
2. Re-run the offline guarded-applicator tests.
3. Re-run the entire isolated `verify_static_analysis_expansion.sh`
   pipeline, including the revised native ELF O0/O2 and bounded-argument
   tests and the return-scan classification regression.
4. Examine any failed decompiler recovery or false-positive mappings and
   correct the implementation rather than weakening assertions arbitrarily.
5. Confirm via a diff-based review that the frozen Slices 1–4 Java providers
   remain unchanged.
6. Complete an adversarial correctness review of special ABI layouts,
   C++ hidden parameters, variance in compiler outputs, and behavior when
   indirect or external targets are unresolved before freezing.

**Release gate:** remain UNFROZEN and unmerged until all required checks
are supported by evidence. Test completion is not, by itself, evidence of
production correctness for arbitrary binaries.
