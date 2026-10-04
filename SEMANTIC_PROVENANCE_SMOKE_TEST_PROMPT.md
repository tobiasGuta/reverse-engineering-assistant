# Slice 3 Semantic Provenance — Live Smoke Test

Use ReVa only. Stay strictly read-only.

Do not run scripts or PyGhidra. Do not execute the binary. Do not use shell commands,
network access, debugger control, emulation, database mutations, renaming, comments,
labels, bookmarks, datatype changes, function creation, prototype changes, imports,
analysis commands, or any other write/action tool.

Work only with the currently open Ghidra program. Do not assume its path; identify the
open program first and use that exact programPath for every ReVa call.

## Goal

Validate that Slice 3 exposes authoritative links between decompiler text, Ghidra
High P-code, SSA varnodes/high variables, and machine addresses without pretending
that decompiled text is a one-to-one source map.

## A — Decompiler token provenance

Choose one non-trivial function containing at least one function call.

1. Use the normal decompilation tool to inspect it.
2. Pick the callee function-name token or another meaningful variable token.
3. Call get-decompiler-provenance using tokenText.
4. Report:
   - token text/class
   - display line and contextual line text
   - whether the token has a direct machine-address link
   - PcodeOp link, if any
   - Varnode link, if any
   - HighVariable and HighSymbol links, if any
5. If a direct address is present, repeat with the address selector and verify that:
   - requestedAddress and canonicalInstructionAddress are explicit
   - highPcodeAtAddress is returned independently of token matches
   - token/line context is not described as a one-to-one source mapping

## B — Display-line contract

Take the displayLineNumber returned in Test A and call get-decompiler-provenance
using displayLine only.

Verify that every returned token reports that same displayLineNumber and that the
meaningful token from Test A is still present.

## C — Call-site semantics

Use the direct call address from Test A with get-callsite-semantics.

Report:
- caller and machine call instruction
- CALL versus CALLIND
- direct-target resolution status
- target address/name/prototype when Ghidra resolves them
- decompiler statement text and statement line numbers
- argumentCount / returnedArgumentCount / argumentsTruncated
- each returned High P-code argument Varnode
- immediate producer when available
- relatedDecompilerTokens and their matchKind

Do not infer ABI register placement from the High P-code argument list. If ABI/storage
placement matters, use get-function-abi separately and explicitly distinguish callee
prototype/storage facts from call-site data-flow facts.

## D — Cross-check one argument

For one argument:
1. Compare its call-site Varnode with its immediate producer.
2. If relatedDecompilerTokens are present, explain whether the match is
   varnode-exact or high-variable.
3. Optionally use the existing read-only data-flow tool for a deeper trace.
4. State clearly where Ghidra evidence ends and analyst/model interpretation begins.

## Final verdict

Return:

A. Token-level provenance: PASS / FAIL
B. Display-line stability: PASS / FAIL
C. Call-site target semantics: PASS / FAIL
D. Argument provenance: PASS / FAIL
E. Any generic API defect discovered
F. Slice 3 status: READY FOR REFINEMENT / NEEDS CORRECTION

A failure is useful. Do not work around a generic contract defect with scripts,
execution, database edits, or guessed mappings.
