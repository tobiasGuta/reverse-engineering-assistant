# Slice 4 Stack Execution State — Live Smoke Test

Use ReVa only. Stay strictly read-only.

Do not run scripts or PyGhidra. Do not execute the binary. Do not use shell
commands, network access, debugger control, emulation, database mutations,
renaming, comments, labels, bookmarks, datatype changes, function creation,
prototype changes, imports, analysis commands, or any other write/action tool.

Work only with the currently open Ghidra program. Identify its exact programPath
first and use that path for every call.

## Goal

Validate the new get-function-stack-state tool as a generic static bridge between
machine instructions and Ghidra's entry-stack-pointer-relative symbolic state.

The tool is not an execution trace and must not claim absolute runtime stack
addresses or stack-pointer modulo alignment.

## A — Function-wide stack state

Choose a non-trivial function with a conventional prologue and at least one call.
For the current x86-64 regression target, main is preferred.

Call get-function-stack-state with:
- the chosen function
- maxInstructions large enough to cover it
- registers containing RBP when that register exists

Report:
- stackPointerRegister
- instructionOrder
- analysisAvailable
- entry instruction depthBefore
- stack depth immediately before and after the prologue's stack allocation,
  using adjacent pre-instruction states / fallThroughDelta
- RBP entry-stack-pointer-relative value after the frame pointer is established,
  if Ghidra resolves it

Do not infer an absolute RSP address.

## B — Machine stack operand bridge

Find one machine operand based on RBP or RSP with a scalar displacement, such as
a local-buffer access.

Inspect that instruction's operands[] result.

If Ghidra reports stackOffsetKnown:
- report the operand text
- report the resolved stackOffset
- compare it with get-function-stack-frame only within the explicitly supported
  Ghidra/entry-relative coordinate evidence
- do not generalize one observed RBP↔stack mapping into an architecture-wide rule

If the operand cannot be resolved, report that as evidence rather than guessing.

## C — Call-site state

Pick a direct call in the function, preferably strcmp, gets, puts, printf, or
another already visible call.

Report:
- call instruction/address
- depthBefore
- stackPointerDepthBefore
- requested frame-register depth, if known
- fallThroughDepthBefore
- fallThroughDelta

For an ordinary call whose propagated fall-through depth is unchanged, describe
fallThroughDelta=0 only as the net static state after the call returns. Do not
claim that the machine CALL instruction never temporarily changes the hardware
stack.

Cross-check the same call with get-callsite-semantics, but keep the contracts
separate:
- get-function-stack-state = entry-relative stack/register state
- get-callsite-semantics = High P-code target/argument provenance
- get-function-abi = callee ABI/storage facts

## D — Pagination / canonicalization

Repeat with startAddress pointing into the middle of an instruction and a small
maxInstructions.

Verify:
- requestedStartAddress preserves the user request
- canonicalStartAddress is the containing instruction start
- returnedInstructionCount respects the bound
- truncated and nextStartAddress are accurate
- continuation preserves ascending address order

## E — Unknown/invalid state handling

Find at least one unavailable register/operand depth naturally if possible.
Verify unknown/invalid sentinels are normalized as:
- known: false
- status: unknown or invalid
- value/stackOffset: null

Do not treat Integer.MAX_VALUE-style sentinels as semantic depths.

## Final verdict

Return:

A. Entry-relative stack-state contract: PASS / FAIL
B. Frame-register tracking: PASS / FAIL
C. Machine stack-operand bridge: PASS / FAIL
D. Call-site net fall-through state: PASS / FAIL
E. Pagination/canonicalization: PASS / FAIL
F. Unknown/invalid normalization: PASS / FAIL
G. Any generic API defect discovered
H. Slice 4 status: READY FOR REFINEMENT / NEEDS CORRECTION

A failure is useful. Do not work around a generic defect with scripts, execution,
database edits, debugger actions, or guessed mappings.
