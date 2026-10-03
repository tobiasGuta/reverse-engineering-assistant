# Slice 2 Stack/ABI Live Regression Prompt

Use the ReVa MCP server to inspect the currently open Ghidra program.

This is a read-only regression test for the new stack/ABI tools.

## Safety rules

- Use read-only ReVa operations only.
- Do not execute the binary.
- Do not run scripts or PyGhidra.
- Do not use shell commands.
- Do not modify labels, comments, types, signatures, functions, variables, bookmarks, bytes, instructions, or any other Ghidra database state.
- Do not use network access.
- Do not construct or send an exploit.

## Setup

1. Call `list-open-programs`.
2. Identify the exact open `programPath`.
3. Identify `main` (or the primary small test function if this is not Grimoire).
4. Use that exact program path in every subsequent call.

## TEST A — StackFrame contract

Call `get-function-stack-frame` on `main`.

Report:

- `offsetSemantics`
- stack pointer register / stack space / stack base space
- frame size, local size, parameter size
- parameter offset and whether it is known
- return-address offset
- stack growth direction
- all returned defined stack variables with:
  - name
  - kind
  - type / length
  - stackOffset
  - storage kind
  - storage varnodes
  - byteDeltaFromStackOffsetToReturnAddress

Verify that every reported stack offset is treated as a **Ghidra stack-space offset**, not as a literal RBP/RSP displacement.

If `local_58` and `local_c` are present, report their stack-space offsets and the byte delta from `local_58` to the return-address offset. Do not infer machine-frame offsets yet.

## TEST B — ABI contract

Call `get-function-abi` on the same function.

Report:

- effective and formal prototypes
- signature source
- calling-convention name and whether it is unresolved
- custom-storage / varargs / no-return / stack-purge facts
- compiler stack model
- PrototypeModel name and flags when available
- stackParameterOffset
- stackParameterAlignment and its exact semantic description
- stackShift
- extraPop / whether known
- return-address storage
- potential input-register storage
- unaffected / killed-by-call / likely-trash storage
- return-value storage
- parameter storage

Explicitly verify that `stackParameterAlignment` is **not** described as the required function-entry or call-site RSP alignment.

## TEST C — Cross-check against machine semantics

Only after Tests A and B, use `get-pcode` or decompilation on the relevant stack-addressing instructions.

For Grimoire specifically, cross-check the instruction that forms the buffer passed to `gets` and the access to `local_c`.

Explain clearly how:

- Ghidra stack-space offsets
- machine RBP/RSP displacement operands
- derived byte distances

can all describe the same storage while using different coordinate systems.

Do not overwrite the StackFrame facts with the machine displacements.

## Final verdict

Return:

A. StackFrame contract: PASS/FAIL and any ambiguity  
B. ABI contract: PASS/FAIL and any ambiguity  
C. Coordinate-system clarity: PASS/FAIL  
D. Any generic ReVa API defect discovered  
E. Whether Slice 2 is ready to freeze or needs correction
