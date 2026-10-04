# Stack Execution State Slice 4 — Frozen Validation Record

Date frozen: **2026-10-04**

Branch: `feat/stack-execution-state`

Code head before this documentation commit:

- `a84983b3260aa4eb510fccc55724c600f7d2c586` — model known and unknown callee purge in integration coverage

Slice 4 is frozen after the complete automated verification path and a final live, read-only regression against a real x86-64 ELF. The freeze means the per-instruction stack-state contract should not be redesigned or broadened without new evidence of a generic correctness, safety, or interoperability defect.

## Scope

Slice 4 adds one read-only MCP tool:

- `get-function-stack-state`

It exposes a bounded view of Ghidra `CallDepthChangeInfo` symbolic state across a function. The tool reports per-instruction stack depth, entry-stack-pointer-relative register values, normal fall-through deltas, and operand stack offsets when Ghidra itself can resolve them.

No native execution, debugger control, shell execution, network activity, arbitrary PyGhidra scripting, P-code emulation, binary patching, or Ghidra database mutation was added.

## Frozen semantic invariants

### Instruction-order contract

Results are returned in ascending program-address order.

Frozen invariant:

> Instruction order is a bounded static listing order, not an execution trace or control-flow traversal.

### Pre-instruction depth

`depthBefore` is the `CallDepthChangeInfo.getDepth(address)` state captured before the instruction.

`stackPointerDepthBefore` is the entry-stack-pointer-relative value from `getSPDepth(address)` when Ghidra can resolve it.

Frozen invariants:

> These values are relative to the symbolic stack-pointer value at function entry. They are not absolute runtime addresses.

> A known symbolic depth does not imply stack-pointer modulo alignment.

### Requested register depth

Requested registers are resolved through `CallDepthChangeInfo.getRegDepth(address, register)`.

A register may be unavailable before the machine instruction that establishes its relationship to the entry stack pointer.

Frozen invariant:

> Unknown/invalid register state is preserved as unavailable; the tool does not infer relationships from register names or calling-convention folklore.

### Fall-through delta

`fallThroughDelta` is derived from two Ghidra pre-instruction states:

`depthBefore(fallThrough) - depthBefore(current)`

and is reported only when both states are known.

Frozen invariants:

> The value describes the statically propagated normal fall-through edge.

> For a call, `fallThroughDelta = 0` means the net static stack state at the caller's fall-through after the callee returns. It is not a claim that the hardware CALL instruction has no transient stack effect.

> Unknown post-call state remains unknown; the tool does not substitute zero.

### Callee-purge uncertainty

The first automated Slice 4 run exposed an invalid test assumption: the synthetic callee lacked a known purge size while the test demanded a known post-call zero delta.

The fixture was split into two cases:

- explicit zero purge -> post-call state may remain known and `fallThroughDelta = 0`
- unresolved purge -> post-call depth and fall-through delta remain unknown/null when Ghidra cannot prove them

Frozen invariant:

> The tool reports Ghidra's propagated state; it does not convert unresolved callee purge/calling-convention information into an assumed zero stack delta.

### Operand stack offsets

Operand offsets are reported only from `CallDepthChangeInfo.getStackOffset(instruction, operandIndex)`.

The final real-binary regression demonstrated an important limitation: Ghidra returned `invalid` for the x86-64 operand `[RBP-0x50]` even though RBP itself was symbolically known.

Frozen invariants:

> The tool never guesses an operand stack offset from a base-register name and displacement when `getStackOffset()` does not resolve it.

> Separate returned facts may be reconciled by an analyst/model when the arithmetic is explicit and local to the function, but that inference must remain distinct from the direct tool field.

### Sentinel normalization

Ghidra `Function.UNKNOWN_STACK_DEPTH_CHANGE` and `Function.INVALID_STACK_DEPTH_CHANGE` sentinels are normalized to schema-stable unavailable values.

Frozen form:

- `known: false`
- `status: "unknown"` or `"invalid"`
- `value: null`

Operand stack-offset sentinels are likewise normalized to `stackOffset: null`.

Frozen invariant:

> Raw sentinel integers must never leak into semantic stack-depth fields.

### Pagination and canonicalization

An optional `startAddress` may point inside an instruction.

Frozen behavior:

- `requestedStartAddress` preserves the original request
- `canonicalStartAddress` is the containing instruction start
- `returnedInstructionCount` respects `maxInstructions`
- `truncated` reflects omitted instructions
- `nextStartAddress` is the next instruction to request
- continuation preserves ascending address order

## Automated verification

The complete local verification harness passed after the callee-purge fixture correction:

- normal Gradle tests
- focused integration tests for Slices 1–4
- self-contained stack-state synthetic fixture
- entry-relative stack-depth tracking
- frame-register tracking
- resolvable stack-operand coverage
- known zero-purge call fall-through coverage
- unknown callee-purge normalization coverage
- pagination/canonicalization coverage
- unknown register rejection
- extension packaging via `buildExtension`
- disposable isolated Ghidra installation
- CPython 3.13 MCP transport tests

The final automated gate completed successfully before the live freeze regression.

## Final live regression

The final regression used only read-only ReVa operations against the open `/grimoire` x86-64 ELF and focused on `main`.

### Entry-relative prologue state

Validated machine facts:

- entry `PUSH RBP`: `depthBefore = 0`
- after `PUSH RBP`: normal fall-through depth `-8`
- `MOV RBP,RSP`: pre-instruction depth `-8`
- after frame-pointer establishment, RBP resolves to `entrySP - 8`
- `SUB RSP,0x50`: pre-instruction depth `-8`
- normal fall-through delta: `-80`
- first instruction after allocation: `depthBefore = -88`

RBP is invalid before the establishing instruction, becomes known as `-8` afterward, remains stable through the body, and becomes invalid again after `LEAVE` restores the caller's frame pointer.

### RBP-relative machine operand reconciliation

For the machine operand `[RBP-0x50]`:

- `get-function-stack-state` reports RBP = `entrySP - 8`
- machine displacement = `-0x50` (`-80`)
- direct `getStackOffset()` result = invalid / null
- `get-function-stack-frame` reports the corresponding local at Ghidra `Stack[-0x58]`

The evidence-supported arithmetic is:

`-8 + (-80) = -88 = -0x58`

This reconciles the machine operand with the Ghidra stack-space coordinate for this function without changing the direct operand-offset field or generalizing the relationship to other functions/architectures.

A second local access produced the same local-function relationship:

`RBP - 0x4 -> -8 + (-4) = -12 = Stack[-0xc]`

### Call-site state

At the direct `strcmp` call:

- `depthBefore = -88`
- `stackPointerDepthBefore = -88`
- RBP depth = `-8`
- fall-through depth = `-88`
- `fallThroughDelta = 0`

At the direct `print_flag` call the same net caller state was preserved.

The regression explicitly treated zero as net post-return static state, not as absence of the hardware CALL return-address push.

### Cross-surface separation

The final regression kept three evidence surfaces distinct:

- `get-function-stack-state` -> entry-relative machine stack/register state
- `get-callsite-semantics` -> High P-code target/argument provenance
- `get-function-abi` -> callee calling-convention and storage facts

For `strcmp`, ABI purge was known zero.

For `print_flag`, function-level purge/calling-convention resolution was incomplete, while the compiler model still allowed Ghidra's propagation to preserve the caller's net state. The tool reported the propagated state without claiming stronger function-specific ABI certainty.

### Pagination

A request starting at `0x00401218`, in the middle of the three-byte `MOV RBP,RSP` instruction, produced:

- requested start: `0x00401218`
- canonical start: `0x00401217`
- exactly two returned instructions
- next start: `0x0040121e`
- `truncated: true`

Continuation from `0x0040121e` remained in ascending address order.

### Unknown / invalid state

The live regression observed naturally unavailable facts:

- RBP at function entry and after return: invalid/null
- non-fall-through edges: unknown/null fall-through depth
- unresolved RBP-relative `getStackOffset()`: invalid/null

No raw Ghidra stack-depth sentinel integers leaked into JSON.

## Final verdict

- entry-relative stack-state contract: **PASS**
- frame-register tracking: **PASS**
- RBP-relative / StackFrame reconciliation: **PASS**
- direct machine operand stack-offset provenance: **PASS**, with the frozen limitation that unresolved Ghidra `getStackOffset()` results remain invalid/null
- call-site net post-return state: **PASS**
- unknown callee-purge handling: **PASS**
- pagination/canonicalization: **PASS**
- sentinel normalization: **PASS**
- remaining generic API defect found by the final regression: **none**
- Slice 4 freeze readiness: **READY**

## Deferred work

The next major realism step is a read-only debugger observer. Objective function querying, richer generic debug-metadata adapters, BSim-assisted similarity, and eventually bounded P-code emulation remain later candidates. None of those capabilities are part of the frozen Slice 4 contract.
