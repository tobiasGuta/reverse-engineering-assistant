Use ReVa to inspect the currently open binary using read-only operations only.

Exercise the new general static-analysis tools rather than solving a particular challenge:

1. Use get-program-overview to establish program-level facts.
2. Select a non-trivial application function and use get-function-cfg to map its basic blocks and branch edges.
3. Pick a branch-heavy basic block and use get-pcode with scope=basic-block to inspect architecture-neutral semantics.
4. Use list-source-files. If source mappings exist, use get-source-mappings on both a source file and an address in the selected function.
5. Cross-check the results against existing ReVa decompilation, xref, call-graph, and data-flow tools.

Do not execute the binary, run scripts, patch bytes, or modify the Ghidra database.

At the end, report:
- which new tool supplied information that was previously awkward or unavailable,
- any inconsistent or ambiguous results,
- any response that was too large or too small to be useful,
- any tool-schema or error-message improvements you would recommend.
