"""Slice 5B prerequisite: trace native ELF call sites with truthful limits.

Runs only inside the isolated Ghidra/PyGhidra MCP verifier. Compiled ELF
fixtures are NOT executed. This tests the existing tracing tool's enriched
completion contract on both unoptimized and optimized code.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_call_boundary_real_binary import (
    C_SOURCE, canonical_address, resolve_function_address, tool,
)

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
    pytest.mark.timeout(420),
]


@pytest.mark.parametrize("optimization", ["O0", "O2"])
async def test_bounded_trace_completion_on_real_elf(
    optimization: str, mcp_stdio_client, isolated_workspace: Path
) -> None:
    compiler = shutil.which("cc")
    assert compiler, "C compiler required for native fixture"
    source = isolated_workspace / f"dataflow_{optimization}.c"
    binary = isolated_workspace / f"dataflow_{optimization}.elf"
    source.write_text(C_SOURCE)
    subprocess.run(
        [compiler, f"-{optimization}", "-fno-inline",
         "-fno-optimize-sibling-calls", "-fno-pie", "-no-pie",
         "-o", str(binary), str(source)],
        capture_output=True, text=True, check=True, timeout=45,
    )
    before = hashlib.sha256(binary.read_bytes()).hexdigest()

    imported = await tool(
        mcp_stdio_client, "import-file",
        path=str(binary), destinationFolder="/",
        analyzeAfterImport=True, enableVersionControl=False,
    )
    assert imported.get("success") is True, imported
    assert len(imported.get("importedPrograms", [])) == 1, imported
    program = imported["importedPrograms"][0]
    target = await resolve_function_address(
        mcp_stdio_client, program, "slice5a_transform"
    )
    cfg = await tool(
        mcp_stdio_client, "get-function-cfg",
        programPath=program, function="slice5a_caller", maxBlocks=64,
    )
    assert not cfg.get("truncated", False), cfg
    sites = [
        ref.get("fromInstruction")
        for block in cfg.get("blocks", [])
        for ref in block.get("calls", [])
        if ref.get("to") and
        canonical_address(ref["to"]) == canonical_address(target)
    ]
    assert len(sites) == 1, cfg
    callsite = sites[0]

    for direction in ("forward", "backward"):
        name = "trace-data-flow-" + direction
        arguments = {"programPath": program, "address": callsite}
        result = await tool(mcp_stdio_client, name, **arguments)
        again = await tool(mcp_stdio_client, name, **arguments)

        assert result["direction"] == direction, result
        assert result["startAddress"] == callsite, result
        assert result["operationCount"] == len(result["operations"]), result
        assert result["operationLimit"] == 500, result
        assert result["complete"] is True, result
        assert result["truncated"] is False, result
        assert result["truncationReason"] is None, result
        assert result["terminatorsComplete"] is True, result
        assert result["visitedVarnodeCount"] >= 1, result
        assert result["scannedEdgeCount"] >= 0, result
        assert "within one function" in result["sliceSemantics"], result
        assert result["operations"] == again["operations"], (result, again)
        assert result["terminators"] == again["terminators"], (result, again)

    assert hashlib.sha256(binary.read_bytes()).hexdigest() == before
