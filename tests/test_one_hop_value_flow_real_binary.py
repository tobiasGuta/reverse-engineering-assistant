"""Slice 5B one-hop tool against actual compiled ELF functions via scratch MCP.

No fixture binary is executed; no persistent Ghidra extension or Codex
MCP service is touched by the isolated verification workflow.
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


async def callsite(client, program, caller_name, callee_name):
    target = await resolve_function_address(client, program, callee_name)
    cfg = await tool(
        client, "get-function-cfg",
        programPath=program, function=caller_name, maxBlocks=64,
    )
    assert not cfg.get("truncated", False), cfg
    sites = [
        ref["fromInstruction"]
        for block in cfg["blocks"]
        for ref in block.get("calls", [])
        if ref.get("to") and canonical_address(ref["to"]) ==
        canonical_address(target)
    ]
    assert len(sites) == 1, cfg
    return sites[0]


@pytest.mark.parametrize("optimization", ["O0", "O2"])
async def test_native_one_hop_call_argument(
    optimization: str, mcp_stdio_client, isolated_workspace: Path
):
    compiler = shutil.which("cc")
    assert compiler, "C compiler required for compiled ELF acceptance"
    source = isolated_workspace / f"onehop_{optimization}.c"
    binary = isolated_workspace / f"onehop_{optimization}.elf"
    source.write_text(C_SOURCE)
    subprocess.run(
        [compiler, f"-{optimization}", "-fno-inline",
         "-fno-optimize-sibling-calls", "-fno-pie", "-no-pie",
         "-o", str(binary), str(source)],
        capture_output=True, text=True, check=True, timeout=45,
    )
    assert binary.read_bytes().startswith(b"\x7fELF")
    before = hashlib.sha256(binary.read_bytes()).hexdigest()

    imported = await tool(
        mcp_stdio_client, "import-file", path=str(binary),
        destinationFolder="/", analyzeAfterImport=True,
        enableVersionControl=False,
    )
    assert imported.get("success") is True, imported
    assert len(imported.get("importedPrograms", [])) == 1, imported
    program = imported["importedPrograms"][0]

    site = await callsite(
        mcp_stdio_client, program, "slice5a_caller", "slice5a_transform"
    )
    args = dict(
        programPath=program, callsite=site,
        argumentIndex=0, maxOperations=128,
    )
    result = await tool(
        mcp_stdio_client, "trace-call-argument-one-hop", **args
    )
    repeated = await tool(
        mcp_stdio_client, "trace-call-argument-one-hop", **args
    )

    assert result["relationStatus"] == "decompiler_positional_candidate", result
    assert result["complete"] is True, result
    assert result["caller"]["name"] == "slice5a_caller", result
    assert result["callee"]["name"] == "slice5a_transform", result
    assert result["opcode"] == "CALL", result
    assert result["argumentCount"] == 1, result
    assert result["calleeFormal"]["slot"] == 0, result
    assert result["callerEvidence"]["function"]["name"] == (
        "slice5a_caller"
    ), result
    assert result["calleeEvidence"]["function"]["name"] == (
        "slice5a_transform"
    ), result
    assert result["callerEvidence"]["complete"] is True, result
    assert result["calleeEvidence"]["complete"] is True, result
    assert "only a decompiler-derived" in (
        result["relationSemantics"]
    ), result
    for key in ("callerEvidence", "calleeEvidence"):
        evidence = result[key]
        assert evidence["operationCount"] <= 128, result
        assert evidence["truncated"] is False, result
        assert evidence["operations"] == repeated[key]["operations"], result

    # Exercise a different argument index and a two-formal callee.
    second_site = await callsite(
        mcp_stdio_client, program,
        "slice5a_caller_two", "slice5a_transform_two"
    )
    second = await tool(
        mcp_stdio_client, "trace-call-argument-one-hop",
        programPath=program, callsite=second_site,
        argumentIndex=1, maxOperations=128,
    )
    assert second["relationStatus"] == "decompiler_positional_candidate", second
    assert second["calleeFormal"]["slot"] == 1, second
    assert second["callee"]["name"] == "slice5a_transform_two", second
    assert second["callerEvidence"] is not None, second
    assert second["calleeEvidence"] is not None, second

    assert hashlib.sha256(binary.read_bytes()).hexdigest() == before
