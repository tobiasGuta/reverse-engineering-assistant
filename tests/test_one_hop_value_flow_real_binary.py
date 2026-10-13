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


def assert_eligible_or_explicitly_ambiguous(result, caller_name, callee_name, index):
    """Never treat Ghidra's unknown calling convention as a proven ABI."""
    assert result["caller"]["name"] == caller_name, result
    assert result["callee"]["name"] == callee_name, result
    assert result["argumentIndex"] == index, result
    assert result["opcode"] == "CALL", result
    assert result["callerEvidence"] is not None, result
    assert "never a runtime-proven" in result["relationSemantics"], result

    status = result["relationStatus"]
    if status == "decompiler_positional_candidate":
        assert result["complete"] is True, result
        assert result["calleeEvidence"] is not None, result
        assert result["calleeFormal"]["slot"] == index, result
        assert result["callerEvidence"]["complete"] is True, result
        assert result["calleeEvidence"]["complete"] is True, result
        assert result["prototypeAmbiguities"] == [], result
        assert result["calleeUnknownCallingConvention"] is False, result
        return True

    assert status == "ambiguous_prototype_or_storage", result
    ambiguities = result["prototypeAmbiguities"]
    assert isinstance(ambiguities, list) and ambiguities, result
    assert set(ambiguities) <= {
        "variadic",
        "custom_parameter_storage",
        "unknown_calling_convention",
        "auto_parameter",
        "forced_indirect_parameter",
    }, result
    assert ("unknown_calling_convention" in ambiguities) == (
        result["calleeUnknownCallingConvention"]
    ), result
    assert ("variadic" in ambiguities) == result["calleeVariadic"], result
    assert ("custom_parameter_storage" in ambiguities) == (
        result["calleeCustomStorage"]
    ), result
    assert result["calleeEvidence"] is None, result
    assert result["complete"] is False, result
    assert "calleeCallingConvention" in result, result
    assert "calleeSignatureSource" in result, result
    return False


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

    known = assert_eligible_or_explicitly_ambiguous(
        result, "slice5a_caller", "slice5a_transform", 0
    )
    assert result["argumentCount"] == 1, result
    sides = ("callerEvidence", "calleeEvidence") if known else ("callerEvidence",)
    for key in sides:
        evidence = result[key]
        assert evidence["operationCount"] <= 128, result
        assert evidence["operations"] == repeated[key]["operations"], result
        assert evidence["operandsTruncated"] is False, result
        for operation in evidence["operations"]:
            assert "sequence" in operation, operation
            assert "inputs" in operation and isinstance(operation["inputs"], list), operation
            assert "output" in operation, operation
            assert "inputsTruncated" in operation, operation

    if known:
        assert result["callerEvidence"]["truncated"] is False, result
        assert result["calleeEvidence"]["truncated"] is False, result
        assert result["calleeEvidence"]["ssaSeeds"], result

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
    assert_eligible_or_explicitly_ambiguous(
        second, "slice5a_caller_two", "slice5a_transform_two", 1
    )
    assert second["argumentCount"] == 2, second

    assert hashlib.sha256(binary.read_bytes()).hexdigest() == before
