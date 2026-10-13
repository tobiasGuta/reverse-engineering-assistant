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


async def establish_known_fixture_signature(
    client, program: str, callee_name: str, signature: str,
) -> dict:
    """Annotate only this imported ELF inside the disposable MCP project.

    The C declaration comes from the compiled fixture source, not from an
    inferred decompiler guess. The Ghidra compiler spec for this imported ELF
    supplies its platform-default calling convention. This is a controlled
    acceptance fixture, NOT an inference of ABI facts by the one-hop tool.
    """
    address = await resolve_function_address(client, program, callee_name)
    parsed = await tool(
        client, "set-function-prototype",
        programPath=program, location=address,
        signature=signature, createIfNotExists=False,
    )
    assert parsed.get("success") is True, parsed
    assert parsed.get("created") is False, parsed
    assert parsed.get("usingCustomStorage") is False, parsed

    # The upstream prototype-setting tool deliberately does not modify the
    # calling convention. Ghidra must receive that metadata separately.
    # This inline script runs only against the disposable project's import,
    # after verifying the exact function identity and platform-default model.
    entry = canonical_address(address)
    code = f"""
fm = currentProgram.getFunctionManager()
addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress({entry})
func = fm.getFunctionAt(addr)
assert func is not None and func.getName() == {callee_name!r}
model = currentProgram.getCompilerSpec().getDefaultCallingConvention()
assert model is not None
model_name = str(model.getName())
assert model_name and model_name != 'unknown'
assert func.getParameterCount() == {signature.count(',') + 1}
tx = currentProgram.startTransaction('test-only known ABI for imported ELF')
success = False
try:
    func.setCallingConvention(model_name)
    assert not func.hasUnknownCallingConventionName()
    assert not func.hasCustomVariableStorage()
    assert not func.hasVarArgs()
    assert str(func.getSignatureSource()) == 'USER_DEFINED'
    success = True
finally:
    currentProgram.endTransaction(tx, success)
print('REVA_KNOWN_ABI=' + model_name)
"""
    applied = await tool(
        client, "run-script", programPath=program, code=code,
        timeoutSeconds=30,
    )
    assert applied.get("success") is True, applied
    assert applied.get("timedOut") is False, applied
    assert applied.get("stdoutTruncated") is False, applied
    assert "REVA_KNOWN_ABI=" in applied.get("stdout", ""), applied
    return {"functionAddress": address, "signature": signature,
            "model": applied["stdout"].split("REVA_KNOWN_ABI=", 1)[1].split()[0]}


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

    # Positive real-binary gate: declare the known C function signatures in
    # the disposable Ghidra project and bind their platform-default ABI.
    # This proves the tool can return two independent graphs when the
    # prerequisite prototype evidence is actually established.
    known_first = await establish_known_fixture_signature(
        mcp_stdio_client, program, "slice5a_transform",
        "int slice5a_transform(int value)",
    )
    known_second = await establish_known_fixture_signature(
        mcp_stdio_client, program, "slice5a_transform_two",
        "int slice5a_transform_two(int first, int second)",
    )
    assert known_first["model"] and known_second["model"], (
        known_first, known_second
    )

    for site_address, argument_index, expected_callee in (
        (site, 0, "slice5a_transform"),
        (second_site, 1, "slice5a_transform_two"),
    ):
        positive = await tool(
            mcp_stdio_client, "trace-call-argument-one-hop",
            programPath=program, callsite=site_address,
            argumentIndex=argument_index, maxOperations=128,
        )
        assert positive["relationStatus"] == (
            "decompiler_positional_candidate"
        ), positive
        assert positive["complete"] is True, positive
        assert positive["callee"]["name"] == expected_callee, positive
        assert positive["calleeUnknownCallingConvention"] is False, positive
        assert positive["calleeCustomStorage"] is False, positive
        assert positive["calleeVariadic"] is False, positive
        assert positive["calleeSignatureSource"] == "USER_DEFINED", positive
        assert positive["prototypeAmbiguities"] == [], positive
        assert positive["calleeFormal"]["slot"] == argument_index, positive
        assert positive["callerEvidence"]["complete"] is True, positive
        assert positive["calleeEvidence"]["complete"] is True, positive
        assert positive["callerEvidence"]["function"]["name"] in (
            "slice5a_caller", "slice5a_caller_two"
        ), positive
        assert positive["calleeEvidence"]["function"]["name"] == (
            expected_callee
        ), positive
        assert positive["calleeEvidence"]["ssaSeeds"], positive
        assert positive["callerEvidence"]["operations"] != (
            positive["calleeEvidence"]["operations"]
        ), positive
        assert "never a runtime-proven" in positive["relationSemantics"], positive

    assert hashlib.sha256(binary.read_bytes()).hexdigest() == before
