"""Slice 5A: inspect compiled Linux ELF call boundaries through real MCP.

The fixture is compiled but NEVER executed. The test uses the isolated
mcp-reva stdio Ghidra project and confirms imported bytes are unchanged.
It exercises both unoptimized and optimized direct function calls.

Run as part of the isolated extension verifier, not against the user's
normal Codex MCP server or persistent Ghidra project.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
    pytest.mark.timeout(420),
]

C_SOURCE = r"""
__attribute__((noinline, used))
int slice5a_transform(int value) {
    return (value ^ 0x5a) + 7;
}

__attribute__((noinline, used))
int slice5a_caller(int seed) {
    volatile int adjusted = seed + 3;
    int transformed = slice5a_transform(adjusted);
    return transformed + 1;
}

int main(int argc, char **argv) {
    (void)argv;
    return slice5a_caller(argc);
}
"""


def decode(result, label: str) -> dict:
    assert result is not None, f"{label}: no MCP response"
    content = getattr(result, "content", None)
    assert content, f"{label}: empty MCP response"
    raw = "\n".join(getattr(item, "text", "") or "" for item in content)
    assert not getattr(result, "isError", False), f"{label}: {raw}"
    parsed = json.loads(raw)
    assert isinstance(parsed, dict), f"{label}: expected JSON object: {raw}"
    return parsed


async def tool(client, name: str, **args) -> dict:
    return decode(await client.call_tool(name, arguments=args), name)


async def resolve_function_address(client, program: str, name: str) -> str:
    """Use the existing paginated ReVa function index; never guess addresses."""
    offset = 0
    for _ in range(40):
        page = await tool(
            client, "get-functions", programPath=program,
            startIndex=offset, maxCount=100,
        )
        found = [
            row for row in page.get("functions", [])
            if row.get("name") == name
        ]
        if found:
            assert len(found) == 1, f"ambiguous function name: {name}"
            return found[0]["address"]
        returned = page.get("actualCount", 0)
        assert isinstance(returned, int)
        if returned == 0 or offset + returned >= page.get("totalCount", 0):
            break
        offset += returned
    pytest.fail(f"{name} absent from Ghidra's analyzed function index")


def canonical_address(raw: str) -> int:
    """Only normal memory addresses are valid in this ELF fixture."""
    return int(raw, 16)


@pytest.mark.parametrize("optimization", ["O0", "O2"])
async def test_compiled_elf_direct_call_boundary(
    optimization: str, mcp_stdio_client, isolated_workspace: Path
) -> None:
    compiler = shutil.which("cc")
    assert compiler, "A C compiler is required for the real-ELF acceptance test"

    source = isolated_workspace / f"slice5a_{optimization}.c"
    binary = isolated_workspace / f"slice5a_{optimization}.elf"
    source.write_text(C_SOURCE)

    command = [
        compiler, f"-{optimization}", "-fno-inline",
        "-fno-optimize-sibling-calls", "-fno-pie", "-no-pie",
        "-o", str(binary), str(source),
    ]
    subprocess.run(
        command, check=True, capture_output=True, text=True,
        timeout=45,
    )
    assert binary.read_bytes().startswith(b"\x7fELF")
    digest_before = hashlib.sha256(binary.read_bytes()).hexdigest()

    imported = await tool(
        mcp_stdio_client, "import-file", path=str(binary),
        destinationFolder="/", analyzeAfterImport=True,
        enableVersionControl=False,
    )
    assert imported.get("success") is True, imported
    programs = imported.get("importedPrograms", [])
    assert len(programs) == 1, imported
    program = programs[0]

    callee_address = await resolve_function_address(
        mcp_stdio_client, program, "slice5a_transform"
    )
    cfg = await tool(
        mcp_stdio_client, "get-function-cfg",
        programPath=program, function="slice5a_caller", maxBlocks=64,
    )
    assert cfg.get("function") == "slice5a_caller", cfg
    assert not cfg.get("truncated", False), cfg

    candidates = [
        ref.get("fromInstruction")
        for block in cfg.get("blocks", [])
        for ref in block.get("calls", [])
        if ref.get("to") and
        canonical_address(ref["to"]) == canonical_address(callee_address)
    ]
    assert len(candidates) == 1, (
        f"Expected one resolved native call to slice5a_transform "
        f"({optimization}); CFG={cfg}"
    )
    callsite = candidates[0]
    assert callsite, cfg

    result = await tool(
        mcp_stdio_client, "inspect-call-boundary",
        programPath=program, callsite=callsite, maxArguments=16,
    )
    assert result.get("caller", {}).get("name") == "slice5a_caller", result
    assert result.get("callOperationCount") == 1, result
    assert not result.get("callOperationsTruncated"), result
    call = result["calls"][0]
    assert call["opcode"] == "CALL", result
    assert call.get("targetKind") == "direct_internal", result
    assert call.get("callee", {}).get("name") == "slice5a_transform", result
    assert canonical_address(call.get("targetAddress")) == canonical_address(
        callee_address
    ), result
    assert call.get("argumentCount", 0) >= 1, result
    assert not call.get("argumentsTruncated"), result
    assert call.get("calleeReturnSiteCount", 0) >= 1, result
    assert not call.get("returnSitesTruncated"), result
    assert not call.get("returnScanTruncated"), result
    assert call.get("mappingStatus") in {
        "decompiler_positional_candidate", "ambiguous_prototype_or_storage"
    }, result
    assert call.get("mappingStatus") != "runtime_verified", result
    if call["mappingStatus"] == "decompiler_positional_candidate":
        assert call["arguments"][0]["candidateFormalIndex"] == 0, result

    digest_after = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert digest_before == digest_after, "ELF input bytes were modified"
