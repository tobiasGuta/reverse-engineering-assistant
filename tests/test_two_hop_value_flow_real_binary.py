"""Two-hop candidate tracing against a real compiled ELF in isolated Ghidra.

The fixture is compiled and imported, NEVER executed. Its source declarations
are supplied as trusted metadata inside the disposable Ghidra project;
ReVa itself must not infer an unknown ABI or claim runtime equivalence.
Run only with a scratch Ghidra installation containing the development
extension, following the existing isolated native-ELF testing pattern.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess

import pytest

from tests.test_call_boundary_real_binary import tool
from tests.test_one_hop_value_flow_real_binary import (
    callsite,
    establish_known_fixture_signature,
)

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
    pytest.mark.timeout(420),
]

C_SOURCE = r"""
__attribute__((noinline, used))
int reva_twohop_sink(int value) {
    return (value ^ 0x59) + 9;
}

__attribute__((noinline, used))
int reva_twohop_middle(int value) {
    int adjusted = value + 2;
    return reva_twohop_sink(adjusted) + 3;
}

__attribute__((noinline, used))
int reva_twohop_entry(int seed) {
    return reva_twohop_middle(seed + 4);
}

int main(int argc, char **argv) {
    (void)argv;
    return reva_twohop_entry(argc);
}
"""


async def test_native_two_hop_direct_call_candidate(
    mcp_stdio_client, isolated_workspace: Path,
) -> None:
    compiler = shutil.which("cc")
    assert compiler, "A C compiler is required for native-ELF verification"
    source = isolated_workspace / "reva_twohop_O0.c"
    binary = isolated_workspace / "reva_twohop_O0.elf"
    source.write_text(C_SOURCE)
    subprocess.run(
        [
            compiler, "-O0", "-fno-inline",
            "-fno-optimize-sibling-calls", "-fno-pie", "-no-pie",
            "-o", str(binary), str(source),
        ],
        check=True, capture_output=True, text=True, timeout=45,
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

    first_site = await callsite(
        mcp_stdio_client, program,
        "reva_twohop_entry", "reva_twohop_middle",
    )
    second_site = await callsite(
        mcp_stdio_client, program,
        "reva_twohop_middle", "reva_twohop_sink",
    )
    assert first_site != second_site

    # This metadata derives from C_SOURCE, not from guessed call semantics.
    # Only the disposable imported analysis project receives annotations.
    for name, signature in (
        ("reva_twohop_middle", "int reva_twohop_middle(int value)"),
        ("reva_twohop_sink", "int reva_twohop_sink(int value)"),
    ):
        known = await establish_known_fixture_signature(
            mcp_stdio_client, program, name, signature,
        )
        assert known["model"] and known["functionAddress"], known

    result = await tool(
        mcp_stdio_client, "trace-call-argument-two-hop",
        programPath=program,
        callsite=first_site,
        argumentIndex=0,
        maxOperations=128,
        maxReportedOperations=128,
    )
    assert result["caller"]["name"] == "reva_twohop_entry", result
    assert result["intermediateFunction"]["name"] == (
        "reva_twohop_middle"
    ), result
    assert result["firstBoundaryStatus"] == (
        "decompiler_positional_candidate"
    ), result
    assert "NO proven runtime" in result["semantics"], result

    middle = result["intermediateFormalEvidence"]
    assert middle["function"]["name"] == "reva_twohop_middle", result
    assert middle["operationCount"] > 0, result
    assert middle["operations"], result
    assert middle["operationCount"] <= 128, result
    assert middle["operationSummary"]["scope"] == (
        "observed_slice_operations_only"
    ), result
    assert result["observedForwardedArgumentCount"] >= 1, result

    positive = [
        candidate for candidate in result["candidateSecondHops"]
        if candidate["boundaryStatus"] == "decompiler_positional_candidate"
        and candidate.get("callee", {}).get("name") == "reva_twohop_sink"
        and candidate["argumentIndex"] == 0
    ]
    assert len(positive) == 1, result
    selected = positive[0]
    assert int(selected["callsite"], 16) == int(second_site, 16), result
    assert selected["intermediateDependency"] == (
        "observed_ssa_dependency_candidate"
    ), selected
    assert selected["intermediateArgumentEvidence"]["function"][
        "name"
    ] == "reva_twohop_middle", selected
    assert selected["calleeFormalEvidence"]["function"]["name"] == (
        "reva_twohop_sink"
    ), selected
    assert selected["calleeFormalEvidence"]["operationCount"] > 0, selected
    assert selected["calleeFormalEvidence"]["operationCount"] <= 128, selected
    assert selected["calleeFormalEvidence"]["operations"], selected
    assert result["secondBoundaryStatus"] == (
        "candidate_list_available"
    ), result
    # Coverage and budget flags are authoritative; no assertion of runtime
    # equality or complete origin discovery is implied by these candidates.
    for evidence in (
        result["callerArgumentEvidence"],
        middle,
        selected["intermediateArgumentEvidence"],
        selected["calleeFormalEvidence"],
    ):
        assert evidence["operationCount"] <= 128, evidence
        assert evidence["reportedOperationCount"] <= 128, evidence
        assert evidence["truncationReason"] is None or isinstance(
            evidence["truncationReason"], str
        ), evidence

    assert hashlib.sha256(binary.read_bytes()).hexdigest() == before
