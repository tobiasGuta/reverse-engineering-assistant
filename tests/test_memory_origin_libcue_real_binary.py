"""Real CVE-2023-43641 binary acceptance for ReVa memory-origin candidates.

Imports existing locally compiled libcue shared objects into an isolated
scratch MCP Ghidra project. Neither shared object is loaded nor executed.
The new tool must expose the known yyparse High P-code LOAD and report
uncertainty even if it finds one or more candidate STORE expressions.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tests.test_call_boundary_real_binary import (
    canonical_address, resolve_function_address, tool,
)

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
    pytest.mark.timeout(420),
]

ROOT = Path("/mnt/Development/Tools/Research/libcue-CVE-2023-43641")
TARGETS = [
    ("vulnerable", "libcue.so.2.2.1", 0x00102359),
    ("patched", "libcue.so.2.3.0", 0x00102339),
]


@pytest.mark.parametrize("version,filename,load_address", TARGETS)
async def test_known_libcue_parser_stack_load_remains_unresolved_without_proof(
    version: str, filename: str, load_address: int,
    mcp_stdio_client, isolated_workspace: Path,
) -> None:
    binary = ROOT / f"build-{version}" / filename
    assert binary.is_file(), (
        f"Required build is missing: {binary}. "
        "Compile libcue v2.2.1/v2.3.0 before running native acceptance."
    )
    original = binary.read_bytes()
    assert original.startswith(b"\x7fELF"), binary
    before = hashlib.sha256(original).hexdigest()

    imported = await tool(
        mcp_stdio_client, "import-file", path=str(binary),
        destinationFolder="/", analyzeAfterImport=True,
        enableVersionControl=False,
    )
    assert imported.get("success") is True, imported
    programs = imported.get("importedPrograms", [])
    assert len(programs) == 1, imported
    program = programs[0]

    yyparse = await resolve_function_address(
        mcp_stdio_client, program, "yyparse",
    )
    assert yyparse, (version, program)
    result = await tool(
        mcp_stdio_client, "trace-memory-load-origins",
        programPath=program, loadAddress=hex(load_address),
        maxScannedOperations=10000, maxSliceOperations=128,
        maxReportedOperations=12,
    )

    assert result["function"] == "yyparse", (version, result)
    assert canonical_address(result["functionAddress"]) == (
        canonical_address(yyparse)
    ), (version, result)
    assert canonical_address(result["loadAddress"]) == load_address, result
    assert result["status"] in {
        "syntactic_store_candidates_only",
        "unresolved_no_syntactic_store",
        "incomplete_scan_budget",
    }, (version, result)
    assert "loadSequence" in result, (version, result)
    assert result["loadWidthBytes"] == 8, (version, result)
    assert result["provenReachingDefinitions"] == 0, result
    assert result["memoryOriginResolved"] is False, result
    assert "NOT a reaching definition" in result["semantics"], result
    assert result["matchingStoresObserved"] >= len(
        result["candidateStores"]
    ), result
    assert len(result["candidateStores"]) <= 8, result
    assert result["candidateStoresOmitted"] == (
        result["matchingStoresObserved"] - len(result["candidateStores"])
    ), result
    assert result["scanTruncated"] == (
        result["status"] == "incomplete_scan_budget"
    ), result

    for candidate in result["candidateStores"]:
        assert candidate["addressRelation"] == (
            "same_ssa_base_and_constant_offset"
        ), candidate
        assert candidate["reachingDefinition"] == "unproven", candidate
        assert candidate["memorySpaceId"] == result["loadSpaceId"], candidate
        assert candidate["storedValueEvidence"]["operationCount"] <= 128, candidate

    report = {
        "version": version,
        "loadAddress": result["loadAddress"],
        "status": result["status"],
        "scannedOperations": result["scannedOperations"],
        "scanTruncated": result["scanTruncated"],
        "candidateStoreCount": len(result["candidateStores"]),
        "candidateStoresOmitted": result["candidateStoresOmitted"],
        "candidateStoreAddresses": [
            item["storeAddress"] for item in result["candidateStores"]
        ],
        "memoryOriginResolved": result["memoryOriginResolved"],
    }
    print("REVA_LIBCUE_MEMORY_ORIGIN=" + json.dumps(report, sort_keys=True))

    assert hashlib.sha256(binary.read_bytes()).hexdigest() == before, (
        "Original libcue binary changed during analysis", binary
    )
