#!/usr/bin/env python3
"""Guarded, additive Slice 5B installer for existing ReVa dev checkout.

Requires frozen 1-5A registrations and the bounded-dataflow prerequisite.
Only the new one-hop provider/tests and two registration surfaces are edited.
Preflight checks all conditions before writing anything. No clone or install.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

OWNED = (
    Path("src/main/java/reva/tools/dataflow/OneHopValueFlowToolProvider.java"),
    Path("src/test.slow/java/reva/tools/dataflow/OneHopValueFlowToolProviderIntegrationTest.java"),
    Path("tests/test_one_hop_value_flow_real_binary.py"),
)


def replace_once(s: str, before: str, after: str, label: str) -> str:
    if after in s and s.count(after) == 1:
        return s
    if s.count(before) != 1 or after in s:
        raise RuntimeError(f"{label}: unexpected registration; refusing to guess")
    return s.replace(before, after, 1)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("repo", nargs="?",
        default="/mnt/Development/Tools/ReVa-Static-Analysis")
    p.add_argument("--refresh", action="store_true",
        help="Allow refresh of ONLY new Slice 5B-owned provider/tests")
    args = p.parse_args()
    repo = Path(args.repo).resolve()
    bundle = Path(__file__).resolve().parent
    manager = repo / "src/main/java/reva/server/McpServerManager.java"
    transport = repo / "tests/test_mcp_tools.py"
    dataflow = repo / "src/main/java/reva/tools/dataflow/DataFlowToolProvider.java"
    helper = repo / "src/main/java/reva/tools/dataflow/BoundedDataFlowSlice.java"
    if not manager.is_file() or not transport.is_file() or not dataflow.is_file() or not helper.is_file():
        raise RuntimeError("Expected ReVa checkout with frozen dataflow prerequisite")
    if not (repo / "build.gradle").is_file():
        raise RuntimeError("Missing ReVa Gradle build definition")

    manager_text = manager.read_text()
    for marker in (
        "ProgramIntelligenceToolProvider", "ControlFlowToolProvider",
        "PcodeToolProvider", "SourceMetadataToolProvider", "StackAbiToolProvider",
        "SemanticProvenanceToolProvider", "StackExecutionStateToolProvider",
        "CallBoundaryToolProvider",
    ):
        if marker not in manager_text:
            raise RuntimeError(f"Missing frozen registration: {marker}")
    if "BoundedDataFlowSlice.collect(" not in dataflow.read_text():
        raise RuntimeError("Bounded dataflow prerequisite not installed")

    manager_next = replace_once(
        manager_text,
        "import reva.tools.callboundary.CallBoundaryToolProvider;\n",
        "import reva.tools.callboundary.CallBoundaryToolProvider;\n"
        "import reva.tools.dataflow.OneHopValueFlowToolProvider;\n",
        "one-hop provider import",
    )
    manager_next = replace_once(
        manager_next,
        "                    new CallBoundaryToolProvider(server));",
        "                    new CallBoundaryToolProvider(server),\n"
        "                    new OneHopValueFlowToolProvider(server));",
        "one-hop ADVANCED_ANALYSIS registration",
    )
    transport_text = transport.read_text()
    transport_next = replace_once(
        transport_text,
        '    "inspect-call-boundary",\n',
        '    "inspect-call-boundary",\n'
        '    "trace-call-argument-one-hop",\n',
        "one-hop MCP catalog expectation",
    )
    for path in OWNED:
        source, target = bundle / path, repo / path
        if not source.is_file():
            raise RuntimeError(f"Missing Slice 5B source: {source}")
        if target.exists() and target.read_bytes() != source.read_bytes() and not args.refresh:
            raise RuntimeError(
                f"Refusing to overwrite existing Slice 5B file: {target}; use --refresh"
            )
    for path in OWNED:
        source, target = bundle / path, repo / path
        if not target.exists() or target.read_bytes() != source.read_bytes():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            print(f"write {target}")
        else:
            print(f"keep  {target}")
    if manager_next != manager_text:
        manager.write_text(manager_next)
        print(f"edit  {manager}")
    if transport_next != transport_text:
        transport.write_text(transport_next)
        print(f"edit  {transport}")
    print("Slice 5B applied. No commit, Ghidra installation or target execution.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError) as e:
        print("error:", e, file=sys.stderr)
        raise SystemExit(2)
