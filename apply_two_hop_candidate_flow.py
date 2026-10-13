#!/usr/bin/env python3
"""Apply the additive two-hop candidate provider to an existing ReVa dev checkout.

No installation, Ghidra project edits, binary execution, or source
modification outside the two-hop-owned files and guarded registration.
This script requires the existing frozen one-hop provider; it will not
recreate or overwrite that implementation.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys

OWNED = (
    Path("src/main/java/reva/tools/dataflow/TwoHopValueFlowToolProvider.java"),
    Path("src/test.slow/java/reva/tools/dataflow/TwoHopValueFlowToolProviderIntegrationTest.java"),
    Path("tests/test_two_hop_value_flow_real_binary.py"),
)

MANAGER = Path("src/main/java/reva/server/McpServerManager.java")
TRANSPORT = Path("tests/test_mcp_tools.py")
ONE_HOP = Path("src/main/java/reva/tools/dataflow/OneHopValueFlowToolProvider.java")
BOUNDED = Path("src/main/java/reva/tools/dataflow/BoundedDataFlowSlice.java")


def guarded_registration(original: str, old: str, new: str, label: str) -> str:
    # Imports/catalog entries contain the old marker, while the
    # expanded constructor replaces it. Handle both shapes idempotently.
    if original.count(new) == 1:
        if original.count(old) <= 1:
            return original
        raise RuntimeError(f"{label}: duplicate previous registration")
    if original.count(old) != 1 or original.count(new) != 0:
        raise RuntimeError(f"{label}: unrecognized/partial registration")
    return original.replace(old, new, 1)


def apply(repo: Path, bundle: Path, refresh: bool) -> None:
    manager = repo / MANAGER
    transport = repo / TRANSPORT
    one_hop = repo / ONE_HOP
    bounded = repo / BOUNDED
    if not all(p.is_file() for p in (manager, transport, one_hop, bounded)):
        raise RuntimeError("Expected a layered ReVa development checkout")
    if not (repo / "build.gradle").is_file():
        raise RuntimeError("Missing ReVa Gradle project")
    if "selectReportedOperations(" not in one_hop.read_text():
        raise RuntimeError("Requires the tested compact one-hop implementation")
    if "BoundedDataFlowSlice.collect(" not in one_hop.read_text():
        raise RuntimeError("Missing bounded one-hop dependency")

    manager_original = manager.read_text()
    transport_original = transport.read_text()
    # Reject partial ownership markers before attempting any expansion.
    owner_import = "import reva.tools.dataflow.TwoHopValueFlowToolProvider;\n"
    owner_ctor = "new TwoHopValueFlowToolProvider(server)"
    owner_tool = '"trace-call-argument-two-hop"'
    complete_import = (
        "import reva.tools.dataflow.OneHopValueFlowToolProvider;\n"
        "import reva.tools.dataflow.TwoHopValueFlowToolProvider;\n"
    )
    complete_ctor = (
        "                    new OneHopValueFlowToolProvider(server),\n"
        "                    new TwoHopValueFlowToolProvider(server));"
    )
    complete_tool = (
        '    "trace-call-argument-one-hop",\n'
        '    "trace-call-argument-two-hop",\n'
    )
    if ((owner_import in manager_original and
            manager_original.count(complete_import) != 1) or
        (owner_ctor in manager_original and
            manager_original.count(complete_ctor) != 1) or
        (owner_tool in transport_original and
            transport_original.count(complete_tool) != 1)):
        raise RuntimeError("Partial two-hop registration; refusing to guess")
    manager_next = guarded_registration(
        manager_original,
        "import reva.tools.dataflow.OneHopValueFlowToolProvider;\n",
        "import reva.tools.dataflow.OneHopValueFlowToolProvider;\n"
        "import reva.tools.dataflow.TwoHopValueFlowToolProvider;\n",
        "two-hop provider import",
    )
    manager_next = guarded_registration(
        manager_next,
        "                    new OneHopValueFlowToolProvider(server));",
        "                    new OneHopValueFlowToolProvider(server),\n"
        "                    new TwoHopValueFlowToolProvider(server));",
        "two-hop tool registration",
    )
    transport_next = guarded_registration(
        transport_original,
        '    "trace-call-argument-one-hop",\n',
        '    "trace-call-argument-one-hop",\n'
        '    "trace-call-argument-two-hop",\n',
        "two-hop MCP catalog",
    )

    # Validate *all* source collisions before any file is written.
    for rel in OWNED:
        src, dst = bundle / rel, repo / rel
        if not src.is_file():
            raise RuntimeError(f"Missing two-hop bundle source: {src}")
        if dst.exists() and dst.read_bytes() != src.read_bytes() and not refresh:
            raise RuntimeError(
                f"Refusing to overwrite locally edited two-hop file: {dst}"
            )
    for rel in OWNED:
        src, dst = bundle / rel, repo / rel
        if not dst.exists() or dst.read_bytes() != src.read_bytes():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            print(f"write {dst}")
        else:
            print(f"keep  {dst}")
    if manager_next != manager_original:
        manager.write_text(manager_next)
        print(f"edit  {manager}")
    if transport_next != transport_original:
        transport.write_text(transport_next)
        print(f"edit  {transport}")
    print("Applied bounded two-hop candidate tool. No Ghidra installation changed.")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("repo", nargs="?",
        default="/mnt/Development/Tools/ReVa-Static-Analysis")
    p.add_argument("--refresh", action="store_true",
        help="Refresh only two-hop-owned provider and tests")
    args = p.parse_args()
    apply(Path(args.repo).resolve(),
          Path(__file__).resolve().parent, args.refresh)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
