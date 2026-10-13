#!/usr/bin/env python3
"""Guarded additive overlay for memory-origin candidate tracing.

Requires the already tested two-hop layered ReVa checkout. Makes no edits to
frozen one-hop/two-hop providers or the Ghidra SDK. No binary is executed.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys

PROVIDER = Path(
    "src/main/java/reva/tools/dataflow/MemoryOriginCandidateToolProvider.java")
TEST = Path(
    "src/test.slow/java/reva/tools/dataflow/MemoryOriginCandidateToolProviderIntegrationTest.java")
OWNED = (PROVIDER, TEST)
MANAGER = Path("src/main/java/reva/server/McpServerManager.java")
CATALOG = Path("tests/test_mcp_tools.py")
TWO_HOP = Path(
    "src/main/java/reva/tools/dataflow/TwoHopValueFlowToolProvider.java")
BOUNDED = Path(
    "src/main/java/reva/tools/dataflow/BoundedDataFlowSlice.java")

BASE_IMPORT = "import reva.tools.dataflow.TwoHopValueFlowToolProvider;\n"
NEW_IMPORT = "import reva.tools.dataflow.MemoryOriginCandidateToolProvider;\n"
BASE_CTOR = "                    new TwoHopValueFlowToolProvider(server));"
NEW_CTOR = (
    "                    new TwoHopValueFlowToolProvider(server),\n"
    "                    new MemoryOriginCandidateToolProvider(server));"
)
BASE_TOOL = '    "trace-call-argument-two-hop",\n'
NEW_TOOL = '    "trace-memory-load-origins",\n'


def apply(repo: Path, bundle: Path, refresh: bool) -> None:
    manager, catalog = repo / MANAGER, repo / CATALOG
    prerequisites = (manager, catalog, repo / TWO_HOP, repo / BOUNDED,
                     repo / "build.gradle")
    if not all(path.is_file() for path in prerequisites):
        raise RuntimeError("Requires layered ReVa checkout with two-hop tool")
    if "trace-call-argument-two-hop" not in (repo / TWO_HOP).read_text():
        raise RuntimeError("Two-hop provider prerequisite not established")

    manager_before, catalog_before = manager.read_text(), catalog.read_text()
    markers = (
        manager_before.count(NEW_IMPORT),
        manager_before.count("new MemoryOriginCandidateToolProvider(server)"),
        catalog_before.count('"trace-memory-load-origins"'),
    )
    if markers == (0, 0, 0):
        if (manager_before.count(BASE_IMPORT) != 1 or
            manager_before.count(BASE_CTOR) != 1 or
            catalog_before.count(BASE_TOOL) != 1):
            raise RuntimeError("Unrecognized two-hop registration; no files changed")
        manager_after = manager_before.replace(
            BASE_IMPORT, BASE_IMPORT + NEW_IMPORT, 1).replace(
            BASE_CTOR, NEW_CTOR, 1)
        catalog_after = catalog_before.replace(
            BASE_TOOL, BASE_TOOL + NEW_TOOL, 1)
    elif markers == (1, 1, 1):
        if (manager_before.count(BASE_IMPORT + NEW_IMPORT) != 1 or
            manager_before.count(NEW_CTOR) != 1 or
            catalog_before.count(BASE_TOOL + NEW_TOOL) != 1):
            raise RuntimeError("Noncanonical memory-origin registration")
        manager_after, catalog_after = manager_before, catalog_before
    else:
        raise RuntimeError("Partial memory-origin registration; no files changed")

    # Reject all collisions and missing bundle inputs before *any* write.
    for rel in OWNED:
        source, target = bundle / rel, repo / rel
        if not source.is_file():
            raise RuntimeError(f"Missing overlay input: {source}")
        if target.exists() and target.read_bytes() != source.read_bytes() and not refresh:
            raise RuntimeError(f"Refusing to overwrite locally edited file: {target}")

    for rel in OWNED:
        source, target = bundle / rel, repo / rel
        if not target.exists() or target.read_bytes() != source.read_bytes():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            print(f"write {target}")
        else:
            print(f"keep  {target}")
    if manager_after != manager_before:
        manager.write_text(manager_after)
        print(f"edit  {manager}")
    if catalog_after != catalog_before:
        catalog.write_text(catalog_after)
        print(f"edit  {catalog}")
    print("Applied memory-origin candidate tool; no Ghidra installation changed.")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("repo", nargs="?",
        default="/mnt/Development/Tools/ReVa-Static-Analysis")
    p.add_argument("--refresh", action="store_true",
        help="Refresh only memory-origin-owned provider and integration test")
    args = p.parse_args()
    apply(Path(args.repo).resolve(), Path(__file__).resolve().parent,
          args.refresh)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
