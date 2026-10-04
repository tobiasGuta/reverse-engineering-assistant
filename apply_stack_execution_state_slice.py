#!/usr/bin/env python3
"""Apply Slice 4 stack execution state to an existing Slices 1-3 ReVa checkout.

This helper is intentionally incremental. It copies only the Slice 4 provider
and integration test, then performs guarded registration edits. It does not
commit, install into Ghidra, or modify frozen Slices 1-3 provider files.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"Could not find expected {label} context")
    if text.count(old) != 1:
        raise RuntimeError(
            f"Expected exactly one {label} context, found {text.count(old)}"
        )
    return text.replace(old, new, 1)


def copy_slice_file(
    source: Path, destination: Path, refresh: bool
) -> None:
    if destination.exists():
        if destination.read_bytes() == source.read_bytes():
            print(f"keep  {destination}")
            return
        if not refresh:
            raise RuntimeError(
                f"Refusing to overwrite differing existing file: {destination}. "
                "Use --refresh to replace only Slice 4-owned files from this bundle."
            )
        shutil.copy2(source, destination)
        print(f"refresh {destination}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    print(f"write {destination}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "repo",
        nargs="?",
        default="/mnt/Development/Tools/ReVa-Static-Analysis",
        help="Existing ReVa checkout with Slices 1-3 already applied",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Replace only differing Slice 4-owned provider/test files from this bundle",
    )
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    bundle = Path(__file__).resolve().parent
    manager = repo / "src/main/java/reva/server/McpServerManager.java"
    transport_test = repo / "tests/test_mcp_tools.py"

    if not manager.exists() or not (repo / "build.gradle").exists():
        print(
            f"error: {repo} does not look like the ReVa repository",
            file=sys.stderr,
        )
        return 2

    manager_text = manager.read_text()
    required_markers = (
        "ProgramIntelligenceToolProvider",
        "ControlFlowToolProvider",
        "PcodeToolProvider",
        "SourceMetadataToolProvider",
        "StackAbiToolProvider",
        "SemanticProvenanceToolProvider",
    )
    missing = [marker for marker in required_markers if marker not in manager_text]
    if missing:
        print(
            "error: checkout does not appear to have frozen Slices 1-3 applied; "
            "missing: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 2

    source_provider = (
        bundle
        / "src/main/java/reva/tools/stackstate/"
        "StackExecutionStateToolProvider.java"
    )
    source_test = (
        bundle
        / "src/test.slow/java/reva/tools/stackstate/"
        "StackExecutionStateToolProviderIntegrationTest.java"
    )
    if not source_provider.exists() or not source_test.exists():
        print("error: Slice 4 bundle files are missing", file=sys.stderr)
        return 2

    copy_slice_file(
        source_provider,
        repo
        / "src/main/java/reva/tools/stackstate/"
        "StackExecutionStateToolProvider.java",
        args.refresh,
    )
    copy_slice_file(
        source_test,
        repo
        / "src/test.slow/java/reva/tools/stackstate/"
        "StackExecutionStateToolProviderIntegrationTest.java",
        args.refresh,
    )

    manager_text = replace_once(
        manager_text,
        "import reva.tools.provenance.SemanticProvenanceToolProvider;\n",
        "import reva.tools.provenance.SemanticProvenanceToolProvider;\n"
        "import reva.tools.stackstate.StackExecutionStateToolProvider;\n",
        "StackExecutionState provider import",
    )

    manager_text = replace_once(
        manager_text,
        """                    new StackAbiToolProvider(server),
                    new SemanticProvenanceToolProvider(server));""",
        """                    new StackAbiToolProvider(server),
                    new SemanticProvenanceToolProvider(server),
                    new StackExecutionStateToolProvider(server));""",
        "ADVANCED_ANALYSIS StackExecutionState registration",
    )

    manager.write_text(manager_text)
    print(f"edit  {manager}")

    if transport_test.exists():
        transport_text = transport_test.read_text()
        transport_text = replace_once(
            transport_text,
            '    "get-callsite-semantics",\n',
            '    "get-callsite-semantics",\n'
            '    "get-function-stack-state",\n',
            "transport StackExecutionState expectation",
        )
        transport_test.write_text(transport_text)
        print(f"edit  {transport_test}")

    print("\nApplied Slice 4 stack execution state. No commit was created.")
    print("Review with: git diff --check && git diff --stat && git diff")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
