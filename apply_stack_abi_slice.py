#!/usr/bin/env python3
"""Apply Slice 2 (stack/ABI intelligence) to an existing Slice 1 ReVa checkout.

This helper is intentionally incremental. It expects the Slice 1 providers to
already be wired into McpServerManager and only adds StackAbiToolProvider,
its integration test, and the two MCP transport expectations. It never commits
or installs into Ghidra.
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
        raise RuntimeError(f"Could not find expected {label} context; checkout layout changed")
    if text.count(old) != 1:
        raise RuntimeError(f"Expected exactly one {label} context, found {text.count(old)}")
    return text.replace(old, new, 1)


def copy_new_file(src: Path, dst: Path) -> None:
    if dst.exists():
        if dst.read_bytes() == src.read_bytes():
            print(f"same  {dst}")
            return
        raise RuntimeError(
            f"Refusing to overwrite existing differing file: {dst}\n"
            "Review or remove that file explicitly before retrying."
        )
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    print(f"write {dst}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", nargs="?", default=".", help="Path to existing Slice 1 ReVa checkout")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    bundle = Path(__file__).resolve().parent
    manager = repo / "src/main/java/reva/server/McpServerManager.java"
    transport_test = repo / "tests/test_mcp_tools.py"

    if not manager.exists() or not (repo / "build.gradle").exists():
        print(f"error: {repo} does not look like the ReVa repository", file=sys.stderr)
        return 2
    if not transport_test.exists():
        print(f"error: missing transport test: {transport_test}", file=sys.stderr)
        return 2

    manager_text = manager.read_text()
    required_slice1_markers = (
        "ProgramIntelligenceToolProvider",
        "ControlFlowToolProvider",
        "PcodeToolProvider",
        "SourceMetadataToolProvider",
    )
    missing = [marker for marker in required_slice1_markers if marker not in manager_text]
    if missing:
        print(
            "error: checkout does not appear to have Slice 1 applied; missing: " +
            ", ".join(missing),
            file=sys.stderr,
        )
        return 2

    source_provider = bundle / "src/main/java/reva/tools/stackabi/StackAbiToolProvider.java"
    source_test = bundle / "src/test.slow/java/reva/tools/stackabi/StackAbiToolProviderIntegrationTest.java"
    if not source_provider.exists() or not source_test.exists():
        print("error: Slice 2 bundle files are missing", file=sys.stderr)
        return 2

    copy_new_file(
        source_provider,
        repo / "src/main/java/reva/tools/stackabi/StackAbiToolProvider.java",
    )
    copy_new_file(
        source_test,
        repo / "src/test.slow/java/reva/tools/stackabi/StackAbiToolProviderIntegrationTest.java",
    )

    manager_text = replace_once(
        manager_text,
        "import reva.tools.sourcemetadata.SourceMetadataToolProvider;\n",
        "import reva.tools.sourcemetadata.SourceMetadataToolProvider;\n"
        "import reva.tools.stackabi.StackAbiToolProvider;\n",
        "StackAbi provider import",
    )

    manager_text = replace_once(
        manager_text,
        """                    new ControlFlowToolProvider(server),
                    new PcodeToolProvider(server),
                    new SourceMetadataToolProvider(server));""",
        """                    new ControlFlowToolProvider(server),
                    new PcodeToolProvider(server),
                    new SourceMetadataToolProvider(server),
                    new StackAbiToolProvider(server));""",
        "ADVANCED_ANALYSIS StackAbi registration",
    )
    manager.write_text(manager_text)
    print(f"edit  {manager}")

    transport_text = transport_test.read_text()
    transport_text = replace_once(
        transport_text,
        '    "get-source-mappings",\n',
        '    "get-source-mappings",\n'
        '    "get-function-stack-frame",\n'
        '    "get-function-abi",\n',
        "transport StackAbi expectations",
    )
    transport_test.write_text(transport_text)
    print(f"edit  {transport_test}")

    print("\nSlice 2 applied. No commit or Ghidra installation was performed.")
    print("Review with: git diff --check && git diff --stat && git diff")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
