#!/usr/bin/env python3
"""Apply ReVa Slice 5A to an existing checkout with frozen Slices 1-4.

No commits, installs, execution, or modification of existing provider classes.
Preflight runs before all writes; --refresh only permits replacing files owned
by Slice 5A. It is not a replacement for verifying the final git diff.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

PROVIDER = Path(
    "src/main/java/reva/tools/callboundary/CallBoundaryToolProvider.java"
)
TEST = Path(
    "src/test.slow/java/reva/tools/callboundary/"
    "CallBoundaryToolProviderIntegrationTest.java"
)


def replacement(contents: str, old: str, new: str, label: str) -> str:
    if contents.count(new) == 1:
        return contents
    if new in contents or contents.count(old) != 1:
        raise RuntimeError(
            f"Unexpected {label} registration state; refusing to guess"
        )
    return contents.replace(old, new, 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "repo",
        nargs="?",
        default="/mnt/Development/Tools/ReVa-Static-Analysis",
        help="Existing upstream ReVa checkout with Slices 1-4 applied",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Overwrite only Slice 5A-owned provider/test files",
    )
    args = parser.parse_args()
    repo = Path(args.repo).resolve()
    bundle = Path(__file__).resolve().parent
    manager = repo / "src/main/java/reva/server/McpServerManager.java"
    transport = repo / "tests/test_mcp_tools.py"

    if not manager.is_file() or not (repo / "build.gradle").is_file():
        print(f"error: Not a ReVa checkout: {repo}", file=sys.stderr)
        return 2
    current = manager.read_text()
    for required in (
        "ProgramIntelligenceToolProvider",
        "ControlFlowToolProvider",
        "PcodeToolProvider",
        "SourceMetadataToolProvider",
        "StackAbiToolProvider",
        "SemanticProvenanceToolProvider",
        "StackExecutionStateToolProvider",
    ):
        if required not in current:
            print(
                f"error: Missing frozen 1-4 registration: {required}",
                file=sys.stderr,
            )
            return 2

    # Preflight every change before touching the target checkout.
    contents = replacement(
        current,
        "import reva.tools.stackstate.StackExecutionStateToolProvider;\n",
        "import reva.tools.stackstate.StackExecutionStateToolProvider;\n"
        "import reva.tools.callboundary.CallBoundaryToolProvider;\n",
        "Slice 5A provider import",
    )
    contents = replacement(
        contents,
        "                    new StackExecutionStateToolProvider(server));",
        "                    new StackExecutionStateToolProvider(server),\n"
        "                    new CallBoundaryToolProvider(server));",
        "Slice 5A ADVANCED_ANALYSIS provider",
    )
    transport_contents = None
    if transport.is_file():
        transport_contents = replacement(
            transport.read_text(),
            '    "get-function-stack-state",\n',
            '    "get-function-stack-state",\n'
            '    "inspect-call-boundary",\n',
            "Slice 5A MCP catalog expectation",
        )

    for path in (PROVIDER, TEST):
        source = bundle / path
        target = repo / path
        if not source.is_file():
            raise RuntimeError(f"Missing Slice 5A bundle file: {source}")
        if target.exists() and target.read_bytes() != source.read_bytes():
            if not args.refresh:
                raise RuntimeError(
                    f"Refusing to overwrite existing file: {target}. "
                    "Use --refresh only for Slice 5A-owned files."
                )

    for path in (PROVIDER, TEST):
        source = bundle / path
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or target.read_bytes() != source.read_bytes():
            shutil.copy2(source, target)
            print(f"write {target}")
        else:
            print(f"keep  {target}")

    if current != contents:
        manager.write_text(contents)
        print(f"edit  {manager}")
    if transport_contents is not None and transport.read_text() != transport_contents:
        transport.write_text(transport_contents)
        print(f"edit  {transport}")

    print("Slice 5A applied. No commit, Ghidra installation, or target execution.")
    print("Inspect: git diff --check && git diff --stat && git diff")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
