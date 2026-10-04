#!/usr/bin/env python3
"""Apply the ReVa generic static-analysis expansion (Slices 1-4) to a checked-out ReVa repository.

Targets the current upstream layout inspected on 2026-10-03. The script is
idempotent for the provider-registration edits and refuses to overwrite an
unexpected McpServerManager layout.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

EXPECTED_UPSTREAM_HEAD = "01a154a8edf233b02a0e7707e2ff5933893c6d53"


def run_git(repo: Path, *args: str) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()
    except Exception:
        return ""


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"Could not find expected {label} context; upstream layout changed")
    if text.count(old) != 1:
        raise RuntimeError(f"Expected exactly one {label} context, found {text.count(old)}")
    return text.replace(old, new, 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", nargs="?", default=".", help="Path to ReVa repository root")
    parser.add_argument("--allow-dirty", action="store_true", help="Apply even if the repo has existing changes")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    bundle = Path(__file__).resolve().parent
    manager = repo / "src/main/java/reva/server/McpServerManager.java"
    transport_test = repo / "tests/test_mcp_tools.py"

    if not manager.exists() or not (repo / "build.gradle").exists():
        print(f"error: {repo} does not look like the ReVa repository", file=sys.stderr)
        return 2

    status = run_git(repo, "status", "--porcelain")
    if status and not args.allow_dirty:
        print("error: repository has existing changes; commit/stash them or pass --allow-dirty", file=sys.stderr)
        print(status, file=sys.stderr)
        return 2

    head = run_git(repo, "rev-parse", "HEAD")
    if head and head != EXPECTED_UPSTREAM_HEAD:
        print(f"warning: bundle was reviewed against upstream {EXPECTED_UPSTREAM_HEAD[:12]}, current HEAD is {head[:12]}")
        print("         guarded edits will stop rather than guessing if upstream layout changed")

    # Copy new Java providers + integration tests.
    source_root = bundle / "src"
    for src in source_root.rglob("*"):
        if src.is_dir():
            continue
        rel = src.relative_to(source_root)
        dst = repo / "src" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        print(f"write {dst.relative_to(repo)}")

    text = manager.read_text()

    old_import = "import reva.tools.diff.DiffToolProvider;\n"
    new_import = old_import + (
        "import reva.tools.program.ProgramIntelligenceToolProvider;\n"
        "import reva.tools.controlflow.ControlFlowToolProvider;\n"
        "import reva.tools.pcode.PcodeToolProvider;\n"
        "import reva.tools.sourcemetadata.SourceMetadataToolProvider;\n"
        "import reva.tools.stackabi.StackAbiToolProvider;\n"
        "import reva.tools.provenance.SemanticProvenanceToolProvider;\n"
        "import reva.tools.stackstate.StackExecutionStateToolProvider;\n"
    )
    text = replace_once(text, old_import, new_import, "provider import")

    old_core = """                    new ConstantSearchToolProvider(server),\n                    new ImportExportToolProvider(server),\n                    new ProjectToolProvider(server, headlessMode));"""
    new_core = """                    new ConstantSearchToolProvider(server),\n                    new ImportExportToolProvider(server),\n                    new ProgramIntelligenceToolProvider(server),\n                    new ProjectToolProvider(server, headlessMode));"""
    text = replace_once(text, old_core, new_core, "CORE_ANALYSIS provider list")

    old_advanced = """                return List.of(\n                    new CallGraphToolProvider(server),\n                    new DataFlowToolProvider(server),\n                    new VtableToolProvider(server));"""
    new_advanced = """                return List.of(\n                    new CallGraphToolProvider(server),\n                    new DataFlowToolProvider(server),\n                    new VtableToolProvider(server),\n                    new ControlFlowToolProvider(server),\n                    new PcodeToolProvider(server),\n                    new SourceMetadataToolProvider(server),\n                    new StackAbiToolProvider(server),\n                    new SemanticProvenanceToolProvider(server),\n                    new StackExecutionStateToolProvider(server));"""
    text = replace_once(text, old_advanced, new_advanced, "ADVANCED_ANALYSIS provider list")

    manager.write_text(text)
    print(f"edit  {manager.relative_to(repo)}")

    if transport_test.exists():
        text = transport_test.read_text()
        old = '    "find-cross-references",\n'
        new = old + (
            '    "get-program-overview",\n'
            '    "get-function-cfg",\n'
            '    "get-pcode",\n'
            '    "list-source-files",\n'
            '    "get-source-mappings",\n'
            '    "get-function-stack-frame",\n'
            '    "get-function-abi",\n'
            '    "get-decompiler-provenance",\n'
            '    "get-callsite-semantics",\n'
            '    "get-function-stack-state",\n'
        )
        text = replace_once(text, old, new, "transport EXPECTED_TOOLS")
        transport_test.write_text(text)
        print(f"edit  {transport_test.relative_to(repo)}")

    print("\nApplied. No commit was created.")
    print("Review with: git diff --check && git diff --stat && git diff")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
