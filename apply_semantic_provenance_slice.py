#!/usr/bin/env python3
"""Apply Slice 3 semantic provenance to an existing Slices 1-2 ReVa checkout.

This helper is intentionally incremental. It copies only the Slice 3 provider
and integration test, then performs guarded registration edits. It does not
commit, install into Ghidra, or modify existing Slice 1-2 provider files.
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
                "Use --refresh to replace only Slice 3-owned files from this bundle."
            )
        shutil.copy2(source, destination)
        print(f"refresh {destination}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    print(f"write {destination}")


def patch_incoming_reference_lines(source_path: Path) -> None:
    """Fix an upstream raw-Clang ordinal exposed as fromLine.

    Only the two known return sites in the pinned context utility are
    affected. Refuse unknown content rather than editing it speculatively.
    """
    original = source_path.read_text()
    marker = "DecompilationDisplayLines.map(renderedC, clangLines)"
    if marker in original:
        print(f"keep  {source_path} (physical-line correction)")
        return

    old_head = """            ClangTokenGroup markup = decompileResults.getCCodeMarkup();
            List<ClangLine> clangLines = DecompilerUtils.toLines(markup);

            // Find the line containing this address"""
    new_head = """            ClangTokenGroup markup = decompileResults.getCCodeMarkup();
            List<ClangLine> clangLines = DecompilerUtils.toLines(markup);
            String renderedC = decompileResults.getDecompiledFunction() != null
                ? decompileResults.getDecompiledFunction().getC() : null;
            Map<ClangLine, Integer> displayLines =
                DecompilationDisplayLines.map(renderedC, clangLines);

            // Find the line containing this address"""

    old_exact = """                    if (tokenAddr != null && tokenAddr.equals(address)) {
                        return clangLine.getLineNumber();
                    }"""
    new_exact = """                    if (tokenAddr != null && tokenAddr.equals(address)) {
                        Integer physical = DecompilationDisplayLines.tokenLine(
                            clangLine, clangLine.indexOfToken(token), displayLines);
                        return physical != null ? physical : -1;
                    }"""

    old_closest = """                    if (closestAddr != null && closestAddr.equals(address)) {
                        return clangLine.getLineNumber();
                    }"""
    new_closest = """                    if (closestAddr != null && closestAddr.equals(address)) {
                        Integer physical = DecompilationDisplayLines.tokenLine(
                            clangLine, 0, displayLines);
                        return physical != null ? physical : -1;
                    }"""

    updated = original
    for old, new in [
        (old_head, new_head),
        (old_exact, new_exact),
        (old_closest, new_closest),
    ]:
        if updated.count(old) != 1:
            raise RuntimeError(
                "Unrecognized upstream DecompilationContextUtil shape; "
                "refusing physical-line patch"
            )
        updated = updated.replace(old, new, 1)
    source_path.write_text(updated)
    print(f"edit  {source_path} (verified physical-line correction)")


def ensure_semantic_registration(manager_text: str) -> str:
    """Accept a fully registered Slice 3 in later-layered ReVa checkouts."""
    imported = "import reva.tools.provenance.SemanticProvenanceToolProvider;\n"
    constructed = "new SemanticProvenanceToolProvider(server)"
    import_count = manager_text.count(imported)
    constructor_count = manager_text.count(constructed)

    if import_count == 1 and constructor_count == 1:
        # Slices 4/5A/5B extend this exact provider list; the original
        # Slice 3 closing ");" no longer exists after layering.
        return manager_text
    if import_count != 0 or constructor_count != 0:
        raise RuntimeError(
            "Partial or duplicate SemanticProvenance registration; refusing to guess"
        )

    manager_next = replace_once(
        manager_text,
        "import reva.tools.stackabi.StackAbiToolProvider;\n",
        "import reva.tools.stackabi.StackAbiToolProvider;\n" + imported,
        "SemanticProvenance provider import",
    )
    return replace_once(
        manager_next,
        """                    new SourceMetadataToolProvider(server),
                    new StackAbiToolProvider(server));""",
        """                    new SourceMetadataToolProvider(server),
                    new StackAbiToolProvider(server),
                    new SemanticProvenanceToolProvider(server));""",
        "ADVANCED_ANALYSIS SemanticProvenance registration",
    )


def ensure_semantic_transport(transport_text: str) -> str:
    """Do not reinsert tools into an already expanded MCP catalog."""
    names = (
        '    "get-decompiler-provenance",\n',
        '    "get-callsite-semantics",\n',
    )
    counts = [transport_text.count(name) for name in names]
    if counts == [1, 1]:
        return transport_text
    if counts != [0, 0]:
        raise RuntimeError(
            "Partial or duplicate SemanticProvenance MCP catalog entries"
        )
    return replace_once(
        transport_text,
        '    "get-function-abi",\n',
        '    "get-function-abi",\n' + "".join(names),
        "transport SemanticProvenance expectations",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "repo",
        nargs="?",
        default="/mnt/Development/Tools/ReVa-Static-Analysis",
        help="Existing ReVa checkout with Slices 1-2 already applied",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Replace only differing Slice 3-owned provider/test files from this bundle",
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
    )
    missing = [marker for marker in required_markers if marker not in manager_text]
    if missing:
        print(
            "error: checkout does not appear to have frozen Slices 1-2 applied; "
            "missing: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 2

    source_provider = (
        bundle
        / "src/main/java/reva/tools/provenance/SemanticProvenanceToolProvider.java"
    )
    source_test = (
        bundle
        / "src/test.slow/java/reva/tools/provenance/"
        "SemanticProvenanceToolProviderIntegrationTest.java"
    )
    source_helper = (
        bundle / "src/main/java/reva/util/DecompilationDisplayLines.java"
    )
    if not source_provider.exists() or not source_test.exists() or not source_helper.exists():
        print("error: Slice 3 bundle files are missing", file=sys.stderr)
        return 2

    copy_slice_file(
        source_provider,
        repo
        / "src/main/java/reva/tools/provenance/"
        "SemanticProvenanceToolProvider.java",
        args.refresh,
    )
    copy_slice_file(
        source_test,
        repo
        / "src/test.slow/java/reva/tools/provenance/"
        "SemanticProvenanceToolProviderIntegrationTest.java",
        args.refresh,
    )

    copy_slice_file(
        source_helper,
        repo / "src/main/java/reva/util/DecompilationDisplayLines.java",
        args.refresh,
    )
    patch_incoming_reference_lines(
        repo / "src/main/java/reva/util/DecompilationContextUtil.java"
    )

    # Preflight registration before any possible metadata write.
    manager_next = ensure_semantic_registration(manager_text)
    transport_next = (
        ensure_semantic_transport(transport_test.read_text())
        if transport_test.exists() else None
    )

    if manager_next != manager_text:
        manager.write_text(manager_next)
        print(f"edit  {manager}")
    else:
        print(f"keep  {manager} (registration already present)")

    if transport_next is not None:
        original_transport = transport_test.read_text()
        if transport_next != original_transport:
            transport_test.write_text(transport_next)
            print(f"edit  {transport_test}")
        else:
            print(f"keep  {transport_test} (MCP tools already listed)")

    print("\nApplied Slice 3 semantic provenance. No commit was created.")
    print("Review with: git diff --check && git diff --stat && git diff")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
