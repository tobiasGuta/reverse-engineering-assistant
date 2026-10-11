#!/usr/bin/env python3
"""Guarded Slice 5B prerequisite: fix pinned upstream dataflow trace collection.

Only DataFlowToolProvider.java is patched in-place; frozen Slices 1-5A
providers are untouched. The pinned upstream blob is verified before any
modification. This does not install ReVa or alter a Ghidra database.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

UPSTREAM_BLOB = "4966146539a743029ace1a505b4a8c7fa9a7cccd"
DATAFLOW = Path("src/main/java/reva/tools/dataflow/DataFlowToolProvider.java")
OWNED = (
    Path("src/main/java/reva/tools/dataflow/BoundedDataFlowSlice.java"),
    Path("src/test.slow/java/reva/tools/dataflow/BoundedDataFlowSliceIntegrationTest.java"),
    Path("tests/test_dataflow_reliability_real_binary.py"),
)


def git_blob_sha(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def replace_exact(text: str, original: str, replacement: str, label: str) -> str:
    count = text.count(original)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, got {count}")
    return text.replace(original, replacement, 1)


def patch_provider(text: str) -> str:
    text = replace_exact(
        text,
        "import ghidra.app.decompiler.component.DecompilerUtils;\n",
        "",
        "DecompilerUtils import",
    )
    text = replace_exact(
        text,
        """            // Perform the slice
            Set<PcodeOp> sliceOps;
            if (direction == SliceDirection.BACKWARD) {
                sliceOps = collectBackwardSlice(seedVarnodes);
            } else {
                sliceOps = collectForwardSlice(seedVarnodes);
            }
""",
        """            // Bounded SSA graph walk; unlike DecompilerUtils this never
            // materializes an unbounded full slice before applying the cap.
            BoundedDataFlowSlice.Result slice = BoundedDataFlowSlice.collect(
                seedVarnodes,
                direction == SliceDirection.BACKWARD
                    ? BoundedDataFlowSlice.Direction.BACKWARD
                    : BoundedDataFlowSlice.Direction.FORWARD,
                MAX_SLICE_SIZE);
            Set<PcodeOp> sliceOps = slice.operations();
""",
        "SSA slice collection",
    )
    text = replace_exact(
        text,
        """            result.put("operationCount", operations.size());
            result.put("operations", operations);
            result.put("terminators", terminators);
""",
        """            result.put("operationCount", operations.size());
            result.put("operations", operations);
            result.put("terminators", terminators);
            result.put("complete", !slice.truncated());
            result.put("truncated", slice.truncated());
            result.put("truncationReason", slice.truncationReason());
            result.put("operationLimit", MAX_SLICE_SIZE);
            result.put("visitedVarnodeCount", slice.visitedVarnodes());
            result.put("terminatorsComplete", !slice.truncated());
            result.put("sliceSemantics",
                "Bounded Ghidra High P-code SSA graph walk within one function. " +
                "Operation lists and terminators are partial when truncated; " +
                "absence of an operation or terminator must not be inferred " +
                "from a partial slice. CALL/CALLIND operations are boundaries. " +
                "No runtime execution, alias analysis, or cross-function propagation.");
""",
        "trace result completeness",
    )
    start = text.index("    private Set<PcodeOp> collectBackwardSlice(List<Varnode> seedVarnodes) {")
    end = text.index("    // ========================================================================\n"
                     "    // Varnode and Variable Finding", start)
    text = text[:start] + text[end:]
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "repo", nargs="?",
        default="/mnt/Development/Tools/ReVa-Static-Analysis",
        help="Existing pinned-upstream ReVa checkout with frozen Slices 1-5A",
    )
    parser.add_argument("--refresh", action="store_true",
                        help="Refresh ONLY Slice 5B-owned helper and integration test")
    args = parser.parse_args()
    repo = Path(args.repo).resolve()
    bundle = Path(__file__).resolve().parent
    provider = repo / DATAFLOW
    manager = repo / "src/main/java/reva/server/McpServerManager.java"
    if not provider.is_file() or not (repo / "build.gradle").is_file():
        raise RuntimeError(f"Not a ReVa source checkout: {repo}")
    manager_text = manager.read_text()
    for frozen in (
        "ProgramIntelligenceToolProvider", "ControlFlowToolProvider",
        "PcodeToolProvider", "SourceMetadataToolProvider",
        "StackAbiToolProvider", "SemanticProvenanceToolProvider",
        "StackExecutionStateToolProvider", "CallBoundaryToolProvider",
    ):
        if frozen not in manager_text:
            raise RuntimeError("Frozen Slices 1-5A not installed: " + frozen)

    raw = provider.read_bytes()
    already_patched = (
        "BoundedDataFlowSlice.collect(" in raw.decode("utf-8")
        and "result.put(\"truncationReason\", slice.truncationReason());" in raw.decode("utf-8")
        and "collectBackwardSlice(" not in raw.decode("utf-8")
    )
    updated = None
    if not already_patched:
        sha = git_blob_sha(raw)
        if sha != UPSTREAM_BLOB:
            raise RuntimeError(
                "Upstream dataflow source differs from pinned revision "
                f"({sha} != {UPSTREAM_BLOB}); refusing to overwrite or guess"
            )
        updated = patch_provider(raw.decode("utf-8"))

    # Validate all files before the first target write.
    for path in OWNED:
        source = bundle / path
        target = repo / path
        if not source.is_file():
            raise RuntimeError(f"Missing development bundle file: {source}")
        if target.exists() and target.read_bytes() != source.read_bytes() and not args.refresh:
            raise RuntimeError(
                f"Refusing to replace differing Slice 5B file: {target}. "
                "Use --refresh only for Slice 5B-owned files."
            )

    for path in OWNED:
        source = bundle / path
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or target.read_bytes() != source.read_bytes():
            shutil.copy2(source, target)
            print(f"write {target}")
        else:
            print(f"keep  {target}")
    if updated is not None:
        provider.write_text(updated)
        print(f"patch {provider}")
    else:
        print(f"keep  {provider} (already patched)")

    print("Applied Slice 5B prerequisite. No commit or extension installation.")
    print("Review: git diff --check && git diff --stat && git status --short")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
