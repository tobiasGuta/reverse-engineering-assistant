"""Offline negative-control tests for guarded Slice 5B prerequisite application."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "apply_dataflow_reliability.py"
REQUIRED = (
    "ProgramIntelligenceToolProvider",
    "ControlFlowToolProvider",
    "PcodeToolProvider",
    "SourceMetadataToolProvider",
    "StackAbiToolProvider",
    "SemanticProvenanceToolProvider",
    "StackExecutionStateToolProvider",
    "CallBoundaryToolProvider",
)


class GuardedDataflowPatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.provider = self.root / (
            "src/main/java/reva/tools/dataflow/DataFlowToolProvider.java"
        )
        self.manager = self.root / "src/main/java/reva/server/McpServerManager.java"
        self.provider.parent.mkdir(parents=True)
        self.manager.parent.mkdir(parents=True)
        self.provider.write_text("non-pinned-provider\n")
        self.manager.write_text("\n".join(REQUIRED))
        (self.root / "build.gradle").write_text("// harmless test stub\n")

    def invoke(self):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.root)],
            check=False, capture_output=True, text=True, timeout=15,
        )

    def test_different_upstream_blob_is_refused_without_writes(self):
        before = self.provider.read_bytes()
        result = self.invoke()
        self.assertEqual(2, result.returncode)
        self.assertIn("differs from pinned revision", result.stderr)
        self.assertEqual(before, self.provider.read_bytes())
        self.assertFalse((
            self.root / "src/main/java/reva/tools/dataflow/BoundedDataFlowSlice.java"
        ).exists())
        self.assertFalse((
            self.root / "tests/test_dataflow_reliability_real_binary.py"
        ).exists())

    def test_missing_frozen_registration_refused_without_writes(self):
        self.manager.write_text(
            self.manager.read_text().replace("CallBoundaryToolProvider", "")
        )
        before = self.provider.read_bytes()
        result = self.invoke()
        self.assertEqual(2, result.returncode)
        self.assertIn("Frozen Slices 1-5A not installed", result.stderr)
        self.assertEqual(before, self.provider.read_bytes())

    def test_pinned_git_blob_is_explicit_contract(self):
        # Inspect actual source through a module import without applying it.
        import importlib.util
        spec = importlib.util.spec_from_file_location("apply_dataflow", SCRIPT)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(
            "4966146539a743029ace1a505b4a8c7fa9a7cccd",
            module.UPSTREAM_BLOB,
        )
        self.assertEqual(
            "9daeafb9864cf43055ae93beb0afd6c7d144bfa4",
            module.git_blob_sha(b"test\n"),
        )


if __name__ == "__main__":
    unittest.main()
