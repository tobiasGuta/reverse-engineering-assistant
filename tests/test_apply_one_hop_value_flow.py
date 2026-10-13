"""Offline preflight and idempotency checks for additive Slice 5B installer."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BUNDLE = Path(__file__).resolve().parents[1]
SCRIPT = BUNDLE / "apply_one_hop_value_flow.py"
PROVIDER = Path("src/main/java/reva/tools/dataflow/OneHopValueFlowToolProvider.java")
TEST = Path("src/test.slow/java/reva/tools/dataflow/OneHopValueFlowToolProviderIntegrationTest.java")
ELF = Path("tests/test_one_hop_value_flow_real_binary.py")


class OneHopApplyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manager = self.root / "src/main/java/reva/server/McpServerManager.java"
        self.transport = self.root / "tests/test_mcp_tools.py"
        dataflow = self.root / "src/main/java/reva/tools/dataflow/DataFlowToolProvider.java"
        helper = self.root / "src/main/java/reva/tools/dataflow/BoundedDataFlowSlice.java"
        for f in (self.manager, self.transport, dataflow, helper):
            f.parent.mkdir(parents=True, exist_ok=True)
        self.manager.write_text(
            "\n".join((
                "ProgramIntelligenceToolProvider",
                "ControlFlowToolProvider",
                "PcodeToolProvider",
                "SourceMetadataToolProvider",
                "StackAbiToolProvider",
                "SemanticProvenanceToolProvider",
                "StackExecutionStateToolProvider",
                "import reva.tools.callboundary.CallBoundaryToolProvider;",
                "new CallBoundaryToolProvider(server));",
            )) + "\n"
        )
        self.transport.write_text('    "inspect-call-boundary",\n')
        dataflow.write_text("BoundedDataFlowSlice.collect(\n")
        helper.write_text("class BoundedDataFlowSlice {}\n")
        (self.root / "build.gradle").write_text("// build\n")

    def run_app(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.root), *args],
            capture_output=True, text=True, check=False, timeout=20,
        )

    def test_apply_idempotent_and_additive(self):
        first = self.run_app()
        self.assertEqual(0, first.returncode, first.stderr)
        old_files = (
            self.manager.read_bytes(), self.transport.read_bytes(),
            (self.root / PROVIDER).read_bytes(),
            (self.root / TEST).read_bytes(),
            (self.root / ELF).read_bytes(),
        )
        second = self.run_app()
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertEqual(old_files, (
            self.manager.read_bytes(), self.transport.read_bytes(),
            (self.root / PROVIDER).read_bytes(),
            (self.root / TEST).read_bytes(),
            (self.root / ELF).read_bytes(),
        ))
        self.assertEqual(
            1, self.manager.read_text().count(
                "import reva.tools.dataflow.OneHopValueFlowToolProvider;"
            )
        )
        self.assertEqual(
            1, self.transport.read_text().count('"trace-call-argument-one-hop"')
        )

    def test_missing_frozen_registration_fails_without_writes(self):
        self.manager.write_text(self.manager.read_text().replace(
            "StackExecutionStateToolProvider", "MISSING"
        ))
        old = self.manager.read_bytes()
        result = self.run_app()
        self.assertEqual(2, result.returncode)
        self.assertIn("Missing frozen registration", result.stderr)
        self.assertEqual(old, self.manager.read_bytes())
        self.assertFalse((self.root / PROVIDER).exists())

    def test_conflicting_registration_refused_atomically(self):
        self.manager.write_text(self.manager.read_text().replace(
            "new CallBoundaryToolProvider(server));",
            "new SomethingElse(server));",
        ))
        result = self.run_app()
        self.assertEqual(2, result.returncode)
        self.assertIn("unexpected registration", result.stderr)
        self.assertFalse((self.root / PROVIDER).exists())

    def test_differing_owned_file_requires_refresh(self):
        existing = self.root / PROVIDER
        existing.parent.mkdir(parents=True, exist_ok=True)
        existing.write_text("preserve me\n")
        result = self.run_app()
        self.assertEqual(2, result.returncode)
        self.assertEqual("preserve me\n", existing.read_text())
        self.assertNotIn("OneHopValueFlowToolProvider;", self.manager.read_text())
        refreshed = self.run_app("--refresh")
        self.assertEqual(0, refreshed.returncode, refreshed.stderr)
        self.assertEqual((BUNDLE / PROVIDER).read_bytes(),
                         existing.read_bytes())


if __name__ == "__main__":
    unittest.main()
