#!/usr/bin/env python3
"""Offline guarded-installer regressions for additive two-hop MCP tool."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BUNDLE = Path(__file__).resolve().parents[1]
SCRIPT = BUNDLE / "apply_two_hop_candidate_flow.py"
PROVIDER = Path("src/main/java/reva/tools/dataflow/TwoHopValueFlowToolProvider.java")
TEST = Path("src/test.slow/java/reva/tools/dataflow/TwoHopValueFlowToolProviderIntegrationTest.java")


class TwoHopInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manager = self.root / "src/main/java/reva/server/McpServerManager.java"
        self.transport = self.root / "tests/test_mcp_tools.py"
        one_hop = self.root / "src/main/java/reva/tools/dataflow/OneHopValueFlowToolProvider.java"
        bounded = self.root / "src/main/java/reva/tools/dataflow/BoundedDataFlowSlice.java"
        for file in (self.manager, self.transport, one_hop, bounded,
                     self.root / "build.gradle"):
            file.parent.mkdir(parents=True, exist_ok=True)
        self.manager.write_text(
            "import reva.tools.dataflow.OneHopValueFlowToolProvider;\n"
            "                    new OneHopValueFlowToolProvider(server));\n"
        )
        self.transport.write_text(
            '    "trace-call-argument-one-hop",\n'
        )
        one_hop.write_text("selectReportedOperations(\nBoundedDataFlowSlice.collect(\n")
        bounded.write_text("class BoundedDataFlowSlice {}\n")
        (self.root / "build.gradle").write_text("// test fixture\n")

    def run_installer(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.root), *args],
            text=True, capture_output=True, timeout=20,
        )

    def test_installs_idempotently(self):
        first = self.run_installer()
        self.assertEqual(0, first.returncode, first.stderr)
        for file in (PROVIDER, TEST):
            self.assertEqual((BUNDLE / file).read_bytes(),
                             (self.root / file).read_bytes())
        self.assertEqual(1, self.manager.read_text().count(
            "import reva.tools.dataflow.TwoHopValueFlowToolProvider;"))
        self.assertEqual(1, self.manager.read_text().count(
            "new TwoHopValueFlowToolProvider(server)"))
        self.assertEqual(1, self.transport.read_text().count(
            '"trace-call-argument-two-hop"'))
        snapshot = {
            f: f.read_bytes() for f in (
                self.manager, self.transport, self.root / PROVIDER,
                self.root / TEST
            )
        }
        second = self.run_installer()
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertEqual(snapshot,
            {f: f.read_bytes() for f in snapshot})

    def test_refresh_only_owned_files(self):
        self.assertEqual(0, self.run_installer().returncode)
        dst = self.root / PROVIDER
        dst.write_text("preserve local work\n")
        before = {file: file.read_bytes() for file in (
            self.manager, self.transport, self.root / TEST
        )}
        rejected = self.run_installer()
        self.assertEqual(2, rejected.returncode)
        self.assertEqual("preserve local work\n", dst.read_text())
        self.assertEqual(before,
            {file: file.read_bytes() for file in before})
        refreshed = self.run_installer("--refresh")
        self.assertEqual(0, refreshed.returncode, refreshed.stderr)
        self.assertEqual((BUNDLE / PROVIDER).read_bytes(), dst.read_bytes())

    def test_refuse_partial_registration_without_writes(self):
        old_manager = self.manager.read_text()
        self.manager.write_text(
            old_manager +
            "import reva.tools.dataflow.TwoHopValueFlowToolProvider;\n"
        )
        original = self.manager.read_bytes()
        fail = self.run_installer()
        self.assertEqual(2, fail.returncode)
        self.assertEqual(original, self.manager.read_bytes())
        self.assertFalse((self.root / PROVIDER).exists())


if __name__ == "__main__":
    unittest.main()
