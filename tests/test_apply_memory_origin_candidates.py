#!/usr/bin/env python3
"""Guarded memory-origin candidate overlay integration tests (offline only)."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BUNDLE = Path(__file__).resolve().parents[1]
INSTALLER = BUNDLE / "apply_memory_origin_candidates.py"
PROVIDER = Path(
    "src/main/java/reva/tools/dataflow/MemoryOriginCandidateToolProvider.java")
INTEGRATION = Path(
    "src/test.slow/java/reva/tools/dataflow/MemoryOriginCandidateToolProviderIntegrationTest.java")
MANAGER = Path("src/main/java/reva/server/McpServerManager.java")
CATALOG = Path("tests/test_mcp_tools.py")
TWO_HOP = Path(
    "src/main/java/reva/tools/dataflow/TwoHopValueFlowToolProvider.java")
BOUNDED = Path(
    "src/main/java/reva/tools/dataflow/BoundedDataFlowSlice.java")


class MemoryOriginInstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for rel in (MANAGER, CATALOG, TWO_HOP, BOUNDED,
                    Path("build.gradle")):
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
        (self.root / MANAGER).write_text(
            "import reva.tools.dataflow.TwoHopValueFlowToolProvider;\n"
            "                    new TwoHopValueFlowToolProvider(server));\n"
        )
        (self.root / CATALOG).write_text(
            '    "trace-call-argument-two-hop",\n'
        )
        (self.root / TWO_HOP).write_text("trace-call-argument-two-hop\n")
        (self.root / BOUNDED).write_text("// preserved helper\n")
        (self.root / "build.gradle").write_text("// fixture\n")

    def run_installer(self, *args):
        return subprocess.run(
            [sys.executable, str(INSTALLER), str(self.root), *args],
            text=True, capture_output=True, timeout=20,
        )

    def test_install_and_reapply_are_idempotent(self):
        first = self.run_installer()
        self.assertEqual(0, first.returncode, first.stderr)
        for rel in (PROVIDER, INTEGRATION):
            self.assertEqual((BUNDLE / rel).read_bytes(),
                             (self.root / rel).read_bytes())
        managed = (self.root / MANAGER).read_text()
        catalog = (self.root / CATALOG).read_text()
        self.assertEqual(1, managed.count(
            "new MemoryOriginCandidateToolProvider(server)"))
        self.assertEqual(1, catalog.count('"trace-memory-load-origins"'))
        before = {
            rel: (self.root / rel).read_bytes()
            for rel in (PROVIDER, INTEGRATION, MANAGER, CATALOG,
                        TWO_HOP, BOUNDED)
        }
        again = self.run_installer()
        self.assertEqual(0, again.returncode, again.stderr)
        self.assertEqual(before, {
            rel: (self.root / rel).read_bytes() for rel in before
        })

    def test_reject_edits_without_refresh(self):
        self.assertEqual(0, self.run_installer().returncode)
        target = self.root / PROVIDER
        target.write_text("local changes\n")
        before_manager = (self.root / MANAGER).read_bytes()
        rejected = self.run_installer()
        self.assertEqual(2, rejected.returncode)
        self.assertEqual("local changes\n", target.read_text())
        self.assertEqual(before_manager, (self.root / MANAGER).read_bytes())
        refreshed = self.run_installer("--refresh")
        self.assertEqual(0, refreshed.returncode, refreshed.stderr)
        self.assertEqual((BUNDLE / PROVIDER).read_bytes(), target.read_bytes())

    def test_partial_registration_is_rejected_before_writes(self):
        manager = self.root / MANAGER
        manager.write_text(manager.read_text() +
            "import reva.tools.dataflow.MemoryOriginCandidateToolProvider;\n")
        before = manager.read_bytes()
        result = self.run_installer()
        self.assertEqual(2, result.returncode)
        self.assertEqual(before, manager.read_bytes())
        self.assertFalse((self.root / PROVIDER).exists())


if __name__ == "__main__":
    unittest.main()
