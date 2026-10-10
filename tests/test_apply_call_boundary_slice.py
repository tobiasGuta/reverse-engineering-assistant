"""Offline regression tests for the guarded Slice 5A applicator.

No Ghidra, network, or upstream checkout is required. Run from the
development repository root:
    python3 -m unittest discover -s tests -p test_apply_call_boundary_slice.py
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BUNDLE = Path(__file__).resolve().parents[1]
SCRIPT = BUNDLE / "apply_call_boundary_slice.py"
PROVIDER = Path(
    "src/main/java/reva/tools/callboundary/CallBoundaryToolProvider.java"
)
TEST = Path(
    "src/test.slow/java/reva/tools/callboundary/"
    "CallBoundaryToolProviderIntegrationTest.java"
)

MANAGER = Path("src/main/java/reva/server/McpServerManager.java")
TRANSPORT = Path("tests/test_mcp_tools.py")
FROZEN = Path("src/main/java/reva/tools/stackstate/FrozenMarker.java")

IMPORT = "import reva.tools.stackstate.StackExecutionStateToolProvider;\n"
REGISTRATION = "                    new StackExecutionStateToolProvider(server));"
TRANSPORT_ENTRY = '    "get-function-stack-state",\n'

MANAGER_STUB = (
    "// frozen registrations\n"
    "// ProgramIntelligenceToolProvider ControlFlowToolProvider\n"
    "// PcodeToolProvider SourceMetadataToolProvider\n"
    "// StackAbiToolProvider SemanticProvenanceToolProvider\n"
    + IMPORT
    + "class Manager {\n"
    + REGISTRATION
    + "\n}\n"
)


class ApplySlice5ATest(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.repo = Path(self.workspace.name) / "upstream"
        self.repo.mkdir()
        for path, text in (
            ("build.gradle", "// fake upstream marker\n"),
            (MANAGER, MANAGER_STUB),
            (TRANSPORT, "EXPECTED_TOOLS = {\n" + TRANSPORT_ENTRY + "}\n"),
            (FROZEN, "original frozen provider\n"),
        ):
            dest = self.repo / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text)

    def run_helper(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.repo), *args],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def test_apply_is_idempotent_and_preserves_frozen_provider(self) -> None:
        frozen_before = (self.repo / FROZEN).read_bytes()
        first = self.run_helper()
        self.assertEqual(0, first.returncode, first.stderr)

        self.assertEqual(
            (BUNDLE / PROVIDER).read_bytes(),
            (self.repo / PROVIDER).read_bytes(),
        )
        self.assertEqual(
            (BUNDLE / TEST).read_bytes(),
            (self.repo / TEST).read_bytes(),
        )
        manager = (self.repo / MANAGER).read_text()
        self.assertEqual(
            1, manager.count("new CallBoundaryToolProvider(server)"),
        )
        self.assertEqual(
            1, manager.count("import reva.tools.callboundary."),
        )
        self.assertIn('"inspect-call-boundary"', (self.repo / TRANSPORT).read_text())
        self.assertEqual(frozen_before, (self.repo / FROZEN).read_bytes())

        saved = [(self.repo / p).read_bytes()
                 for p in (PROVIDER, TEST, MANAGER, TRANSPORT, FROZEN)]
        second = self.run_helper()
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertEqual(saved, [(self.repo / p).read_bytes()
                                 for p in (PROVIDER, TEST, MANAGER, TRANSPORT, FROZEN)])

    def test_conflict_causes_no_partial_writes(self) -> None:
        dest = self.repo / PROVIDER
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text("DO NOT REPLACE\n")
        manager_before = (self.repo / MANAGER).read_bytes()
        transport_before = (self.repo / TRANSPORT).read_bytes()
        result = self.run_helper()
        self.assertEqual(2, result.returncode)
        self.assertIn("Refusing to overwrite", result.stderr)
        self.assertEqual("DO NOT REPLACE\n", dest.read_text())
        self.assertFalse((self.repo / TEST).exists())
        self.assertEqual(manager_before, (self.repo / MANAGER).read_bytes())
        self.assertEqual(transport_before, (self.repo / TRANSPORT).read_bytes())

    def test_refresh_changes_only_owned_files(self) -> None:
        initial = self.run_helper()
        self.assertEqual(0, initial.returncode, initial.stderr)
        frozen_before = (self.repo / FROZEN).read_bytes()
        (self.repo / PROVIDER).write_text("older Slice 5A provider\n")
        refreshed = self.run_helper("--refresh")
        self.assertEqual(0, refreshed.returncode, refreshed.stderr)
        self.assertEqual((BUNDLE / PROVIDER).read_bytes(),
                         (self.repo / PROVIDER).read_bytes())
        self.assertEqual(frozen_before, (self.repo / FROZEN).read_bytes())

    def test_missing_frozen_registration_refuses_before_copy(self) -> None:
        (self.repo / MANAGER).write_text(
            MANAGER_STUB.replace("StackAbiToolProvider", "MissingAbi")
        )
        result = self.run_helper()
        self.assertEqual(2, result.returncode)
        self.assertIn("Missing frozen", result.stderr)
        self.assertFalse((self.repo / PROVIDER).exists())
        self.assertFalse((self.repo / TEST).exists())


if __name__ == "__main__":
    unittest.main()
