"""Offline regression for Slice 3 installation into later ReVa layers."""

import pytest

from apply_semantic_provenance_slice import (
    ensure_semantic_registration,
    ensure_semantic_transport,
)


def test_later_layer_registration_is_preserved_byte_for_byte():
    manager = (
        "import reva.tools.stackabi.StackAbiToolProvider;\n"
        "import reva.tools.provenance.SemanticProvenanceToolProvider;\n"
        "import reva.tools.callboundary.CallBoundaryToolProvider;\n"
        "                    new SourceMetadataToolProvider(server),\n"
        "                    new StackAbiToolProvider(server),\n"
        "                    new SemanticProvenanceToolProvider(server),\n"
        "                    new CallBoundaryToolProvider(server));\n"
    )
    catalog = (
        '    "get-function-abi",\n'
        '    "get-decompiler-provenance",\n'
        '    "get-callsite-semantics",\n'
        '    "inspect-call-boundary",\n'
        '    "trace-call-argument-one-hop",\n'
    )
    assert ensure_semantic_registration(manager) == manager
    assert ensure_semantic_transport(catalog) == catalog


def test_original_slice_registration_can_still_be_applied():
    manager = (
        "import reva.tools.stackabi.StackAbiToolProvider;\n"
        "                    new SourceMetadataToolProvider(server),\n"
        "                    new StackAbiToolProvider(server));\n"
    )
    catalog = '    "get-function-abi",\n'
    expanded = ensure_semantic_registration(manager)
    assert expanded.count(
        "import reva.tools.provenance.SemanticProvenanceToolProvider;"
    ) == 1
    assert expanded.count("new SemanticProvenanceToolProvider(server)") == 1
    assert ensure_semantic_registration(expanded) == expanded

    tool_catalog = ensure_semantic_transport(catalog)
    assert tool_catalog.count('"get-decompiler-provenance"') == 1
    assert tool_catalog.count('"get-callsite-semantics"') == 1
    assert ensure_semantic_transport(tool_catalog) == tool_catalog


def test_inconsistent_registration_fails_closed():
    partial_manager = (
        "import reva.tools.provenance.SemanticProvenanceToolProvider;\n"
        "                    new StackAbiToolProvider(server));\n"
    )
    with pytest.raises(RuntimeError, match="Partial or duplicate"):
        ensure_semantic_registration(partial_manager)

    with pytest.raises(RuntimeError, match="Partial or duplicate"):
        ensure_semantic_transport('    "get-decompiler-provenance",\n')
