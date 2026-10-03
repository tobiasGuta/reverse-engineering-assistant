#!/usr/bin/env bash
set -euo pipefail

: "${GHIDRA_INSTALL_DIR:=/mnt/Development/Tools/Reverse-Engineering/ghidra_12.1.3_PUBLIC}"
export GHIDRA_INSTALL_DIR

if ! command -v gradle >/dev/null 2>&1; then
  echo "gradle is not installed/in PATH. ReVa requires Gradle 8.x+; install/configure it first." >&2
  exit 2
fi

printf 'Using GHIDRA_INSTALL_DIR=%s\n' "$GHIDRA_INSTALL_DIR"
java -version
gradle --version | sed -n '1,12p'

git diff --check

gradle test --info

gradle integrationTest \
  --tests '*ProgramIntelligenceToolProviderIntegrationTest' \
  --tests '*ControlFlowToolProviderIntegrationTest' \
  --tests '*PcodeToolProviderIntegrationTest' \
  --tests '*SourceMetadataToolProviderIntegrationTest' \
  --info

uv run pytest tests/test_mcp_tools.py -q

echo
printf '%s\n' 'Static-analysis expansion verification completed.'
