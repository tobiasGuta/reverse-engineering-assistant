#!/usr/bin/env bash
set -euo pipefail

: "${GHIDRA_INSTALL_DIR:=/mnt/Development/Tools/Reverse-Engineering/ghidra_12.1.3_PUBLIC}"
export GHIDRA_INSTALL_DIR

GHIDRA_GRADLE_WRAPPER="$GHIDRA_INSTALL_DIR/support/gradle/gradlew"

if command -v gradle >/dev/null 2>&1; then
  GRADLE_CMD=(gradle)
elif [[ -x "$GHIDRA_GRADLE_WRAPPER" ]]; then
  GRADLE_CMD=("$GHIDRA_GRADLE_WRAPPER")
else
  echo "error: no system Gradle found and Ghidra's supplied Gradle wrapper is unavailable:" >&2
  echo "  $GHIDRA_GRADLE_WRAPPER" >&2
  echo "Ghidra 12.1.x supports using its supplied wrapper when Internet access is available." >&2
  exit 2
fi

printf 'Using GHIDRA_INSTALL_DIR=%s\n' "$GHIDRA_INSTALL_DIR"
printf 'Using Gradle command: %s\n' "${GRADLE_CMD[*]}"
java -version
"${GRADLE_CMD[@]}" --version | sed -n '1,12p'

git diff --check

"${GRADLE_CMD[@]}" test --info

"${GRADLE_CMD[@]}" integrationTest \
  --tests '*ProgramIntelligenceToolProviderIntegrationTest' \
  --tests '*ControlFlowToolProviderIntegrationTest' \
  --tests '*PcodeToolProviderIntegrationTest' \
  --tests '*SourceMetadataToolProviderIntegrationTest' \
  --info

uv run pytest tests/test_mcp_tools.py -q

echo
printf '%s\n' 'Static-analysis expansion verification completed.'
