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

if ! command -v uv >/dev/null 2>&1; then
  echo "error: uv is required for the Python MCP transport check" >&2
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

# ReVa's current lockfile pins JPype1 1.5.2. It has a prebuilt CPython 3.13
# Linux wheel but no CPython 3.14 wheel, so Fedora 44's system Python 3.14
# falls back to a native source build. Use an isolated uv-managed 3.13
# environment for this transport-only regression check. Some uv installations
# configure managed Python downloads as "manual", so explicitly ensure 3.13
# is installed before creating/running the test environment.
printf '\nEnsuring uv-managed CPython 3.13 is available...\n'
uv python install 3.13

printf '\nRunning Python MCP transport check with CPython 3.13...\n'
UV_PROJECT_ENVIRONMENT=.venv-reva-py313 \
  uv run --python 3.13 --frozen pytest tests/test_mcp_tools.py -q

echo
printf '%s\n' 'Static-analysis expansion verification completed.'
