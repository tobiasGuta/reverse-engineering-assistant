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
  exit 2
fi

for cmd in uv unzip cp mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: required command not found: $cmd" >&2
    exit 2
  fi
done

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
  --tests '*StackAbiToolProviderIntegrationTest' \
  --tests '*SemanticProvenanceToolProviderIntegrationTest' \
  --info

# Build the exact extension under test. Python/PyGhidra discovers ReVa as a
# Ghidra extension, so running pytest against the normal workstation Ghidra
# would otherwise load whichever ReVa version is already installed there.
"${GRADLE_CMD[@]}" buildExtension

EXTENSION_ZIP="$(ls -1t dist/*.zip 2>/dev/null | head -n 1 || true)"
if [[ -z "$EXTENSION_ZIP" || ! -f "$EXTENSION_ZIP" ]]; then
  echo "error: buildExtension did not produce a zip in dist/" >&2
  exit 2
fi

# Clone the Ghidra installation into a throwaway sibling directory. On
# filesystems supporting reflinks (including Btrfs), this is copy-on-write;
# elsewhere GNU cp falls back to a normal copy. The real Ghidra installation
# and its installed ReVa extension are never modified.
GHIDRA_PARENT="$(dirname "$GHIDRA_INSTALL_DIR")"
SCRATCH_ROOT="$(mktemp -d "$GHIDRA_PARENT/.reva-ghidra-test.XXXXXX")"
SCRATCH_GHIDRA="$SCRATCH_ROOT/$(basename "$GHIDRA_INSTALL_DIR")"
cleanup_scratch() {
  if [[ -n "${SCRATCH_ROOT:-}" && -d "$SCRATCH_ROOT" ]]; then
    rm -rf -- "$SCRATCH_ROOT"
  fi
}
trap cleanup_scratch EXIT

mkdir -p "$SCRATCH_GHIDRA"
printf '\nCreating isolated Ghidra test copy at %s...\n' "$SCRATCH_GHIDRA"
if cp --help 2>/dev/null | grep -q -- '--reflink'; then
  cp -a --reflink=auto "$GHIDRA_INSTALL_DIR/." "$SCRATCH_GHIDRA/"
else
  cp -a "$GHIDRA_INSTALL_DIR/." "$SCRATCH_GHIDRA/"
fi

# Remove only the ReVa directory inside the disposable copy, then install the
# freshly built extension. This prevents stale files from an older ReVa build.
rm -rf -- "$SCRATCH_GHIDRA/Ghidra/Extensions/ReVa"
mkdir -p "$SCRATCH_GHIDRA/Ghidra/Extensions"
unzip -q "$EXTENSION_ZIP" -d "$SCRATCH_GHIDRA/Ghidra/Extensions"

# Isolate Ghidra user settings too. GUI-installed extensions live below the
# user settings directory and could otherwise shadow/duplicate the scratch
# extension during PyGhidra startup.
mkdir -p "$SCRATCH_ROOT/xdg"

# ReVa currently pins JPype1 1.5.2, which has a CPython 3.13 Linux wheel but
# no CPython 3.14 wheel. Use an isolated uv-managed 3.13 environment so Fedora
# 44 does not need a native JPype source build.
printf '\nEnsuring uv-managed CPython 3.13 is available...\n'
uv python install 3.13

printf '\nRunning Python MCP transport check against isolated development extension...\n'
GHIDRA_INSTALL_DIR="$SCRATCH_GHIDRA" \
XDG_CONFIG_HOME="$SCRATCH_ROOT/xdg" \
UV_PROJECT_ENVIRONMENT=.venv-reva-py313 \
  uv run --python 3.13 --frozen pytest tests/test_mcp_tools.py -q

echo
printf '%s\n' 'Static-analysis expansion (Slices 1-3) verification completed.'
