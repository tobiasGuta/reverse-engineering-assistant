#!/usr/bin/env bash
set -euo pipefail

SOURCE_REPO="${SOURCE_REPO:-/mnt/Development/Tools/ReVa-Static-Analysis}"
STABLE_GHIDRA="${STABLE_GHIDRA:-/mnt/Development/Tools/Reverse-Engineering/ghidra_12.1.3_PUBLIC}"
DEV_GHIDRA="${DEV_GHIDRA:-/mnt/Development/Tools/Reverse-Engineering/ghidra_12.1.3_REVA_DEV}"
DEV_CONFIG="${DEV_CONFIG:-/mnt/Development/Tools/Reverse-Engineering/.reva-dev-config}"

REFRESH=false
if [[ "${1:-}" == "--refresh" ]]; then
  REFRESH=true
elif [[ $# -gt 0 ]]; then
  echo "usage: $0 [--refresh]" >&2
  exit 2
fi

if [[ ! -d "$SOURCE_REPO/.git" ]]; then
  echo "error: source checkout not found: $SOURCE_REPO" >&2
  exit 2
fi
if [[ ! -x "$STABLE_GHIDRA/ghidraRun" ]]; then
  echo "error: stable Ghidra installation not found: $STABLE_GHIDRA" >&2
  exit 2
fi
if [[ "$DEV_GHIDRA" == "$STABLE_GHIDRA" ]]; then
  echo "error: DEV_GHIDRA must not equal STABLE_GHIDRA" >&2
  exit 2
fi

case "$(basename "$DEV_GHIDRA")" in
  *REVA_DEV*) ;;
  *)
    echo "error: refusing destructive dev refresh because DEV_GHIDRA basename does not contain REVA_DEV:" >&2
    echo "  $DEV_GHIDRA" >&2
    exit 2
    ;;
esac

GHIDRA_GRADLE_WRAPPER="$STABLE_GHIDRA/support/gradle/gradlew"
if [[ ! -x "$GHIDRA_GRADLE_WRAPPER" ]]; then
  echo "error: Ghidra Gradle wrapper not found: $GHIDRA_GRADLE_WRAPPER" >&2
  exit 2
fi

if [[ -e "$DEV_GHIDRA" ]]; then
  if [[ "$REFRESH" != true ]]; then
    echo "error: development Ghidra already exists: $DEV_GHIDRA" >&2
    echo "Re-run with --refresh to replace only that development copy." >&2
    exit 2
  fi
  echo "Refreshing development Ghidra copy..."
  rm -rf -- "$DEV_GHIDRA"
fi

cd "$SOURCE_REPO"

echo "Checking source diff..."
git diff --check

echo "Building development ReVa extension..."
export GHIDRA_INSTALL_DIR="$STABLE_GHIDRA"
"$GHIDRA_GRADLE_WRAPPER" buildExtension

EXTENSION_ZIP="$(ls -1t dist/*.zip 2>/dev/null | head -n 1 || true)"
if [[ -z "$EXTENSION_ZIP" || ! -f "$EXTENSION_ZIP" ]]; then
  echo "error: buildExtension did not produce a zip in $SOURCE_REPO/dist" >&2
  exit 2
fi

echo "Creating persistent isolated Ghidra development copy..."
mkdir -p "$DEV_GHIDRA"
if cp --help 2>/dev/null | grep -q -- '--reflink'; then
  cp -a --reflink=auto "$STABLE_GHIDRA/." "$DEV_GHIDRA/"
else
  cp -a "$STABLE_GHIDRA/." "$DEV_GHIDRA/"
fi

# Remove any stable or previous development ReVa only from the development copy.
rm -rf --   "$DEV_GHIDRA/Ghidra/Extensions/ReVa"   "$DEV_GHIDRA/Ghidra/Extensions/ReVa-Static-Analysis"

mkdir -p "$DEV_GHIDRA/Ghidra/Extensions"
unzip -q "$EXTENSION_ZIP" -d "$DEV_GHIDRA/Ghidra/Extensions"

mkdir -p "$DEV_CONFIG"

echo
echo "Development environment prepared."
echo "Stable Ghidra was not modified:"
echo "  $STABLE_GHIDRA"
echo
echo "Development Ghidra:"
echo "  $DEV_GHIDRA"
echo
echo "Development settings:"
echo "  $DEV_CONFIG"
echo
echo "Launch it with:"
printf '  XDG_CONFIG_HOME=%q %q\n' "$DEV_CONFIG" "$DEV_GHIDRA/ghidraRun"
echo
echo "Use this copy for the manual MCP smoke test."
