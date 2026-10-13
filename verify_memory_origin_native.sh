#!/usr/bin/env bash
# Targeted libcue memory-origin regression: build and test a scratch extension.
# The stable Ghidra SDK is read-only; no normal project or binary is executed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-/mnt/Development/Tools/ReVa-Static-Analysis}"
STABLE="${GHIDRA_INSTALL_DIR:-/mnt/Development/Tools/Reverse-Engineering/ghidra_12.1.3_PUBLIC}"
WRAPPER="$STABLE/support/gradle/gradlew"

for command in uv unzip cp mktemp python3; do
    if ! command -v "$command" >/dev/null 2>&1; then
        printf 'ERROR: missing required command: %s\n' "$command" >&2
        exit 2
    fi
done
test -x "$WRAPPER" || { echo "ERROR: Ghidra Gradle wrapper absent" >&2; exit 2; }
test -f "$SRC/src/main/java/reva/tools/dataflow/MemoryOriginCandidateToolProvider.java" || {
    echo "ERROR: memory-origin development overlay not installed" >&2; exit 2;
}
test -f "$SRC/tests/test_memory_origin_libcue_real_binary.py" || {
    echo "ERROR: memory-origin native acceptance test not installed" >&2; exit 2;
}
test -d "$STABLE/Ghidra" || { echo "ERROR: Ghidra SDK path invalid" >&2; exit 2; }

cd "$SRC"
git diff --check
export GHIDRA_INSTALL_DIR="$STABLE"
"$WRAPPER" buildExtension --console=plain

# Verify the compiled memory-origin implementation is in the artifact under test.
ZIP="$(python3 - "$SRC" <<'PY'
from pathlib import Path
from io import BytesIO
from zipfile import ZipFile
import sys
dist = Path(sys.argv[1]) / "dist"
archives = list(dist.glob("*ReVa-Static-Analysis.zip"))
if not archives:
    raise SystemExit("ERROR: no ReVa extension archive")
archive = max(archives, key=lambda path: path.stat().st_mtime_ns)
with ZipFile(archive) as outer:
    jars = [name for name in outer.namelist()
            if name.endswith(
                "ReVa-Static-Analysis/lib/ReVa-Static-Analysis.jar")]
    if len(jars) != 1:
        raise SystemExit("ERROR: unexpected extension layout")
    with ZipFile(BytesIO(outer.read(jars[0]))) as jar:
        cls = jar.read(
            "reva/tools/dataflow/MemoryOriginCandidateToolProvider.class")
if b"trace-memory-load-origins" not in cls:
    raise SystemExit("ERROR: current memory-origin provider missing from archive")
print(archive)
PY
)"

STABLE_PARENT="$(dirname "$STABLE")"
SCRATCH="$(mktemp -d "$STABLE_PARENT/.reva-memory-origin-test.XXXXXX")"
cleanup() {
    if [[ -n "${SCRATCH:-}" && -d "$SCRATCH" ]]; then
        rm -rf -- "$SCRATCH"
    fi
}
trap cleanup EXIT

COPY="$SCRATCH/$(basename "$STABLE")"
mkdir -p "$COPY"
cp -a --reflink=auto "$STABLE/." "$COPY/"
EXT="$COPY/Ghidra/Extensions"
# Remove stale ReVa only INSIDE THE DISPOSABLE COPY.
rm -rf -- "$EXT/ReVa" "$EXT/ReVa-Static-Analysis"
unzip -q "$ZIP" -d "$EXT"
test -s "$EXT/ReVa-Static-Analysis/lib/ReVa-Static-Analysis.jar"
mkdir -p "$SCRATCH/xdg"

echo "Running isolated real-libcue memory-origin investigation (ELFs never executed)."
GHIDRA_INSTALL_DIR="$COPY" \
XDG_CONFIG_HOME="$SCRATCH/xdg" \
UV_PROJECT_ENVIRONMENT=.venv-reva-py313 \
    uv run --python 3.13 --frozen pytest \
    tests/test_memory_origin_libcue_real_binary.py -q -s

echo "PASS: isolated libcue memory-origin acceptance completed."
