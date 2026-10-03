#!/usr/bin/env bash
set -euo pipefail

UPSTREAM_URL="https://github.com/cyberkaida/reverse-engineering-assistant.git"
UPSTREAM_COMMIT="01a154a8edf233b02a0e7707e2ff5933893c6d53"
DEFAULT_DEST="/mnt/Development/Tools/ReVa-Static-Analysis"

DEST="${1:-$DEFAULT_DEST}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ -e "$DEST" ]]; then
  echo "error: destination already exists: $DEST" >&2
  echo "Choose another path or remove it yourself after reviewing its contents." >&2
  exit 2
fi

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is required" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required" >&2
  exit 2
fi

echo "Cloning upstream ReVa..."
git clone "$UPSTREAM_URL" "$DEST"

cd "$DEST"

echo "Checking out reviewed upstream commit..."
git checkout "$UPSTREAM_COMMIT"
git switch -c feat/static-analysis-expansion-local

echo "Applying generic static-analysis expansion..."
python3 "$SCRIPT_DIR/apply_static_analysis_expansion.py" .

echo
echo "Running diff safety checks..."
git diff --check
git status --short
git diff --stat

cat <<EOF

Prepared local test checkout:
  $DEST

No commit was created.
No extension was installed.
No Ghidra project or binary was modified.

Next:
  export GHIDRA_INSTALL_DIR=/mnt/Development/Tools/Reverse-Engineering/ghidra_12.1.3_PUBLIC
  "$SCRIPT_DIR/verify_static_analysis_expansion.sh"

EOF
