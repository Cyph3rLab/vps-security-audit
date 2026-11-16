#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/vps_audit.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

[[ -f "$SCRIPT" ]] || fail 'vps_audit.sh is missing'
bash -n "$SCRIPT" || fail 'bash syntax check failed'
grep -q '^SCRIPT_VERSION="1\.1"' "$SCRIPT" || fail 'unexpected script version'
grep -q '^umask 077' "$SCRIPT" || fail 'secure umask is not configured'
grep -q '^REPORT_MODE=600' "$SCRIPT" || fail 'report mode is not 600'
grep -q 'REPORT_TMP=.*mktemp' "$SCRIPT" || fail 'temporary report file handling is missing'
grep -q 'PROMPT_TMP=.*mktemp' "$SCRIPT" || fail 'temporary prompt file handling is missing'
grep -q 'chmod "\$REPORT_MODE"' "$SCRIPT" || fail 'report permissions are not explicitly set'

printf 'PASS: basic project checks\n'
