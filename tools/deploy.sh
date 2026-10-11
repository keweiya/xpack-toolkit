#!/usr/bin/env bash
# Local wrapper for the verified unlock workflow.
#
#   ./tools/deploy.sh install    install build/ with a verified signed license
#   ./tools/deploy.sh deploy     compatibility alias for install
#   ./tools/deploy.sh restore    restore verified official binaries and root rows
#   ./tools/deploy.sh verify     verify binary, encrypted root rows and license DB
#   ./tools/deploy.sh cert       retain a verified signed license for manual import
#
# Signing inputs: local SIGN_KEY or pre-issued LICENSE_FILE; no key downloads.
# Existing valid signed licenses may be reused without changing expiry/nodes.
# Set NODES, EXPIRES and ASSIGNEE via environment when issuing a new license.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-install}"
if [ $# -gt 0 ]; then shift; fi
case "$MODE" in
  deploy) MODE=install ;;
  install|restore|verify|cert) ;;
  *) printf 'usage: %s {install|deploy|restore|verify|cert}\n' "$0" >&2; exit 1 ;;
esac
[ $# -eq 0 ] || { printf 'Use EXPIRES/NODES/ASSIGNEE environment variables, not positional arguments.\n' >&2; exit 1; }
export STATE="$ROOT/state"
export LOCAL=1
export ARTIFACT_DIR="$ROOT/build"
exec bash "$ROOT/unlock.sh" "$MODE"
