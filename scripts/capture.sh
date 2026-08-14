#!/usr/bin/env bash
set -euo pipefail

# Captures DynamoDB Local + memcached traffic for process.clj's decode
# pipeline. Run this *before* loading setup.clj (which starts the whole
# stack as a side effect of loading -- see its ns docstring) so tshark sees
# the initial TCP handshakes too. Stop with Ctrl-C once you've done the peer
# work you want captured.
#
# Usage: scripts/capture.sh [path]
# Writes to `path` if given, else $TSHARK_LOG, else /tmp/tshark.log. If you
# use a non-default path, `(reset! setup/tshark-log "that/path")` in the
# REPL too, so setup.clj's port-owners dump and process.clj's read line up
# with it.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-${TSHARK_LOG:-/tmp/tshark.log}}"

echo "Capturing to ${OUT} (Ctrl-C to stop)..."
sudo tshark -i lo0 -f "tcp port 8000 or tcp port 11211" -T ek -l \
  -d tcp.port==8000,http > "${OUT}"
