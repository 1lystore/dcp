#!/bin/sh
# DCP Agent Docker Entrypoint
#
# Handles:
# 1. Automatic pairing if DCP_PAIR_GRANT is set
# 2. Running the agent in specified mode

set -e

# Auto-pair if grant provided and not already configured
if [ -n "$DCP_PAIR_GRANT" ]; then
  # Check if already configured
  if ! dcp-agent status --json 2>/dev/null | grep -q '"configured": true'; then
    echo "[DCP] Pairing with vault..."
    dcp-agent pair "$DCP_PAIR_GRANT"
    echo "[DCP] Pairing complete"
  else
    echo "[DCP] Agent already configured, skipping pairing"
  fi
fi

# Handle different modes
case "$1" in
  secrets)
    # OpenClaw exec provider mode - read from stdin, write to stdout
    exec dcp-agent secrets
    ;;
  run|proxy)
    # Proxy mode - start HTTP server
    exec dcp-agent run --mode proxy
    ;;
  status)
    exec dcp-agent status "$@"
    ;;
  get-secret)
    shift
    exec dcp-agent get-secret "$@"
    ;;
  *)
    # Pass through to dcp-agent
    exec dcp-agent "$@"
    ;;
esac
