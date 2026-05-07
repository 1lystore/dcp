#!/bin/bash
# Debug wrapper to log what OpenClaw sends

LOG=/tmp/dcp-debug.log
echo "=== $(date) ===" >> "$LOG"
echo "ARGS: $@" >> "$LOG"
echo "STDIN:" >> "$LOG"
cat | tee -a "$LOG" | /Users/iftakharrahmany/.nvm/versions/node/v22.22.2/bin/node /Users/iftakharrahmany/myproducts/dcp/packages/dcp-agent/dist/index.js "$@"
EXIT=$?
echo "EXIT: $EXIT" >> "$LOG"
exit $EXIT
