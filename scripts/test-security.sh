#!/usr/bin/env bash
# test-security.sh - Security Regression Tests
# protocol spec: Security Regression Tests
#
# Ensures all Sprint 0 security fixes remain intact
# and no new security vulnerabilities are introduced.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS_COUNT=0
FAIL_COUNT=0

green() { echo -e "\033[32m$1\033[0m"; }
red() { echo -e "\033[31m$1\033[0m"; }
yellow() { echo -e "\033[33m$1\033[0m"; }

pass() {
  green "PASS: $1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
  red "FAIL: $1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "=== DCP Security Regression Tests ==="
echo ""

# =============================================================================
# Test 1: No private keys in status --json
# =============================================================================
echo "Test 1: No private keys in agent status --json"
if grep -n "redactConfigForOutput" "${ROOT_DIR}/packages/dcp-agent/src/index.ts" > /dev/null 2>&1; then
  pass "status --json uses redactConfigForOutput to protect secrets"
else
  fail "status --json missing redactConfigForOutput"
fi

# =============================================================================
# Test 2: No private keys in list --json
# =============================================================================
echo "Test 2: No private keys in agent list --json"
if grep -rn "JSON.stringify(configs" "${ROOT_DIR}/packages/dcp-agent/src/index.ts" > /dev/null 2>&1; then
  fail "list --json might directly stringify configs (could leak keys)"
else
  pass "list --json does not directly stringify raw configs"
fi

# =============================================================================
# Test 3: No Math.random in security-critical code
# =============================================================================
echo "Test 3: No Math.random in security-critical code"
MATH_RANDOM_FILES=$(grep -rn "Math\.random" "${ROOT_DIR}/packages/dcp-core/src/" "${ROOT_DIR}/packages/dcp-telegram/src/" 2>/dev/null || true)
if [[ -n "${MATH_RANDOM_FILES}" ]]; then
  fail "Math.random found in security code"
  echo "${MATH_RANDOM_FILES}"
else
  pass "No Math.random in dcp-core or dcp-telegram src"
fi

# =============================================================================
# Test 4: crypto.randomInt used for pairing codes
# =============================================================================
echo "Test 4: CSPRNG used for pairing codes"
if grep -n "randomInt" "${ROOT_DIR}/packages/dcp-telegram/src/store.ts" > /dev/null 2>&1; then
  pass "Telegram pairing uses crypto.randomInt"
else
  fail "Telegram pairing does not use crypto.randomInt"
fi

# =============================================================================
# Test 5: canonicalJson is recursive
# =============================================================================
echo "Test 5: canonicalJson is recursive (handles nested objects)"
CANONICAL_IMPL=$(grep -n "function canonicalJson" "${ROOT_DIR}/packages/dcp-core/src/crypto.ts" 2>/dev/null || true)
if [[ -z "${CANONICAL_IMPL}" ]]; then
  fail "canonicalJson not found in dcp-core/src/crypto.ts"
else
  if grep -A 15 "function canonicalJson" "${ROOT_DIR}/packages/dcp-core/src/crypto.ts" | grep -q "normalize"; then
    pass "canonicalJson is recursive (uses normalize helper)"
  else
    fail "canonicalJson might not be recursive"
  fi
fi

# =============================================================================
# Test 6: Only one canonicalJson implementation in src directories
# =============================================================================
echo "Test 6: Single canonicalJson implementation in src"
# Exclude test files - test files can have their own helper implementations
if command -v rg >/dev/null 2>&1; then
  IMPL_MATCHES=$(rg -n "(export )?function canonicalJson" "${ROOT_DIR}/packages" \
    -g "*.ts" \
    -g "!**/*.d.ts" \
    -g "!**/node_modules/**" \
    -g "!**/dist/**" \
    -g "!**/build/**" \
    -g "!**/target/**" \
    2>/dev/null | grep "/src/" || true)
else
  IMPL_MATCHES=$(find "${ROOT_DIR}/packages" \
    \( -path "*/node_modules/*" -o -path "*/dist/*" -o -path "*/build/*" -o -path "*/target/*" \) -prune -o \
    -path "*/src/*.ts" ! -name "*.d.ts" -type f -print0 \
    | xargs -0 grep -nE "(export )?function canonicalJson" 2>/dev/null || true)
fi
IMPL_COUNT=$(printf "%s\n" "${IMPL_MATCHES}" | sed '/^$/d' | wc -l | tr -d ' ')
if [[ "${IMPL_COUNT}" -eq 1 ]]; then
  pass "Single canonicalJson implementation in src"
elif [[ "${IMPL_COUNT}" -eq 0 ]]; then
  fail "No canonicalJson implementation found in src"
else
  fail "Multiple canonicalJson implementations found in src (${IMPL_COUNT})"
  printf "%s\n" "${IMPL_MATCHES}"
fi

# =============================================================================
# Test 7: Telegram webhook signature validation exists
# =============================================================================
echo "Test 7: Telegram webhook signature validation"
if grep -n "validateTelegramUpdate" "${ROOT_DIR}/packages/dcp-telegram/src/webhook.ts" > /dev/null 2>&1; then
  if grep -n "timingSafeEqual" "${ROOT_DIR}/packages/dcp-telegram/src/webhook.ts" > /dev/null 2>&1; then
    pass "Telegram webhook validation uses timing-safe comparison"
  else
    fail "Telegram webhook validation exists but missing timingSafeEqual"
  fi
else
  fail "validateTelegramUpdate function not found"
fi

# =============================================================================
# Test 8: Approval commands are single-use
# =============================================================================
echo "Test 8: Approval commands are single-use (processed_at check)"
if grep -n "processed_at IS NULL" "${ROOT_DIR}/packages/dcp-telegram/src/store.ts" > /dev/null 2>&1; then
  pass "Approval commands checked for single-use via processed_at"
else
  fail "Approval commands missing single-use check"
fi

# =============================================================================
# Test 9: No secrets in notifications
# =============================================================================
echo "Test 9: Notifications are privacy-safe"
if grep -n "NEVER include" "${ROOT_DIR}/packages/dcp-telegram/src/notification.ts" > /dev/null 2>&1 || \
   grep -n "FORBIDDEN" "${ROOT_DIR}/packages/dcp-telegram/src/notification.ts" > /dev/null 2>&1; then
  pass "Notification module has privacy documentation"
else
  fail "Notification module missing privacy documentation"
fi

# =============================================================================
# Test 10: Ed25519 signature verification exists
# =============================================================================
echo "Test 10: Ed25519 signature verification"
if grep -n "verifyEd25519\|createVerify.*Ed25519" "${ROOT_DIR}/packages/dcp-telegram/src/webhook.ts" > /dev/null 2>&1; then
  pass "Ed25519 signature verification exists"
else
  fail "Ed25519 signature verification not found"
fi

# =============================================================================
# Test 11: Nonce replay protection
# =============================================================================
echo "Test 11: Nonce replay protection"
if grep -n "NonceStore\|checkAndMark" "${ROOT_DIR}/packages/dcp-telegram/src/"*.ts > /dev/null 2>&1; then
  pass "Nonce replay protection exists"
else
  fail "Nonce replay protection not found"
fi

# =============================================================================
# Test 12: Config file permissions check
# =============================================================================
echo "Test 12: Config file permission checks (0600)"
if grep -rn "0o600\|0600" "${ROOT_DIR}/packages/dcp-agent/src/"*.ts > /dev/null 2>&1; then
  pass "Config file permission check exists (0600)"
else
  fail "Config file permission check not found"
fi

# =============================================================================
# Test 13: Cloud-Connect — match-code is MANDATORY on approve (Rule #6)
# =============================================================================
echo "Test 13: Cloud-Connect approve requires a match code"
if grep -n "presentedCode\|expectedCode\|constantTimeStrEqual" "${ROOT_DIR}/packages/dcp-vault/src/server/index.ts" > /dev/null 2>&1; then
  pass "Cloud-Connect approve enforces a mandatory, constant-time match code"
else
  fail "Cloud-Connect approve match-code enforcement not found"
fi

# =============================================================================
# Test 14: Cloud-Connect — PKCE is S256-only (no plain downgrade)
# =============================================================================
echo "Test 14: Relay OAuth PKCE is S256-only"
if grep -rn "code_challenge_methods_supported" "${ROOT_DIR}/packages/dcp-relay/src/oauth/metadata.ts" | grep -q "S256" && \
   ! grep -rn "'plain'" "${ROOT_DIR}/packages/dcp-relay/src/oauth/"*.ts > /dev/null 2>&1; then
  pass "Relay advertises + enforces PKCE S256 only (no plain)"
else
  fail "Relay PKCE may allow plain or S256 not enforced"
fi

# =============================================================================
# Test 15: Cloud-Connect — access tokens are DPoP + audience bound (Rules #2)
# =============================================================================
echo "Test 15: Relay access tokens are DPoP + audience bound"
if grep -n "cnf" "${ROOT_DIR}/packages/dcp-relay/src/oauth/tokens.ts" | grep -q "jkt" && \
   grep -qn "setAudience" "${ROOT_DIR}/packages/dcp-relay/src/oauth/tokens.ts"; then
  pass "Access tokens bind cnf.jkt (DPoP) + audience (RFC 8707)"
else
  fail "Access tokens missing DPoP/audience binding"
fi

# =============================================================================
# Test 16: Cloud-Connect — DPoP proofs are single-use (jti replay guard)
# =============================================================================
echo "Test 16: Relay DPoP proofs have a jti replay guard"
if grep -qn "dpop_replay\|jtiGuard\|createJtiGuard" "${ROOT_DIR}/packages/dcp-relay/src/oauth/dpop.ts"; then
  pass "DPoP proofs are single-use (jti replay guard)"
else
  fail "DPoP jti replay guard not found"
fi

# =============================================================================
# Test 17: Cloud-Connect — refresh tokens rotate with reuse detection (Rule #3)
# =============================================================================
echo "Test 17: Refresh tokens rotate with reuse detection"
if grep -qn "reuse_detected" "${ROOT_DIR}/packages/dcp-relay/src/oauth/store.ts"; then
  pass "Refresh-token reuse is detected (whole-chain revoke)"
else
  fail "Refresh-token reuse detection not found"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=== Security Test Summary ==="
echo "Passed: ${PASS_COUNT}"
echo "Failed: ${FAIL_COUNT}"

if [[ "${FAIL_COUNT}" -gt 0 ]]; then
  red "Some security tests failed!"
  exit 1
fi

green "All security tests passed!"
exit 0
