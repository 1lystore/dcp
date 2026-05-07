#!/bin/bash
# DCP Agent Install Script
# Usage: curl -fsSL https://dcp.1ly.store/install | sh
# With pairing: curl -fsSL https://dcp.1ly.store/install | sh -s -- --pair <grant>
#
# This script:
# 1. Checks for Node.js (installs via nvm if missing)
# 2. Installs @dcprotocol/agent globally
# 3. Optionally pairs with a vault if --pair is provided

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments
PAIR_GRANT=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --pair)
      PAIR_GRANT="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║       DCP Agent Installer                ║"
echo "║       Secure secrets for AI agents       ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check OS
OS="$(uname -s)"
case "$OS" in
  Linux*)   PLATFORM="linux" ;;
  Darwin*)  PLATFORM="macos" ;;
  *)        log_error "Unsupported OS: $OS"; exit 1 ;;
esac
log_info "Detected platform: $PLATFORM"

# Check for Node.js
check_node() {
  if command -v node &> /dev/null; then
    NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
    if [ "$NODE_VERSION" -ge 18 ] && [ "$NODE_VERSION" -lt 23 ]; then
      log_success "Node.js $(node -v) detected"
      return 0
    else
      log_warn "Node.js $(node -v) found but DCP requires Node 18-22"
      return 1
    fi
  fi
  return 1
}

# Install Node.js via nvm
install_node() {
  log_info "Installing Node.js via nvm..."

  # Install nvm if not present
  if [ ! -d "$HOME/.nvm" ]; then
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
  fi

  # Load nvm
  export NVM_DIR="$HOME/.nvm"
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

  # Install Node 20 LTS
  nvm install 20
  nvm use 20

  log_success "Node.js $(node -v) installed"
}

# Main installation
main() {
  # Check/install Node.js
  if ! check_node; then
    install_node
  fi

  # Install dcp-agent
  log_info "Installing @dcprotocol/agent..."
  npm install -g @dcprotocol/agent
  log_success "dcp-agent installed"

  # Verify installation
  if command -v dcp-agent &> /dev/null; then
    log_success "Installation verified: $(dcp-agent --version)"
  else
    # Try adding npm global bin to PATH
    NPM_BIN=$(npm bin -g 2>/dev/null || echo "$HOME/.npm-global/bin")
    if [ -x "$NPM_BIN/dcp-agent" ]; then
      log_warn "dcp-agent installed but not in PATH"
      log_info "Add to your shell profile: export PATH=\"$NPM_BIN:\$PATH\""
      export PATH="$NPM_BIN:$PATH"
    fi
  fi

  # Pair if grant provided
  if [ -n "$PAIR_GRANT" ]; then
    echo ""
    log_info "Pairing with vault..."
    dcp-agent pair "$PAIR_GRANT"
    log_success "Agent paired successfully"
  fi

  echo ""
  echo "╔══════════════════════════════════════════╗"
  echo "║       Installation Complete!             ║"
  echo "╚══════════════════════════════════════════╝"
  echo ""

  if [ -z "$PAIR_GRANT" ]; then
    echo "Next steps:"
    echo "  1. Get a pairing grant from your DCP vault (Desktop app or CLI)"
    echo "  2. Run: dcp-agent pair <your-grant-token>"
    echo "  3. Configure OpenClaw to use DCP secrets provider"
    echo ""
    echo "OpenClaw config (openclaw.json5):"
    echo '  {'
    echo '    secrets: {'
    echo '      providers: {'
    echo '        dcp: {'
    echo '          source: "exec",'
    echo '          command: "dcp-agent",'
    echo '          args: ["secrets"]'
    echo '        }'
    echo '      }'
    echo '    }'
    echo '  }'
  else
    echo "Your agent is ready!"
    echo ""
    echo "Check status: dcp-agent status"
    echo ""
    echo "OpenClaw config (openclaw.json5):"
    echo '  {'
    echo '    secrets: {'
    echo '      providers: {'
    echo '        dcp: {'
    echo '          source: "exec",'
    echo '          command: "dcp-agent",'
    echo '          args: ["secrets"]'
    echo '        }'
    echo '      }'
    echo '    },'
    echo '    providers: {'
    echo '      openai: {'
    echo '        apiKey: { "$ref": "dcp:credentials.api.openai" }'
    echo '      }'
    echo '    }'
    echo '  }'
  fi
  echo ""
}

main
