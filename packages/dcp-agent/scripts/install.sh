#!/usr/bin/env bash
set -euo pipefail

DCP_NODE_VERSION="${DCP_NODE_VERSION:-22.22.2}"
DCP_ROOT="${DCP_ROOT:-/opt/dcp}"
DCP_NODE_DIR="$DCP_ROOT/node-v$DCP_NODE_VERSION"
DCP_NODE_BIN="$DCP_NODE_DIR/bin"
DCP_NPM="$DCP_NODE_BIN/npm"

service_npm_command() {
  local node_bin="$1"
  local npm_bin="$2"
  local bin_dir
  bin_dir="$(dirname "$node_bin")"
  echo "/usr/bin/env PATH=$bin_dir:$PATH $node_bin $npm_bin --loglevel=error"
}

usage() {
  echo "Usage:"
  echo "  curl -fsSL https://dcpagent.com/install.sh | sudo bash -s -- 'dcp_vps_v1_...'"
}

die() {
  echo "Error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

as_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "Run with sudo. Example: curl -fsSL https://dcpagent.com/install.sh | sudo bash -s -- 'dcp_vps_v1_...'"
  fi
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "Unsupported CPU architecture: $(uname -m)" ;;
  esac
}

has_node_22() {
  command -v node >/dev/null 2>&1 || return 1
  local major
  major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || true)"
  [ "$major" = "22" ]
}

install_private_node() {
  if [ -x "$DCP_NPM" ]; then
    return 0
  fi

  need_cmd curl
  need_cmd tar

  local arch tarball url tmp
  arch="$(detect_arch)"
  tarball="node-v$DCP_NODE_VERSION-linux-$arch.tar.xz"
  url="https://nodejs.org/dist/v$DCP_NODE_VERSION/$tarball"
  tmp="$(mktemp -d)"

  echo "Installing DCP runtime..."
  mkdir -p "$DCP_ROOT"
  curl -fsSL "$url" -o "$tmp/$tarball"
  tar -xJf "$tmp/$tarball" -C "$tmp"
  rm -rf "$DCP_NODE_DIR"
  mv "$tmp/node-v$DCP_NODE_VERSION-linux-$arch" "$DCP_NODE_DIR"
  rm -rf "$tmp"
}

stop_existing_service() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files dcp-agent.service >/dev/null 2>&1; then
    echo "Stopping existing DCP agent service..."
    systemctl stop dcp-agent >/dev/null 2>&1 || true
  fi
}

main() {
  as_root

  local invite="${1:-}"
  if [ "$invite" = "--pair" ]; then
    invite="${2:-}"
  fi

  if [ -z "$invite" ]; then
    usage
    exit 1
  fi

  if [[ "$invite" != dcp_vps_v1_* ]]; then
    die "Invalid DCP VPS invite. It must start with dcp_vps_v1_"
  fi

  stop_existing_service

  if has_node_22 && command -v npm >/dev/null 2>&1; then
    echo "Using system Node $(node -v) for install."
    local node_bin npm_bin
    node_bin="$(command -v node)"
    npm_bin="$(command -v npm)"
    PATH="$(dirname "$node_bin"):$PATH" DCP_SERVICE_NPM="$(service_npm_command "$node_bin" "$npm_bin")" "$node_bin" "$npm_bin" --loglevel=error exec --yes --package @dcprotocol/agent@latest -- dcp-agent install-service "$invite"
  else
    install_private_node
    echo "Using DCP runtime $("$DCP_NODE_BIN/node" -v) for install."
    PATH="$DCP_NODE_BIN:$PATH" DCP_SERVICE_NPM="$(service_npm_command "$DCP_NODE_BIN/node" "$DCP_NPM")" "$DCP_NODE_BIN/node" "$DCP_NPM" --loglevel=error exec --yes --package @dcprotocol/agent@latest -- dcp-agent install-service "$invite"
  fi
}

main "$@"
