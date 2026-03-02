#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

info() { printf "\n==> %s\n" "$1"; }

info "1) Install deps (root)"
cd "$ROOT_DIR"
npm install

info "2) Build packages"
npm run build

info "3) Initialize vault"
./packages/dcp-cli/dist/cli.js init || true

info "4) Create Solana wallet"
./packages/dcp-cli/dist/cli.js create-wallet --chain solana || true

info "5) Add sample data"
./packages/dcp-cli/dist/cli.js add address.home || true
./packages/dcp-cli/dist/cli.js add preferences.sizes || true

info "6) Start REST server (localhost:8420)"
node ./packages/dcp-server/dist/index.js &
SERVER_PID=$!

sleep 2

info "7) Run read-personal-data example"
cd "$ROOT_DIR/examples/read-personal-data"
npm install
node index.js || true

info "8) Run sign-solana-tx example"
cd "$ROOT_DIR/examples/sign-solana-tx"
npm install
node index.js || true

info "9) Stop server"
kill "$SERVER_PID"

info "Done"
