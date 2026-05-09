# Release Process

This repo is a multi-package workspace. Releases are coordinated across packages.

## Pre-release Checklist

- `pnpm test` passes for all workspaces
- README and examples reflect current CLI/package names
- Version numbers updated in each package

## Package Names

- `@dcprotocol/core`
- `@dcprotocol/client`
- `@dcprotocol/vault`
- `@dcprotocol/agent`
- `@dcprotocol/relay`
- `@dcprotocol/relay-client`
- `@dcprotocol/telegram`

## Publish (manual)

1. Build all packages:
   ```bash
   pnpm run build
   ```
2. Publish from each package directory:
   ```bash
   cd packages/dcp-core && npm publish --access public
   cd ../dcp-client && npm publish --access public
   cd ../dcp-vault && npm publish --access public
   cd ../dcp-agent && npm publish --access public
   cd ../dcp-relay && npm publish --access public
   cd ../dcp-relay-client && npm publish --access public
   cd ../dcp-telegram && npm publish --access public
   ```

## Post-release

- Update changelog (if used)
- Tag the release in Git
