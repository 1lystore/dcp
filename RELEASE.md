# Release Process

This repo is a multi-package workspace. Releases are coordinated across packages.

## Pre-release Checklist

- `npm test` passes for all workspaces
- README and examples reflect current CLI/package names
- Version numbers updated in each package

## Package Names

- `@dcprotocol/core`
- `@dcprotocol/cli`
- `@dcprotocol/mcp`
- `@dcprotocol/server`

## Publish (manual)

1. Build all packages:
   ```bash
   npm run build
   ```
2. Publish from each package directory:
   ```bash
   cd packages/dcp-core && npm publish --access public
   cd ../dcp-cli && npm publish --access public
   cd ../dcp-mcp && npm publish --access public
   cd ../dcp-server && npm publish --access public
   ```

## Post-release

- Update changelog (if used)
- Tag the release in Git

