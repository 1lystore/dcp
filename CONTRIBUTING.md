# Contributing to DCP

DCP is an open protocol. The more people build on it, the stronger it gets. Whether you're fixing a typo, adding a new chain, or building a Python SDK — we're glad you're here.

## Where to Start

Not sure where to jump in? Here are the highest-impact contributions right now:

| Contribution | Difficulty | Impact |
|-------------|-----------|--------|
| Fix a bug or improve error messages | Easy | High |
| Add an example or integration guide | Easy | High |
| New data schema (driver's license, health profile) | Medium | High |
| New EVM chain support (Polygon, Arbitrum, etc.) | Medium | High |
| Python SDK | Medium | Very High |
| LangChain / CrewAI / AutoGen integration | Medium | High |
| Improve test coverage | Easy | Medium |

Items marked **[help wanted]** in the [Roadmap](./ROADMAP.md) are specifically waiting for contributors.

## Setting Up

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/dcp.git
cd dcp

# Install dependencies
npm install

# Build all packages
npm run build

# Run tests (make sure everything passes before you start)
npm test

# Try it out
dcp init
dcp create-wallet --chain solana
```

### Project Structure

```
packages/
  dcp-core/       Core library (crypto, wallet, storage, budget)
  dcp-cli/        CLI tool (commands in src/commands/)
  dcp-mcp/        MCP server for AI agents
  dcp-server/     REST API server (Fastify, localhost:8420)
```

CLI binary is `dcp`. Packages are scoped under `@dcprotocol/*`. Data lives in `~/.dcp`.

## What We Accept

**Yes, send it:**
- Bug fixes and security patches
- New blockchain support (see "Adding a Chain" below)
- New data schemas (driver's license, health records, travel documents)
- MCP tool additions following existing patterns
- Framework integrations (LangChain, CrewAI, AutoGen, OpenAI functions)
- Python SDK, Go SDK, Rust SDK — any language
- Documentation improvements, examples, tutorials
- Test coverage improvements
- Performance optimizations
- Better error messages and developer experience

**Open an issue first:**
- New vault item types or operations
- Changes to encryption or key management
- Changes to the consent or approval flow
- New trust source implementations
- Changes to budget engine logic
- Anything that touches the core security model

**We will not accept:**
- Anything that weakens the security model
- Dependencies on paid services in the core
- Features that require Docker or an external database server
- Raw key export operations (this will never exist)
- Bypassing consent or budget enforcement
- Breaking changes to the CLI or MCP tool interface without migration path

## Adding a New Chain

EVM chains are easiest because they reuse secp256k1 signing. Current chain logic lives in:
- `packages/dcp-core/src/wallet.ts`
- `packages/dcp-core/src/types.ts`
- `packages/dcp-core/src/budget.ts` (defaults)

Suggested steps:
1. Add chain identifier in `types.ts`
2. Update wallet creation/signing in `wallet.ts`
3. Add default budgets in `budget.ts`
4. Add tests in `packages/dcp-core/tests/`
5. Update the Supported Chains table in `README.md`

If the chain is non‑EVM (Bitcoin, Cosmos, Tron), open an issue first to discuss key derivation and signing specifics.

## Adding a New Data Schema

Phase 1 stores JSON payloads by scope (e.g., `address.home`, `preferences.sizes`).
There is no formal schema registry yet.

To add a new data type:
1. Choose a scope name (document it in PRD/README)
2. Add examples to `README.md`
3. Add tests for encryption round‑trip

Formal schema registry and validation is on the roadmap.

## Pull Requests

Keep PRs focused. One feature or fix per PR. Include:

- **What** — clear description of the change
- **Why** — what problem does this solve
- **Tests** — for new behavior
- **Docs** — update if behavior changes

We review PRs within a few days. If it's been a week with no response, ping us.

### Commit Messages

No strict format. Just be clear:

```
Good:  "add Polygon chain support"
Good:  "fix budget check failing on zero-amount transactions"
Good:  "improve error message for expired sessions"
Bad:   "fix stuff"
Bad:   "update"
```

## Testing

```bash
# Run all tests
npm test

# Run tests for a specific package
npm test --workspace=packages/dcp-core

# Run a specific test file
npx vitest run packages/dcp-core/tests/crypto.test.ts
```

Write tests for:
- Any new chain (wallet creation, signing, address derivation)
- Any new schema (validation, encryption roundtrip)
- Any budget or consent logic changes
- Any new CLI command or MCP tool

## Security Issues

**Do not open public issues for security vulnerabilities.**

Email `support@1ly.store` with:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment

We will acknowledge within 48 hours and work with you on a fix. Security researchers will be credited in the release notes (unless you prefer to remain anonymous).

## Code of Conduct

Be respectful. Give constructive feedback. Assume good intent. We're all here to make agents safer for everyone.


## Questions?

Open a [GitHub Discussion](https://github.com/1lystore/dcp/discussions) or file an issue. No question is too basic — we’re happy to help.