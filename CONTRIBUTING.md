# Contributing to DCP

DCP is an open protocol. The more people build on it, the stronger it gets. Whether you're fixing a typo, adding a new chain, or improving agent integrations, this guide should help you get started.

## Where to Start

Not sure where to jump in? Here are the highest-impact contributions right now:

| Contribution | Difficulty | Impact |
|-------------|-----------|--------|
| Fix a bug or improve error messages | Easy | High |
| Add an example or integration guide | Easy | High |
| New data schema (driver's license, health profile) | Medium | High |
| New EVM chain support (Polygon, Arbitrum, etc.) | Medium | High |
| LangChain / CrewAI / AutoGen integration | Medium | High |
| Improve test coverage | Easy | Medium |

Items marked **[help wanted]** in the [Roadmap](./ROADMAP.md) are specifically waiting for contributors.

## Setting Up

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/dcp.git
cd dcp

# Install dependencies
pnpm install

# Build all packages
pnpm run build

# Run tests (make sure everything passes before you start)
pnpm test

# Try it out
dcp init
dcp create-wallet --chain solana
```

### Project Structure

```
packages/
  dcp-core/       Core library (crypto, wallet, storage, budget)
  dcp-vault/      CLI and local REST API server
  dcp-agent/      Agent runtime for MCP, HTTP MCP, and local proxy mode
  dcp-relay/      Encrypted relay service
```

CLI binary is `dcp`. Packages are scoped under `@dcprotocol/*`. Data lives in `~/.dcp`.

## What We Accept

**Yes, send it:**
- Bug fixes and security patches
- New blockchain support (see "Adding a Chain" below)
- New data schemas (driver's license, health records, travel documents)
- MCP tool additions following existing patterns
- Framework integrations (LangChain, CrewAI, AutoGen, OpenAI functions)
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
1. Choose a scope name (document it in protocol spec/README)
2. Add examples to `README.md`
3. Add tests for encryption round‑trip

Formal schema registry and validation is on the roadmap.

## Adding Your Service to Known Services Registry

If you're building a service or platform that integrates with DCP (like Virtuals, Eliza, 1ly), you can add yourself to the **Known Services Registry** so users see your service as "verified" in DCP Desktop and CLI.

### Quick Process

1. **Edit the registry file:**
   ```bash
   # File: packages/dcp-core/src/services.ts
   ```

2. **Add your service to `KNOWN_SERVICES` object:**
   ```typescript
   export const KNOWN_SERVICES: Record<string, KnownService> = {
     '1ly': { ... },
     'virtuals': { ... },

     // Add your service:
     'your-service-id': {
       service_id: 'your-service-id',
       name: 'Your Service Name',
       connect_url: 'https://yourservice.com/api/dcp/connect',
       auth_url: 'https://yourservice.com/settings/dcp',
       public_key: 'ed25519:<your-base64-public-key>',
       default_scopes: [
         'sign:solana',
         'sign:base',
         'read:credentials.api.your-service'
       ],
       verified: true,
       description: 'Brief description of your service',
       icon_url: 'https://yourservice.com/favicon.ico'
     }
   };
   ```

3. **What you need to provide:**
   - **Service ID**: Unique identifier (lowercase, no spaces)
   - **Public Key**: Your Ed25519 public key (for signing relay requests)
   - **Connect URL**: Your API endpoint that receives vault routing info
   - **Auth URL**: Where users log into your service
   - **Default Scopes**: Permissions your service typically needs
   - **Icon**: Your service logo/favicon (optional)

4. **Requirements for verification:**
   - ✅ Service must implement `/api/dcp/connect` endpoint
   - ✅ Service must handle vault routing info: `{ vault_id, hpke_public_key, relay_url, scopes_granted }`
   - ✅ Service must sign relay requests with Ed25519 private key
   - ✅ Service must respect granted scopes and budgets
   - ✅ Documentation showing how users connect their DCP wallet

5. **Submit PR with:**
   - Your service added to `KNOWN_SERVICES`
   - Brief description in PR of what your service does
   - Link to your DCP integration docs
   - Test showing your connect endpoint works

### Example PR Title
```
feat: add YourService to known services registry
```

### What This Gives Users
When you're in the registry:
- Users can run: `dcp trust your-service-id` (auto-fills everything)
- Users see "✓ Verified" badge in DCP Desktop
- Your icon shows up in the UI
- Connect flow is one command instead of manual setup

### Integration Help
Not sure how to implement the DCP connect endpoint? Check:
- Example: `packages/dcp-vault/` (reference implementation)
- Programmatic client: `@dcprotocol/client` (for backend experiments)
- Docs: `README.md` section on "Service / Marketplace Flow"

Questions? Open a discussion or issue - we'll help you integrate!

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
