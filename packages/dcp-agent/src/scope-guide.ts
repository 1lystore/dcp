export const CANONICAL_SCOPE_GUIDE = `Use these DCP scopes exactly. Do not invent aliases.

Common identity scopes:
- User name, full name, display name, legal name: identity.name
- Email address: identity.email
- Phone number: identity.phone
- Home address as identity data: identity.home_address

Common address scopes:
- Home address record: address.home
- Work address record: address.work
- Shipping address record: address.shipping

Common API credential scopes:
- OpenAI API key: credentials.api.openai
- Anthropic API key: credentials.api.anthropic
- Stripe API key: credentials.api.stripe
- GitHub token: credentials.api.github

Rules:
- Never use username, user.name, profile.name, displayName, legalName, legal_name, contact.email, user.email, or email.
- For "what is my name", always read identity.name.
- For "what is my email", always read identity.email.
- If the user asks for a value not listed here, ask the user for the exact DCP scope instead of guessing.`;

export const VAULT_READ_DESCRIPTION = `Read data from the user's vault. Only use when the user explicitly asks you to read their info. Requires user consent.

${CANONICAL_SCOPE_GUIDE}

Supported scope families:
- identity.*
- address.*
- credentials.api.*`;

export const VAULT_WRITE_DESCRIPTION = `Store data in the user's vault. Only use when the user explicitly asks you to save/store something. Requires user consent.

${CANONICAL_SCOPE_GUIDE}

Example write:
- scope: credentials.api.openai
- data: {"key": "sk-xxx", "label": "OpenAI API key"}`;

export const SCOPE_PROPERTY_DESCRIPTION =
  'Exact DCP scope. Use identity.name for name and identity.email for email. Do not guess aliases such as username, displayName, legalName, user.email, or profile.name.';

export const VAULT_GET_ADDRESS_DESCRIPTION = `Get the user's public wallet address from DCP.

Use this when the user asks for their wallet address, public address, Solana address, or when you need a source address before building a Solana transaction.

Rules:
- chain must be solana.
- This returns a public address only. It does not sign or send anything.
- No user approval is required.`;

export const VAULT_BUDGET_CHECK_DESCRIPTION = `Check whether a proposed Solana transaction is within the user's DCP budget policy.

Use this before asking DCP to sign a transaction when you know the amount. It returns whether the amount is allowed, remaining limits, and whether manual approval is required.

Rules:
- currency should be SOL, USDC, USDT, or 1LY.
- chain should be solana when provided.
- This does not sign or send anything.
- No user approval is required.`;

export const VAULT_SCOPE_GUIDE_DESCRIPTION = `Return the canonical DCP scope names.

Use this before vault_read or vault_write if you are not completely sure which scope to use.

Rules:
- For the user's name, use identity.name.
- For the user's email, use identity.email.
- Do not guess aliases like username, displayName, legalName, user.email, or profile.name.
- No user approval is required.`;

export const VAULT_SIGN_TX_DESCRIPTION = `Sign an unsigned Solana transaction using the user's DCP vault wallet.

Use this only when the user asks you to sign, approve, pay, transfer, swap, mint, stake, or otherwise authorize a Solana transaction. The private key never leaves the vault.

Rules:
- chain must be solana.
- unsigned_tx must be the unsigned Solana transaction encoded as base64.
- For 1LY transfers, use SPL token mint Aih3sbAbu39Yn7jB2Qf4btZ5eWtDGQJH2gMfC4qdBAGS.
- Include amount, currency, destination, and a clear description whenever available so DCP can show a useful approval request and enforce budgets.
- This signs only. It does not broadcast/send the transaction unless your client does that separately.
- Manual approval is required when the amount is above the user's approval threshold.`;

export const VAULT_SIGN_MESSAGE_DESCRIPTION = `Sign a message using the user's DCP vault wallet.

Use this when the user asks to sign a login challenge, nonce, authentication message, or other Solana wallet message. The private key never leaves the vault.

Rules:
- chain must be solana.
- message is the exact message to sign.
- encoding is utf8 unless the message is already base64.
- Include a clear description when available.
- User approval is required.`;
