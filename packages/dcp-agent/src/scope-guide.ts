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

export const VAULT_GET_BALANCES_DESCRIPTION = `Read the user's Solana wallet balances (SOL and SPL tokens such as USDC).

Use this when the user asks how much SOL/USDC/token they have, or when you need to know the balance before building a transfer, swap, or payment.

Rules:
- Returns balances for the user's own DCP wallet address. You do not pass an address.
- This is a read-only public lookup. It does not sign or send anything.
- No user approval is required.`;

export const VAULT_GET_TX_STATUS_DESCRIPTION = `Check the on-chain status of a Solana transaction by its signature.

Use this after you submit a transaction (for example one signed via vault_sign_tx) to see whether it is processed, confirmed, finalized, failed, or not found.

Rules:
- signature is the base58 Solana transaction signature.
- This is a read-only public lookup. It does not sign or send anything.
- No user approval is required.`;

export const VAULT_GET_TX_HISTORY_DESCRIPTION = `List recent transaction signatures for the user's Solana wallet.

Use this when the user asks about their recent activity or history. Returns signatures with light metadata (slot, time, status) and explorer links — not full transaction contents.

Rules:
- Returns activity for the user's own DCP wallet address. You do not pass an address.
- limit is optional (default 20, maximum 50). Use before with a signature to paginate older activity.
- This is a read-only public lookup. It does not sign or send anything.
- No user approval is required.`;

export const VAULT_SEARCH_TOKENS_DESCRIPTION = `Search the Solana (Jupiter) token list by symbol, name, or mint.

Use this to resolve a token the user names (for example "BONK") to its mint address and decimals before a swap or transfer.

Rules:
- query is the symbol, name, or mint to search for.
- limit is optional (default 10, maximum 20).
- This is a read-only public lookup. It does not sign or send anything.
- No user approval is required.`;

export const VAULT_TRANSFER_DESCRIPTION = `Send SOL or an SPL token (e.g. USDC) from the user's DCP wallet to a recipient. DCP builds the transfer, signs it in the vault (private key never leaves the device), submits it to Solana, and confirms it.

Use this when the user asks to send, pay, or transfer funds to an address. Prefer this over manually building a transaction and using vault_sign_tx.

Rules:
- chain must be solana. to is the recipient's Solana address. amount is the human amount (for example 0.05 SOL, or 1.5 USDC).
- currency is SOL for native, or a token symbol like USDC. For an arbitrary SPL token, pass mint and decimals as well.
- Sending a token to a recipient who has never held it works automatically — DCP creates their token account (the user pays the small one-time rent).
- The user pays the network fee from their own wallet.
- Manual approval is required when the amount is above the user's approval threshold; budget limits are enforced.
- Provide a stable idempotency_key for the intended transfer to avoid accidental double-sends.
- Returns the transaction signature and a confirmation status. If confirmation times out the status is "submitted"; poll vault_get_tx_status with the signature.`;

export const VAULT_SWAP_DESCRIPTION = `Swap one Solana token for another from the user's DCP wallet, via Jupiter. DCP gets the quote, builds the swap, signs it in the vault (key never leaves the device), submits it, and confirms it.

Use this when the user asks to swap, convert, or exchange tokens (for example "swap 1 SOL to USDC").

Rules:
- chain must be solana. from_token and to_token are 'SOL', a known symbol like 'USDC', or a mint address (with from_decimals/to_decimals for arbitrary mints).
- amount is the amount of the input (from_token) to swap.
- slippage_bps is optional (default 50 = 0.5%).
- Budget and consent are enforced on the input amount; the user pays the network fee.
- Provide a stable idempotency_key to avoid accidental double-swaps.
- Returns the signature, confirmation status, and the estimated output amount.`;

export const VAULT_SIGN_MESSAGE_DESCRIPTION = `Sign a message using the user's DCP vault wallet.

Use this when the user asks to sign a login challenge, nonce, authentication message, or other Solana wallet message. The private key never leaves the vault.

Rules:
- chain must be solana.
- message is the exact message to sign.
- encoding is utf8 unless the message is already base64.
- Include a clear description when available.
- User approval is required.`;

export const VAULT_SIGN_X402_DESCRIPTION = `Sign a Solana x402 payment payload using the user's DCP vault wallet.

Use this when the user asks to pay an x402-protected API, authorize an x402 payment, or sign a pay.sh/x402 payment payload.

Rules:
- network must be solana.
- payload must be the exact x402 payment payload encoded as base64. Do not rewrite or reformat it.
- Include amount, currency, recipient, and purpose whenever available so DCP can show a useful approval request and enforce budgets.
- For 1LY payments, use currency 1LY.
- This signs only. It does not submit or settle the payment unless your client does that separately.
- Manual approval is required when the amount is above the user's approval threshold.`;
