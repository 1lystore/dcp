/**
 * Example: Sign a Solana Transaction with DCP Vault
 *
 * This example demonstrates how an AI agent can request transaction signing
 * via the DCP Vault REST API without ever having access to the private key.
 *
 * Prerequisites:
 * 1. Initialize vault: `dcp init`
 * 2. Create Solana wallet: `dcp create-wallet --chain solana`
 * 3. Start vault server: `npx @dcprotocol/server` (or run from packages/dcp-server)
 * 4. Unlock vault via CLI before making requests
 *
 * Flow:
 * 1. Agent builds an unsigned transaction
 * 2. Agent calls POST /v1/vault/sign with the unsigned tx
 * 3. If no session exists, user must approve via CLI or REST
 * 4. Vault signs and returns the signed transaction
 * 5. Agent broadcasts the signed transaction
 */

import { Connection, PublicKey, SystemProgram, Transaction } from '@solana/web3.js';

const VAULT_URL = 'http://127.0.0.1:8420';
const AGENT_NAME = 'solana-tx-example';

// Solana devnet connection
const connection = new Connection('https://api.devnet.solana.com', 'confirmed');

/**
 * Get the wallet address from the vault
 */
async function getWalletAddress() {
  const response = await fetch(`${VAULT_URL}/address/solana`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Failed to get address: ${error.error?.message || response.statusText}`);
  }
  const data = await response.json();
  return new PublicKey(data.address);
}

/**
 * Build an unsigned transfer transaction
 */
async function buildTransferTransaction(fromPubkey, toPubkey, lamports) {
  const transaction = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey,
      toPubkey,
      lamports,
    })
  );

  // Get recent blockhash
  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash();
  transaction.recentBlockhash = blockhash;
  transaction.lastValidBlockHeight = lastValidBlockHeight;
  transaction.feePayer = fromPubkey;

  return transaction;
}

/**
 * Sign transaction via DCP Vault
 */
async function signWithVault(unsignedTx, amount, sessionId = null) {
  // Serialize the unsigned transaction to base64
  const serialized = unsignedTx.serialize({
    requireAllSignatures: false,
    verifySignatures: false,
  });
  const base64Tx = Buffer.from(serialized).toString('base64');

  const body = {
    chain: 'solana',
    unsigned_tx: base64Tx,
    amount: amount / 1e9, // Convert lamports to SOL
    currency: 'SOL',
    agent_name: AGENT_NAME,
    description: 'Solana transfer transaction',
  };

  if (sessionId) {
    body.session_id = sessionId;
  }

  const response = await fetch(`${VAULT_URL}/v1/vault/sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const data = await response.json();

  if (!response.ok) {
    if (data.error?.code === 'VAULT_LOCKED') {
      throw new Error('Vault is locked. Run `dcp init` and enter your passphrase.');
    }
    throw new Error(`Sign failed: ${data.error?.message || response.statusText}`);
  }

  return data;
}

/**
 * Poll for consent approval
 */
async function waitForConsent(consentId, timeoutMs = 120000) {
  console.log(`\nWaiting for consent approval...`);
  console.log(`Approve with: curl -X POST ${VAULT_URL}/consent/${consentId}/approve -H "Content-Type: application/json"`);
  console.log(`Or use CLI: dcp approve ${consentId}\n`);

  const startTime = Date.now();
  const pollInterval = 2000;

  while (Date.now() - startTime < timeoutMs) {
    const response = await fetch(`${VAULT_URL}/consent`);
    const data = await response.json();

    const consent = data.pending?.find((c) => c.id === consentId);

    if (!consent) {
      // Consent no longer pending - either approved or denied
      // Try signing again with the same request
      return true;
    }

    await new Promise((resolve) => setTimeout(resolve, pollInterval));
  }

  throw new Error('Consent timed out');
}

/**
 * Main example flow
 */
async function main() {
  console.log('=== DCP Vault: Sign Solana Transaction Example ===\n');

  // Step 1: Check vault health
  console.log('1. Checking vault health...');
  try {
    const health = await fetch(`${VAULT_URL}/health`);
    const healthData = await health.json();
    console.log(`   Status: ${healthData.status}`);
    console.log(`   Unlocked: ${healthData.unlocked}`);

    if (!healthData.unlocked) {
      console.error('\n   ERROR: Vault is locked. Please unlock first:');
      console.error('   Run: dcp init');
      process.exit(1);
    }
  } catch (error) {
    console.error('\n   ERROR: Cannot connect to vault server.');
    console.error('   Make sure the server is running: npx @dcprotocol/server');
    process.exit(1);
  }

  // Step 2: Get wallet address
  console.log('\n2. Getting wallet address from vault...');
  let fromPubkey;
  try {
    fromPubkey = await getWalletAddress();
    console.log(`   Address: ${fromPubkey.toBase58()}`);
  } catch (error) {
    console.error(`\n   ERROR: ${error.message}`);
    console.error('   Create a wallet first: dcp create-wallet --chain solana');
    process.exit(1);
  }

  // Step 3: Build unsigned transaction (send 0.001 SOL to self as demo)
  console.log('\n3. Building unsigned transfer transaction...');
  const lamports = 1_000_000; // 0.001 SOL
  const toPubkey = fromPubkey; // Send to self for demo
  const unsignedTx = await buildTransferTransaction(fromPubkey, toPubkey, lamports);
  console.log(`   Amount: ${lamports / 1e9} SOL`);
  console.log(`   To: ${toPubkey.toBase58()}`);

  // Step 4: Request signature from vault
  console.log('\n4. Requesting signature from vault...');
  let signResult = await signWithVault(unsignedTx, lamports);

  // Handle consent flow if needed
  if (signResult.requires_consent) {
    console.log(`   Consent required (ID: ${signResult.consent_id})`);
    await waitForConsent(signResult.consent_id);

    // Retry after consent
    console.log('\n5. Retrying signature after consent...');
    signResult = await signWithVault(unsignedTx, lamports);

    if (signResult.requires_consent) {
      console.error('   Still requires consent. Was it approved?');
      process.exit(1);
    }
  }

  console.log(`   Signed! Signature: ${signResult.signature?.slice(0, 20)}...`);
  console.log(`   Remaining daily budget: ${signResult.remaining_daily} SOL`);

  // Step 5: The signed transaction can now be broadcast
  console.log('\n6. Ready to broadcast!');
  console.log('   The signed transaction is in signResult.signed_tx');
  console.log('   In production, you would call:');
  console.log('   connection.sendRawTransaction(Buffer.from(signResult.signed_tx, "base64"))');

  // Uncomment to actually broadcast (requires funded wallet):
  // const signature = await connection.sendRawTransaction(
  //   Buffer.from(signResult.signed_tx, 'base64')
  // );
  // console.log(`   Broadcast! Signature: ${signature}`);

  console.log('\n=== Example Complete ===');
}

main().catch((error) => {
  console.error('Error:', error.message);
  process.exit(1);
});
