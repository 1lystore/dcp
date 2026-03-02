/**
 * Example: Read Personal Data from DCP Vault
 *
 * This example demonstrates how an AI agent can request personal data
 * via the DCP Vault REST API with user consent.
 *
 * Prerequisites:
 * 1. Initialize vault: `dcp init`
 * 2. Add some personal data: `dcp add address.home`
 * 3. Start vault server: `npx @dcprotocol/server`
 * 4. Unlock vault via `dcp init` / passphrase before making requests
 *
 * Flow:
 * 1. Agent requests data from a specific scope
 * 2. If no session exists, user must approve via CLI or REST
 * 3. Once approved, vault decrypts and returns the data
 * 4. Optionally, user can grant a session for future requests
 */

const VAULT_URL = 'http://127.0.0.1:8420';
const AGENT_NAME = 'personal-data-example';

/**
 * List available scopes in the vault
 */
async function listScopes() {
  const response = await fetch(`${VAULT_URL}/scopes`);
  if (!response.ok) {
    throw new Error(`Failed to list scopes: ${response.statusText}`);
  }
  return (await response.json()).scopes;
}

/**
 * Read data from a specific scope
 */
async function readData(scope, sessionId = null) {
  const body = {
    scope,
    agent_name: AGENT_NAME,
    description: `Reading ${scope} for demonstration`,
  };

  if (sessionId) {
    body.session_id = sessionId;
  }

  const response = await fetch(`${VAULT_URL}/v1/vault/read`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const data = await response.json();

  if (!response.ok) {
    if (data.error?.code === 'VAULT_LOCKED') {
      throw new Error('Vault is locked. Run `dcp init` and enter your passphrase.');
    }
    throw new Error(`Read failed: ${data.error?.message || response.statusText}`);
  }

  return data;
}

/**
 * Poll for consent approval
 */
async function waitForConsent(consentId, timeoutMs = 120000) {
  console.log(`\nWaiting for consent approval...`);
  console.log(`Approve with: curl -X POST ${VAULT_URL}/consent/${consentId}/approve -H "Content-Type: application/json"`);
  console.log(`Or approve with session: curl -X POST ${VAULT_URL}/consent/${consentId}/approve -H "Content-Type: application/json" -d '{"session":true}'`);
  console.log(`Or use CLI: dcp approve ${consentId}\n`);

  const startTime = Date.now();
  const pollInterval = 2000;

  while (Date.now() - startTime < timeoutMs) {
    const response = await fetch(`${VAULT_URL}/consent`);
    const data = await response.json();

    const consent = data.pending?.find((c) => c.id === consentId);

    if (!consent) {
      // Consent no longer pending - either approved or denied
      return true;
    }

    await new Promise((resolve) => setTimeout(resolve, pollInterval));
  }

  throw new Error('Consent timed out');
}

/**
 * List active sessions
 */
async function listSessions() {
  const response = await fetch(`${VAULT_URL}/agents`);
  if (!response.ok) {
    throw new Error(`Failed to list sessions: ${response.statusText}`);
  }
  return (await response.json()).agents;
}

/**
 * Main example flow
 */
async function main() {
  console.log('=== DCP Vault: Read Personal Data Example ===\n');

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

  // Step 2: List available scopes
  console.log('\n2. Listing available scopes...');
  const scopes = await listScopes();
  if (scopes.length === 0) {
    console.log('   No data in vault yet.');
    console.log('   Add some data: dcp add address.home');
    process.exit(0);
  }

  console.log('   Available scopes:');
  for (const s of scopes) {
    const typeIcon = s.type === 'WALLET_KEY' ? '🔐' : '📄';
    console.log(`   ${typeIcon} ${s.scope} (${s.sensitivity})`);
  }

  // Step 3: Find a readable scope (not wallet, not critical)
  const readableScope = scopes.find(
    (s) => s.type === 'PERSONAL_DATA' && s.sensitivity !== 'critical'
  );

  if (!readableScope) {
    console.log('\n   No readable personal data found.');
    console.log('   Add non-critical data: dcp add preferences.sizes');
    process.exit(0);
  }

  // Step 4: Request data read
  console.log(`\n3. Requesting to read: ${readableScope.scope}...`);
  let readResult = await readData(readableScope.scope);

  // Handle consent flow if needed
  if (readResult.requires_consent) {
    console.log(`   Consent required (ID: ${readResult.consent_id})`);
    await waitForConsent(readResult.consent_id);

    // Retry after consent
    console.log('\n4. Retrying read after consent...');
    readResult = await readData(readableScope.scope);

    if (readResult.requires_consent) {
      console.error('   Still requires consent. Was it approved?');
      process.exit(1);
    }
  }

  // Step 5: Display the data
  console.log(`\n5. Data retrieved successfully!`);
  console.log(`   Scope: ${readResult.scope}`);
  console.log('   Data:');
  console.log(JSON.stringify(readResult.data, null, 4));

  // Step 6: Check for active sessions
  console.log('\n6. Checking for active sessions...');
  const sessions = await listSessions();
  const mySession = sessions.find((s) => s.agent_name === AGENT_NAME);

  if (mySession) {
    console.log(`   Found session: ${mySession.id}`);
    console.log(`   Granted scopes: ${mySession.granted_scopes.join(', ')}`);
    console.log(`   Expires: ${new Date(mySession.expires_at).toLocaleString()}`);
    console.log('\n   With a session, future reads won\'t need consent approval!');
  } else {
    console.log('   No active session found.');
    console.log('   Tip: Approve consent with session=true to skip future consent prompts:');
    console.log(`   curl -X POST ${VAULT_URL}/consent/<id>/approve -d '{"session":true}'`);
  }

  console.log('\n=== Example Complete ===');
}

main().catch((error) => {
  console.error('Error:', error.message);
  process.exit(1);
});
