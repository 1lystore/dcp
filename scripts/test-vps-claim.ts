#!/usr/bin/env npx tsx
/**
 * Test VPS Pairing Claim Submission (macOS)
 *
 * This script tests the VPS pairing flow without installing systemd service.
 * Usage: npx tsx scripts/test-vps-claim.ts 'dcp_vps_v1_...'
 */

import * as os from 'node:os';
import {
  generateAgentKeypair,
  generateVerificationPhrase,
  parsePairingInvite,
  createPairingClaim,
  submitPairingClaim,
  waitForPairingApproval,
} from '../packages/dcp-agent/src/pairing.js';

const inviteToken = process.argv[2];
if (!inviteToken) {
  console.error('Usage: npx tsx scripts/test-vps-claim.ts <dcp_vps_v1_...>');
  process.exit(1);
}

if (!inviteToken.startsWith('dcp_vps_v1_')) {
  console.error('Error: Invalid invite format. Must start with dcp_vps_v1_');
  process.exit(1);
}

async function main() {
  console.log('\n=== Testing VPS Pairing Claim ===\n');

  // 1. Parse invite
  console.log('1. Parsing invite...');
  const inviteData = parsePairingInvite(inviteToken);
  console.log('   Vault ID:', inviteData.vault_id);
  console.log('   Relay URL:', inviteData.relay_url);
  console.log('   Invite ID:', inviteData.invite_id);

  // 2. Generate keypair
  console.log('\n2. Generating agent keypair...');
  const { privateKey, publicKey } = generateAgentKeypair();
  console.log('   Public key:', Buffer.from(publicKey).toString('base64').slice(0, 20) + '...');

  // 3. Create and submit claim
  console.log('\n3. Submitting pairing claim to relay...');
  const hostname = os.hostname();
  const version = '0.0.1-test';

  const claim = createPairingClaim(inviteData, privateKey, publicKey, hostname, version);
  const claimResult = await submitPairingClaim(claim, inviteData.relay_url);

  if (!claimResult.success) {
    console.error('   ERROR:', claimResult.error);
    process.exit(1);
  }

  console.log('   ✓ Claim submitted!');
  console.log('   Claim ID:', claimResult.claim_id);

  // 4. Show verification phrase
  const verificationPhrase = generateVerificationPhrase(publicKey, inviteData.invite_id);

  console.log('\n' + '═'.repeat(60));
  console.log('\n  VERIFICATION PHRASE:\n');
  console.log('    ' + verificationPhrase);
  console.log('\n' + '═'.repeat(60));
  console.log('\nCheck Desktop → Agents for the pending claim.');
  console.log('Verify the phrase matches and click Approve.\n');

  // 5. Wait for approval
  console.log('5. Waiting for approval from vault...');
  console.log('   (Press Ctrl+C to cancel)\n');

  const approvalResult = await waitForPairingApproval(
    claimResult.claim_id!,
    inviteData.relay_url
  );

  if (approvalResult.status !== 'approved' || !approvalResult.agent_id) {
    console.error('\n   ✗ Pairing failed:', approvalResult.status);
    if (approvalResult.error) {
      console.error('   Error:', approvalResult.error);
    }
    process.exit(1);
  }

  console.log('\n   ✓ PAIRING APPROVED!');
  console.log('   Agent ID:', approvalResult.agent_id);
  console.log('\n=== VPS Pairing Test Complete ===\n');
}

main().catch(err => {
  console.error('\nError:', err.message);
  process.exit(1);
});
