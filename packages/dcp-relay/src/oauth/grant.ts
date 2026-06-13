/**
 * OAuth grant processing for Cloud-Connect.
 *
 * A connect-link-driven, device-flow-style grant (works for headless cloud
 * agents) plus refresh-token rotation. All the security rules live here:
 *  - PKCE S256 binds the connect call to the token call.
 *  - DPoP binds every call to the agent's key; the access token carries cnf.jkt.
 *  - The access token is audience-bound to ONE vault (RFC 8707).
 *  - Refresh tokens rotate with reuse-detection (whole-chain revoke).
 *  - The agent stays INERT until the owner approves on-device (the bridge gates
 *    token issuance on the vault's approval status).
 *
 * Pure logic: returns { status, body }. The HTTP layer just (de)serializes.
 */

import type { RelayOAuthKeys } from './keys.js';
import type { AuthSessionStore, RefreshTokenStore } from './store.js';
import type { JtiReplayGuard } from './dpop.js';
import type { VaultConnectBridge } from './bridge.js';
import { verifyDpopProof, DpopError } from './dpop.js';
import { verifyPkceS256 } from './pkce.js';
import { issueAccessToken, DEFAULT_ACCESS_TOKEN_TTL_SEC } from './tokens.js';
import { parseConnectLinkRouting } from './connect-link-lite.js';

export const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

export interface GrantDeps {
  keys: RelayOAuthKeys;
  sessions: AuthSessionStore;
  refresh: RefreshTokenStore;
  jtiGuard: JtiReplayGuard;
  bridge: VaultConnectBridge;
  /** Public base URL of the relay (issuer + resource origin). No trailing slash. */
  issuer: string;
  accessTtlSec?: number;
  /** Poll interval hint (seconds) returned to the device-flow client. */
  pollIntervalSec?: number;
}

export interface GrantResponse {
  status: number;
  body: Record<string, unknown>;
}

const oauthError = (status: number, error: string, description?: string): GrantResponse => ({
  status,
  body: description ? { error, error_description: description } : { error },
});

function resourceFor(issuer: string, vaultId: string): string {
  return `${issuer.replace(/\/+$/, '')}/v/${vaultId}/mcp`;
}

// ----------------------------------------------------------------------------
// /oauth/connect — redeem a connect-link, open an authorization session
// ----------------------------------------------------------------------------

export interface ConnectRequest {
  connectLink: string;
  codeChallenge: string;
  codeChallengeMethod?: string;
  dpopProof: string;
  /** HTTP method + full URL of the /oauth/connect request (for DPoP htm/htu). */
  method: string;
  url: string;
  sourceIp?: string;
  clientId?: string;
  scope?: string;
}

export async function processConnect(
  deps: GrantDeps,
  req: ConnectRequest
): Promise<GrantResponse> {
  const routing = parseConnectLinkRouting(req.connectLink);
  if (!routing) {
    return oauthError(400, 'invalid_request', 'connect_link is missing or malformed');
  }
  if (!req.codeChallenge || (req.codeChallengeMethod ?? 'S256') !== 'S256') {
    return oauthError(400, 'invalid_request', 'PKCE code_challenge with method S256 is required');
  }

  let jkt: string;
  try {
    const dpop = await verifyDpopProof(req.dpopProof, {
      method: req.method,
      url: req.url,
      jtiGuard: deps.jtiGuard,
    });
    jkt = dpop.jkt;
  } catch (e) {
    if (e instanceof DpopError) return oauthError(400, 'invalid_dpop_proof', e.message);
    return oauthError(400, 'invalid_dpop_proof', 'DPoP proof invalid');
  }

  const redeem = await deps.bridge.redeem({
    vaultId: routing.vault_id,
    connectLink: req.connectLink,
    redeemerKey: jkt,
    sourceIp: req.sourceIp,
  });

  if (!redeem.ok) {
    if (redeem.reason === 'vault_unreachable') {
      return oauthError(503, 'temporarily_unavailable', 'The target vault is offline');
    }
    return oauthError(400, 'invalid_grant', `connect-link could not be redeemed (${redeem.reason || 'failed'})`);
  }

  const session = deps.sessions.create({
    vault_id: routing.vault_id,
    link_id: routing.link_id,
    agent_id: redeem.agentId,
    agent_jkt: jkt,
    code_challenge: req.codeChallenge,
    scope: req.scope || '',
    audience: resourceFor(deps.issuer, routing.vault_id),
    match_code: redeem.matchCode,
    client_id: req.clientId,
  });

  return {
    status: 200,
    body: {
      // Device-flow shape: poll /oauth/token with this device_code.
      device_code: session.session_id,
      match_code: redeem.matchCode,
      interval: deps.pollIntervalSec ?? 3,
      expires_in: Math.max(1, Math.round((session.expires_at - Date.now()) / 1000)),
      message:
        'Approve this connection on your DCP device. Confirm the match code shown here matches the one on your device.',
    },
  };
}

// ----------------------------------------------------------------------------
// /oauth/token — device_code poll + refresh_token rotation
// ----------------------------------------------------------------------------

export interface TokenRequest {
  grantType: string;
  /** device_code grant */
  deviceCode?: string;
  codeVerifier?: string;
  /** refresh_token grant */
  refreshToken?: string;
  dpopProof: string;
  method: string;
  url: string;
}

export async function processToken(deps: GrantDeps, req: TokenRequest): Promise<GrantResponse> {
  // Every token request must carry a fresh DPoP proof bound to this endpoint.
  let jkt: string;
  try {
    const dpop = await verifyDpopProof(req.dpopProof, {
      method: req.method,
      url: req.url,
      jtiGuard: deps.jtiGuard,
    });
    jkt = dpop.jkt;
  } catch (e) {
    if (e instanceof DpopError) return oauthError(400, 'invalid_dpop_proof', e.message);
    return oauthError(400, 'invalid_dpop_proof', 'DPoP proof invalid');
  }

  if (req.grantType === DEVICE_CODE_GRANT) {
    return processDeviceCodeGrant(deps, req, jkt);
  }
  if (req.grantType === 'refresh_token') {
    return processRefreshGrant(deps, req, jkt);
  }
  return oauthError(400, 'unsupported_grant_type');
}

const accessTtl = (deps: GrantDeps) => deps.accessTtlSec ?? DEFAULT_ACCESS_TOKEN_TTL_SEC;

async function processDeviceCodeGrant(
  deps: GrantDeps,
  req: TokenRequest,
  jkt: string
): Promise<GrantResponse> {
  if (!req.deviceCode || !req.codeVerifier) {
    return oauthError(400, 'invalid_request', 'device_code and code_verifier are required');
  }
  const session = deps.sessions.get(req.deviceCode);
  if (!session) return oauthError(400, 'invalid_grant', 'unknown device_code');
  if (session.status === 'expired') return oauthError(400, 'expired_token');
  if (session.status === 'issued') return oauthError(400, 'invalid_grant', 'device_code already used');

  // The token request must use the SAME DPoP key as the connect request.
  if (jkt !== session.agent_jkt) {
    return oauthError(400, 'invalid_grant', 'DPoP key does not match the authorization session');
  }
  // PKCE binds connect -> token.
  if (!verifyPkceS256(req.codeVerifier, session.code_challenge)) {
    return oauthError(400, 'invalid_grant', 'PKCE verification failed');
  }

  if (!session.agent_id) return oauthError(400, 'invalid_grant', 'session has no bound agent');

  const approval = await deps.bridge.approvalStatus({
    vaultId: session.vault_id,
    agentId: session.agent_id,
  });
  if (approval.status === 'pending') return oauthError(400, 'authorization_pending');
  if (approval.status === 'denied' || approval.status === 'revoked') {
    return oauthError(400, 'access_denied');
  }
  if (approval.status !== 'approved') return oauthError(400, 'invalid_grant', 'authorization not granted');

  const scope = approval.scope ?? session.scope ?? '';
  const access = await issueAccessToken({
    keys: deps.keys,
    issuer: deps.issuer,
    subject: session.agent_id,
    audience: session.audience,
    vaultId: session.vault_id,
    scope,
    jkt: session.agent_jkt,
    ttlSec: accessTtl(deps),
  });
  const { token: refreshToken } = deps.refresh.issue({
    vault_id: session.vault_id,
    agent_id: session.agent_id,
    jkt: session.agent_jkt,
    scope,
    audience: session.audience,
  });
  deps.sessions.setStatus(session.session_id, 'issued');

  return {
    status: 200,
    body: {
      access_token: access,
      token_type: 'DPoP',
      expires_in: accessTtl(deps),
      refresh_token: refreshToken,
      scope,
    },
  };
}

async function processRefreshGrant(
  deps: GrantDeps,
  req: TokenRequest,
  jkt: string
): Promise<GrantResponse> {
  if (!req.refreshToken) return oauthError(400, 'invalid_request', 'refresh_token is required');

  const rotated = deps.refresh.rotate(req.refreshToken);
  if (!rotated.ok || !rotated.context || !rotated.token) {
    return oauthError(400, 'invalid_grant', `refresh failed (${rotated.reason || 'unknown'})`);
  }
  // The refresh must be presented with the SAME DPoP key it was bound to.
  if (rotated.context.jkt !== jkt) {
    // Suspicious: valid refresh token presented with a different key. Kill the chain.
    const chain = deps.refresh.chainFor(rotated.token);
    if (chain) deps.refresh.revokeChain(chain);
    return oauthError(400, 'invalid_grant', 'DPoP key does not match the refresh token binding');
  }

  const access = await issueAccessToken({
    keys: deps.keys,
    issuer: deps.issuer,
    subject: rotated.context.agent_id,
    audience: rotated.context.audience,
    vaultId: rotated.context.vault_id,
    scope: rotated.context.scope,
    jkt: rotated.context.jkt,
    ttlSec: accessTtl(deps),
  });

  return {
    status: 200,
    body: {
      access_token: access,
      token_type: 'DPoP',
      expires_in: accessTtl(deps),
      refresh_token: rotated.token,
      scope: rotated.context.scope,
    },
  };
}
