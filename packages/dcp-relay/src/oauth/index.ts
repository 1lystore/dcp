/**
 * DCP Relay OAuth 2.1 primitives (Cloud-Connect feature).
 *
 * Building blocks for the relay's per-vault MCP authorization:
 *  - keys:     ES256 token-signing key + JWKS
 *  - pkce:     RFC 7636 S256 verification
 *  - dpop:     RFC 9449 sender-constraint proof verification
 *  - tokens:   short-lived, audience-bound (RFC 8707), DPoP-bound access tokens
 *  - metadata: RFC 8414 AS metadata + RFC 9728 protected-resource metadata
 */

export {
  initOAuthKeys,
  generateOAuthPrivateJwk,
  OAUTH_SIGNING_ALG,
  type RelayOAuthKeys,
} from './keys.js';

export { isValidCodeVerifier, computeS256Challenge, verifyPkceS256 } from './pkce.js';

export {
  verifyDpopProof,
  createJtiGuard,
  jwkThumbprint,
  DpopError,
  type DpopVerifyOptions,
  type DpopVerifyResult,
  type JtiReplayGuard,
} from './dpop.js';

export {
  issueAccessToken,
  verifyAccessToken,
  AccessTokenError,
  DEFAULT_ACCESS_TOKEN_TTL_SEC,
  type IssueAccessTokenInput,
  type VerifyAccessTokenInput,
  type AccessTokenClaims,
} from './tokens.js';

export {
  authorizationServerMetadata,
  protectedResourceMetadata,
  wwwAuthenticateChallenge,
  type AsMetadataOptions,
  type PrmOptions,
} from './metadata.js';

export {
  ClientStore,
  AuthSessionStore,
  RefreshTokenStore,
  type RegisteredClient,
  type AuthSession,
  type AuthSessionStatus,
  type RefreshContext,
  type RotateResult,
} from './store.js';

export {
  UnavailableVaultBridge,
  UnavailableMcpBridge,
  type VaultConnectBridge,
  type BridgeRedeemInput,
  type BridgeRedeemResult,
  type BridgeApprovalInput,
  type BridgeApprovalResult,
  type BridgePairingInput,
  type McpDataBridge,
  type AuthedMcpRequest,
} from './bridge.js';

export {
  parseConnectLinkRouting,
  isConnectLinkToken,
  type ConnectLinkRouting,
} from './connect-link-lite.js';

export {
  processConnect,
  processToken,
  processAuthorize,
  authorizeStatus,
  DEVICE_CODE_GRANT,
  type GrantDeps,
  type GrantResponse,
  type ConnectRequest,
  type TokenRequest,
  type AuthorizeRequest,
  type AuthorizeResult,
} from './grant.js';
