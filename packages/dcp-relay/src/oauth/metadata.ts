/**
 * OAuth discovery metadata.
 *  - Authorization Server Metadata (RFC 8414): /.well-known/oauth-authorization-server
 *  - Protected Resource Metadata (RFC 9728): /.well-known/oauth-protected-resource[/<path>]
 *
 * MCP clients discover how to authenticate by fetching these. We advertise only
 * what we actually enforce: authorization_code + PKCE(S256), refresh_token, DCR,
 * DPoP, and bearer methods. No implicit/password/plain — OAuth 2.1 hardening.
 */

import { stripTrailingSlashes } from '../safe-url.js';

export interface AsMetadataOptions {
  /** Public base URL of the relay (the OAuth issuer), e.g. https://relay.example. No trailing slash. */
  issuer: string;
  scopesSupported?: string[];
}

export function authorizationServerMetadata(opts: AsMetadataOptions): Record<string, unknown> {
  const base = stripTrailingSlashes(opts.issuer);
  return {
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    revocation_endpoint: `${base}/oauth/revoke`,
    jwks_uri: `${base}/oauth/jwks`,
    scopes_supported: opts.scopesSupported ?? [],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    dpop_signing_alg_values_supported: ['ES256', 'ES384', 'EdDSA', 'RS256', 'PS256'],
    revocation_endpoint_auth_methods_supported: ['none'],
    // OAuth 2.1: PKCE required, no implicit grant, no plain challenge.
    require_pushed_authorization_requests: false,
  };
}

export interface PrmOptions {
  /** The protected resource identifier (the per-vault MCP URL). */
  resource: string;
  /** The authorization server issuer(s) that protect this resource. */
  authorizationServers: string[];
  scopesSupported?: string[];
}

export function protectedResourceMetadata(opts: PrmOptions): Record<string, unknown> {
  return {
    resource: opts.resource,
    authorization_servers: opts.authorizationServers,
    bearer_methods_supported: ['header'],
    scopes_supported: opts.scopesSupported ?? [],
    // Tokens are DPoP-bound; advertise the proof algs the resource accepts.
    dpop_signing_alg_values_supported: ['ES256', 'ES384', 'EdDSA', 'RS256', 'PS256'],
  };
}

/**
 * Build the `WWW-Authenticate` header value for a 401 from the MCP resource,
 * pointing clients at the Protected Resource Metadata (RFC 9728 §5.1).
 */
export function wwwAuthenticateChallenge(opts: {
  resourceMetadataUrl: string;
  error?: string;
  errorDescription?: string;
}): string {
  let header = `DPoP realm="DCP", resource_metadata="${opts.resourceMetadataUrl}"`;
  if (opts.error) header += `, error="${opts.error}"`;
  if (opts.errorDescription) header += `, error_description="${opts.errorDescription}"`;
  return header;
}
