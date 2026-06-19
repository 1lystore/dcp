/**
 * Permission scope normalization. Fixes old permission_scopes saved without an
 * operation prefix (read:/write:/sign:) for backward compatibility with agents
 * created before the prefix was introduced.
 */

const SIGNING_CHAINS = ['solana'];

export function normalizePermissionScope(scope: string): string {
  // Already has a valid prefix - return as-is
  if (scope.startsWith('read:') || scope.startsWith('write:') || scope.startsWith('sign:')) {
    return scope;
  }

  // Check if it's a chain name that should be sign:
  const lowerScope = scope.toLowerCase();
  if (SIGNING_CHAINS.includes(lowerScope)) {
    return `sign:${lowerScope}`;
  }

  // Everything else gets read: prefix (identity, credentials, etc.)
  return `read:${scope}`;
}

export function normalizePermissionScopes(scopes: string[]): string[] {
  if (!scopes || !Array.isArray(scopes)) return [];

  // Normalize each scope and remove duplicates
  const normalized = scopes.map(normalizePermissionScope);
  return [...new Set(normalized)];
}
