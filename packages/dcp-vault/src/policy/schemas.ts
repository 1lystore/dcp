/**
 * Input Validation Schemas using Zod
 *
 * All API request bodies are validated against these schemas
 * to prevent injection attacks and ensure data integrity.
 */

import { z } from 'zod';

// ============================================================================
// Common Schemas
// ============================================================================

export const UUIDSchema = z.string().uuid();
export const Base64Schema = z.string().regex(/^[A-Za-z0-9+/]+=*$/, 'Invalid base64 encoding');
export const Base64UrlSchema = z.string().regex(/^[A-Za-z0-9_-]+=*$/, 'Invalid base64url encoding');
export const TimestampSchema = z.number().int().positive();
export const HexSchema = z.string().regex(/^(0x)?[0-9a-fA-F]+$/, 'Invalid hex string');

// Chain validation
export const ChainSchema = z.enum(['solana']);
export type Chain = z.infer<typeof ChainSchema>;

// ============================================================================
// Request Schemas
// ============================================================================

/**
 * Vault unlock request
 */
export const UnlockRequestSchema = z.object({
  passphrase: z.string().min(1).max(256),
});

/**
 * Read/Reveal data request
 */
export const RevealRequestSchema = z.object({
  type: z.literal('reveal'),
  path: z.string().min(1).max(256),
  fields: z.array(z.string().max(64)).optional(),
  agent_id: UUIDSchema,
  request_id: UUIDSchema,
  nonce: UUIDSchema,
  timestamp: TimestampSchema,
  signature: Base64Schema,
});

/**
 * Sign transaction request
 */
export const SignTxRequestSchema = z.object({
  type: z.literal('sign_tx'),
  wallet: z.string().min(1).max(128),
  chain: ChainSchema,
  payload: z.string().min(1).max(100000), // Max 100KB payload
  amount: z.number().nonnegative().optional(),
  currency: z.string().max(10).optional(),
  destination: z.string().max(256).optional(),
  reason: z.string().max(500).optional(),
  agent_id: UUIDSchema,
  request_id: UUIDSchema,
  nonce: UUIDSchema,
  timestamp: TimestampSchema,
  signature: Base64Schema,
  idempotency_key: z.string().max(64).optional(),
});

/**
 * Sign message request
 */
export const SignMessageRequestSchema = z.object({
  chain: ChainSchema,
  message: z.string().min(1).max(10000),
  encoding: z.enum(['utf8', 'base64']).optional(),
  description: z.string().max(500).optional(),
});


/**
 * Write data request
 */
export const WriteRequestSchema = z.object({
  scope: z.string().min(1).max(256),
  data: z.record(z.string(), z.unknown()),
  sensitivity: z.enum(['public', 'private', 'secret']).optional(),
});

/**
 * Create pairing grant request
 */
export const CreatePairingGrantSchema = z.object({
  agent_name: z.string().min(1).max(64),
  permission_scopes: z.array(z.string().max(128)).min(1).max(50),
  tier: z.enum(['local', 'free', 'paid']).optional(),
  ttl_ms: z.number().int().positive().max(7 * 24 * 60 * 60 * 1000).optional(), // Max 7 days
  budget: z.object({
    daily: z.number().nonnegative(),
    currency: z.string().max(10),
    auto_approve_under: z.number().nonnegative(),
  }).optional(),
});

/**
 * Consent action request
 */
export const ConsentActionSchema = z.object({
  action: z.enum(['approve', 'deny']),
  session_scopes: z.array(z.string().max(128)).optional(),
});

// ============================================================================
// Validation Helper
// ============================================================================

/**
 * Validate request body against a Zod schema
 * @throws Error with VALIDATION_ERROR code if validation fails
 */
export function validateRequest<T>(schema: z.ZodSchema<T>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    const errors = result.error.issues.map((e: z.ZodIssue) => `${e.path.join('.')}: ${e.message}`);
    throw new Error(`VALIDATION_ERROR: ${errors.join(', ')}`);
  }
  return result.data;
}

/**
 * Create a Fastify-compatible schema validator
 */
export function createValidator<T>(schema: z.ZodSchema<T>) {
  return (data: unknown): T => validateRequest(schema, data);
}
