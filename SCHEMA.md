# DCP Canonical Schema (Phase 1)

Each scope is stored as a standalone encrypted record. Every record **must** include `schema_version`.

Notes:
- `schema_version` is a string (`"1.0"`).
- CRITICAL scopes are **reference-only** to agents (data never returned in plaintext).
- Arrays are real JSON arrays (no comma strings).
- All timestamps are ISO 8601 format.

---

## Sensitivity Levels

| Level | Description | Agent Access |
|-------|-------------|--------------|
| `standard` | Non-sensitive preferences | Returned in plaintext |
| `sensitive` | PII (name, email, address) | Returned in plaintext with consent |
| `critical` | Secrets (keys, passports, credentials) | Reference-only, never returned |

---

## Item Types

| Type | Description |
|------|-------------|
| `WALLET_KEY` | Cryptocurrency wallet keys |
| `ADDRESS` | Physical addresses |
| `IDENTITY` | Personal identity information |
| `PREFERENCES` | User preferences |
| `CREDENTIALS` | API keys and credentials |
| `HEALTH` | Health information |
| `BUDGET` | Budget configuration |

---

## Identity

### `identity.name` (SENSITIVE)
```json
{
  "schema_version": "1.0",
  "first": "John",
  "last": "Doe",
  "middle": "ABC",
  "full": "John ABC Doe",
  "display": "J Doe"
}
```

### `identity.email` (SENSITIVE)
```json
{
  "schema_version": "1.0",
  "email": "user@example.com",
  "verified": true
}
```

### `identity.phone` (SENSITIVE)
```json
{
  "schema_version": "1.0",
  "e164": "+14155551234",
  "country_code": "+1",
  "number": "4155551234"
}
```

### `identity.passport` (CRITICAL)
```json
{
  "schema_version": "1.0",
  "full_name": "JOHN DOE ABC",
  "number": "A12345678",
  "issuing_country": "US",
  "issuing_authority": "US Department of State",
  "nationality": "US",
  "date_of_birth": "1990-01-01",
  "expiry": "2030-12-31",
  "gender": "M"
}
```

### `identity.drivers_license` (CRITICAL)
```json
{
  "schema_version": "1.0",
  "full_name": "JOHN DOE ABC",
  "number": "DL-1237890",
  "issuing_state": "California",
  "issuing_country": "US",
  "date_of_birth": "1990-01-15",
  "expiry": "2032-06-30",
  "class": "LMV"
}
```

---

## Address

### `address.home` / `address.work` (SENSITIVE)
```json
{
  "schema_version": "1.0",
  "label": "Work",
  "line1": "1600 Amphitheatre Parkway",
  "line2": "",
  "street": "1600 Amphitheatre Parkway",
  "city": "Mountain View",
  "state": "California",
  "postal_code": "94043",
  "zip": "94043",
  "country": "US",
  "country_code": "US"
}
```

---

## Preferences

### `preferences.sizes` (STANDARD)
```json
{
  "schema_version": "1.0",
  "shirt": "M",
  "pants": "32",
  "shoe": "10",
  "shoe_unit": "US",
  "width": "standard",
  "unit": "US"
}
```

### `preferences.brands` (STANDARD)
```json
{
  "schema_version": "1.0",
  "preferred": ["Nike", "Adidas"],
  "avoided": ["Puma"]
}
```

### `preferences.diet` (STANDARD)
```json
{
  "schema_version": "1.0",
  "restrictions": ["vegetarian"],
  "allergies": ["peanut", "shellfish"],
  "preferences": ["organic", "local"]
}
```

### `preferences.travel` (STANDARD)
```json
{
  "schema_version": "1.0",
  "seat": "window",
  "class": "economy",
  "meal": "vegetarian",
  "loyalty_programs": ["SkyMiles", "United"],
  "hotel_preference": ["non-smoking", "high-floor"]
}
```

---

## Credentials

### `credentials.api` / `credentials.api.<service>` (CRITICAL)
```json
{
  "schema_version": "1.0",
  "label": "OpenAI Production",
  "service": "openai",
  "key": "sk-abc123...",
  "base_url": "https://api.openai.com/v1",
  "auth_type": "bearer",
  "headers": {
    "X-Custom-Header": "value"
  }
}
```

---

## Health

### `health.profile` (SENSITIVE)
```json
{
  "schema_version": "1.0",
  "blood_type": "A+",
  "conditions": ["high bp"],
  "medications": ["albuterol"],
  "emergency_contact": {
    "name": "Jane Doe",
    "phone": "+1234567889",
    "relationship": "spouse"
  }
}
```

---

## Budget

### `budget.default` (STANDARD)
```json
{
  "schema_version": "1.0",
  "daily_limit": 500,
  "per_tx_limit": 200,
  "currency": "USD",
  "require_approval_above": 150
}
```

---

## Wallets

### `wallet.<chain>` / `wallet.<chain>.<label>` (CRITICAL)

Wallet keys are stored encrypted and never returned to agents. Only the public address and supported operations are exposed.

**Supported Chains:**
- `solana` (Ed25519)

*Multi-chain architecture supports adding additional chains in the future.*

**Stored Data (Internal Only):**
```json
{
  "schema_version": "1.0",
  "chain": "solana",
  "public_address": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
  "key_type": "ed25519",
  "private_key": "<encrypted>"
}
```

**Exposed to Agents (WalletInfo):**
```json
{
  "chain": "solana",
  "public_address": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
  "key_type": "ed25519",
  "operations": ["sign_tx", "sign_message", "get_address"]
}
```

---

## Database Tables

### vault_records
Primary encrypted data storage.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | Unique record ID |
| `scope` | TEXT UNIQUE | Scope path (e.g., `identity.email`) |
| `item_type` | TEXT | One of ItemType values |
| `sensitivity` | TEXT | `standard`, `sensitive`, `critical` |
| `ciphertext` | BLOB | Encrypted data |
| `nonce` | BLOB | Encryption nonce |
| `dek_wrapped` | BLOB | Wrapped data encryption key |
| `dek_nonce` | BLOB | DEK wrap nonce |
| `chain` | TEXT | For wallet records only |
| `public_address` | TEXT | For wallet records only |
| `schema_version` | TEXT | Schema version (default: "1.0") |
| `created_at` | TEXT | ISO timestamp |
| `updated_at` | TEXT | ISO timestamp |

### agent_sessions
Active agent sessions with granted permissions.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | Session ID |
| `agent_name` | TEXT | Agent identifier |
| `agent_fingerprint` | TEXT | Optional fingerprint |
| `marketplace` | TEXT | Optional marketplace |
| `trust_tier` | TEXT | `unknown`, `verified`, `trusted` |
| `granted_scopes` | TEXT | JSON array of scopes |
| `purpose` | TEXT | Session purpose |
| `consent_mode` | TEXT | `once`, `session`, `always`, `profile` |
| `profile_name` | TEXT | Optional profile name |
| `token_id` | TEXT | Associated token ID |
| `expires_at` | TEXT | ISO timestamp |
| `created_at` | TEXT | ISO timestamp |
| `last_used_at` | TEXT | ISO timestamp |
| `revoked_at` | TEXT | ISO timestamp (if revoked) |

### agent_connections
Agent pairing and connection state.

| Column | Type | Description |
|--------|------|-------------|
| `agent_id` | TEXT PK | Agent identifier |
| `name` | TEXT | Display name |
| `mode` | TEXT | `proxy`, `mcp`, `sdk` |
| `status` | TEXT | `pending`, `active`, `stale`, `revoked` |
| `service_id` | TEXT | Optional service identifier |
| `service_public_key` | TEXT | Ed25519 public key for relay auth |
| `permission_scopes` | TEXT | JSON array of scopes |
| `budget_daily` | REAL | Daily spending limit |
| `budget_currency` | TEXT | Currency code (default: USDC) |
| `budget_auto_approve_under` | REAL | Auto-approve threshold |
| `tier` | TEXT | `free`, `pro` |
| `token_hash` | TEXT | Hashed session token |
| `created_at` | TEXT | ISO timestamp |
| `paired_at` | TEXT | ISO timestamp |
| `last_seen_at` | TEXT | ISO timestamp |
| `last_request_at` | TEXT | ISO timestamp |
| `request_count` | INTEGER | Total requests |
| `revoked_at` | TEXT | ISO timestamp (if revoked) |

### spend_events
Budget tracking and transaction history.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | Event ID |
| `agent_session_id` | TEXT FK | Reference to agent_sessions |
| `amount` | REAL | Transaction amount |
| `currency` | TEXT | Currency code |
| `chain` | TEXT | Blockchain network |
| `operation` | TEXT | Operation type |
| `destination` | TEXT | Optional destination address |
| `idempotency_key` | TEXT UNIQUE | Deduplication key |
| `status` | TEXT | `committed`, `pending`, `failed` |
| `tx_signature` | TEXT | Transaction signature |
| `created_at` | TEXT | ISO timestamp |

### audit_events
Security audit trail.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | Event ID |
| `event_type` | TEXT | `GRANT`, `READ`, `EXECUTE`, `DENY`, `REVOKE`, `EXPIRE`, `CONFIG` |
| `agent_name` | TEXT | Agent involved |
| `scope` | TEXT | Scope accessed |
| `operation` | TEXT | Operation performed |
| `details` | TEXT | Additional details |
| `outcome` | TEXT | Result description |
| `created_at` | TEXT | ISO timestamp |

### pending_consents
Consent requests awaiting user approval.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | Consent request ID |
| `agent_name` | TEXT | Requesting agent |
| `action` | TEXT | Requested action |
| `scope` | TEXT | Requested scope |
| `details` | TEXT | Request details |
| `status` | TEXT | `pending`, `approved`, `denied`, `expired`, `consumed` |
| `created_at` | TEXT | ISO timestamp |
| `expires_at` | TEXT | ISO timestamp |
| `resolved_at` | TEXT | ISO timestamp (when resolved) |
| `session_id` | TEXT | Associated session ID |

### trusted_services
Verified service registry.

| Column | Type | Description |
|--------|------|-------------|
| `service_id` | TEXT PK | Service identifier |
| `name` | TEXT | Display name |
| `public_key` | TEXT | Ed25519 public key |
| `scopes` | TEXT | JSON array of allowed scopes |
| `budget_daily` | REAL | Daily spending limit |
| `budget_currency` | TEXT | Currency code |
| `budget_auto_approve_under` | REAL | Auto-approve threshold |
| `trusted_at` | TEXT | ISO timestamp |
| `connected_at` | TEXT | ISO timestamp |
| `enabled` | INTEGER | 1=enabled, 0=disabled |
| `verified` | INTEGER | 1=verified, 0=unverified |

### saved_profiles
Reusable permission profiles.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | Profile ID |
| `name` | TEXT UNIQUE | Profile name |
| `allowed_scopes` | TEXT | JSON array of scopes |
| `spending_limit_per_tx` | TEXT | JSON object by currency |
| `spending_limit_daily` | TEXT | JSON object by currency |
| `approval_threshold` | TEXT | JSON object by currency |
| `allowed_purposes` | TEXT | JSON array of purposes |
| `allow_always_expiry_days` | INTEGER | Days until expiry |
| `created_at` | TEXT | ISO timestamp |
| `updated_at` | TEXT | ISO timestamp |

### pairing_tokens
Temporary pairing tokens for proxy flow.

| Column | Type | Description |
|--------|------|-------------|
| `token_hash` | TEXT PK | SHA-256 hash of token |
| `service_id` | TEXT | Target service |
| `scopes` | TEXT | JSON array of scopes |
| `budget_daily` | REAL | Daily limit |
| `budget_currency` | TEXT | Currency code |
| `budget_auto_approve_under` | REAL | Auto-approve threshold |
| `created_at` | TEXT | ISO timestamp |
| `expires_at` | TEXT | ISO timestamp |
| `used_at` | TEXT | ISO timestamp (when used) |

### telegram_configs
Telegram notification configuration.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | Config ID |
| `chat_id` | TEXT UNIQUE | Telegram chat ID |
| `bot_token_ciphertext` | BLOB | Encrypted bot token |
| `bot_token_nonce` | BLOB | Encryption nonce |
| `bot_token_dek_wrapped` | BLOB | Wrapped DEK |
| `bot_token_dek_nonce` | BLOB | DEK nonce |
| `enabled` | INTEGER | 1=enabled |
| `notify_consent` | INTEGER | 1=notify on consent |
| `rate_limit_per_hour` | INTEGER | Max notifications/hour |
| `last_notification_at` | TEXT | ISO timestamp |
| `notifications_this_hour` | INTEGER | Current hour count |
| `hour_window_start` | TEXT | ISO timestamp |
| `created_at` | TEXT | ISO timestamp |
| `updated_at` | TEXT | ISO timestamp |
| `paired_at` | TEXT | ISO timestamp |
| `muted_until` | TEXT | ISO timestamp (if muted) |

### telegram_pairing_codes
Temporary codes for Telegram linking.

| Column | Type | Description |
|--------|------|-------------|
| `code` | TEXT PK | 6-digit pairing code |
| `vault_id` | TEXT | Target vault |
| `expires_at` | TEXT | ISO timestamp (10 min) |
| `used` | INTEGER | 0=unused, 1=used |
| `created_at` | TEXT | ISO timestamp |

### telegram_notification_log
Notification audit trail.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | Log entry ID |
| `chat_id` | TEXT | Telegram chat ID |
| `consent_id` | TEXT | Related consent ID |
| `notification_type` | TEXT | `consent_request`, `test`, `pairing_success`, `budget_alert` |
| `category` | TEXT | Request category |
| `agent_name` | TEXT | Agent name |
| `sent_at` | TEXT | ISO timestamp |
| `delivered_at` | TEXT | ISO timestamp |
| `error` | TEXT | Error message (if failed) |

---

## Telegram Notification Types

| Type | Description |
|------|-------------|
| `consent_request` | Approval request from agent |
| `test` | Test notification |
| `pairing_success` | Successful Telegram pairing |
| `budget_alert` | Budget threshold exceeded |

## Telegram Request Categories

Privacy-safe categories for notifications (no sensitive details):

| Category | Description |
|----------|-------------|
| `transaction_signing` | Blockchain transaction |
| `message_signing` | Message signature |
| `data_read` | Reading personal data |
| `data_write` | Writing personal data |
| `credential_access` | Accessing credentials |
| `other` | Other operations |

---

## Error Codes

| Code | Description |
|------|-------------|
| `VAULT_NOT_INITIALIZED` | Vault not set up |
| `VAULT_LOCKED` | Vault is locked |
| `CONSENT_REQUIRED` | User approval needed |
| `CONSENT_DENIED` | User denied request |
| `CONSENT_EXPIRED` | Consent request expired |
| `CONSENT_TIMEOUT` | Consent request timed out |
| `CONSENT_NOT_FOUND` | Consent not found |
| `SCOPE_VIOLATION` | Scope not granted |
| `BUDGET_EXCEEDED_TX` | Per-transaction limit exceeded |
| `BUDGET_EXCEEDED_DAILY` | Daily limit exceeded |
| `TOKEN_EXPIRED` | Session token expired |
| `TOKEN_REVOKED` | Session token revoked |
| `INVALID_CHAIN` | Unsupported blockchain |
| `INVALID_TX` | Invalid transaction |
| `INVALID_SCHEMA` | Schema validation failed |
| `IDEMPOTENCY_CONFLICT` | Duplicate request |
| `RATE_LIMITED` | Rate limit exceeded |
| `RECORD_NOT_FOUND` | Record not found |
| `INTERNAL_ERROR` | Internal error |
| `VALIDATION_ERROR` | Input validation failed |
| `UNAUTHORIZED` | Not authorized |
| `SERVICE_NOT_TRUSTED` | Service not trusted |
| `SERVICE_NOT_FOUND` | Service not found |
| `SERVICE_ALREADY_TRUSTED` | Service already trusted |
| `INVALID_SERVICE_SIGNATURE` | Signature verification failed |
| `SERVICE_SCOPE_VIOLATION` | Service scope violation |
| `INVALID_PUBLIC_KEY` | Invalid public key format |
