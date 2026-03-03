# DCP Canonical Schema (Phase 1)

Each scope is stored as a standalone encrypted record. Every record **must** include `schema_version`.

Notes:
- `schema_version` is a string (`"1.0"`).
- CRITICAL scopes are **reference-only** to agents (data never returned in plaintext).
- Arrays are real JSON arrays (no comma strings).

---

## Identity

### `identity.name` (SENSITIVE)
```json
{
  "schema_version": "1.0",
  "first": "John",
  "last": "Doe",
  "middle": "ABC",
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
  "city": "Mountain View",
  "state": "California",
  "postal_code": "94043",
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
  "shoe_unit": "US"
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
  "allergies": ["peanut", "shellfish"]
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
  "hotel_preference": ["smoking", "high-floor"]
}
```

---

## Credentials

### `credentials.api` (CRITICAL)
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
    "name": "ABC ",
    "phone": "+1234567889",
    "relationship": "brother"
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
