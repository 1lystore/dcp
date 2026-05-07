import { SensitivityLevel, ItemType } from '@dcprotocol/core';

export type ScopeConfig = {
  sensitivity: SensitivityLevel;
  itemType: ItemType;
  fields: {
    name: string;
    label: string;
    masked?: boolean;
    optional?: boolean;
    array?: boolean;
    boolean?: boolean;
    json?: boolean;
  }[];
  transform?: (data: Record<string, unknown>, scope: string) => Record<string, unknown>;
};

// Scope metadata for interactive prompts (field names match PRD schema)
export const SCOPE_CONFIG: Record<string, ScopeConfig> = {
  'identity.name': {
    sensitivity: 'sensitive',
    itemType: 'IDENTITY',
    fields: [
      { name: 'first', label: 'First name' },
      { name: 'last', label: 'Last name' },
      { name: 'middle', label: 'Middle name', optional: true },
      { name: 'display', label: 'Display name', optional: true },
    ],
  },
  'identity.email': {
    sensitivity: 'sensitive',
    itemType: 'IDENTITY',
    fields: [
      { name: 'email', label: 'Email address' },
      { name: 'verified', label: 'Email verified?', boolean: true, optional: true },
    ],
  },
  'identity.phone': {
    sensitivity: 'sensitive',
    itemType: 'IDENTITY',
    fields: [
      { name: 'e164', label: 'Phone (E.164, e.g., +14155551234)', optional: true },
      { name: 'country_code', label: 'Country code (e.g., +1)' },
      { name: 'number', label: 'Phone number' },
    ],
    transform: (data) => {
      const cc = String(data.country_code || '').replace(/\s+/g, '');
      const num = String(data.number || '').replace(/\s+/g, '');
      if (!data.e164 && cc && num) {
        return { ...data, e164: `${cc}${num}` };
      }
      return data;
    },
  },
  'identity.passport': {
    sensitivity: 'critical',
    itemType: 'IDENTITY',
    fields: [
      { name: 'full_name', label: 'Full name (as printed)', masked: true },
      { name: 'number', label: 'Passport number', masked: true },
      { name: 'issuing_country', label: 'Issuing country (ISO-3166-1 alpha-2)' },
      { name: 'nationality', label: 'Nationality (ISO-3166-1 alpha-2)' },
      { name: 'date_of_birth', label: 'Date of birth (YYYY-MM-DD)', masked: true },
      { name: 'expiry', label: 'Expiry date (YYYY-MM-DD)', masked: true },
      { name: 'gender', label: 'Gender (M/F/X)' },
    ],
  },
  'identity.drivers_license': {
    sensitivity: 'critical',
    itemType: 'IDENTITY',
    fields: [
      { name: 'full_name', label: 'Full name (as printed)', masked: true },
      { name: 'number', label: 'License number', masked: true },
      { name: 'issuing_state', label: 'Issuing state/province' },
      { name: 'issuing_country', label: 'Issuing country (ISO-3166-1 alpha-2)' },
      { name: 'date_of_birth', label: 'Date of birth (YYYY-MM-DD)', masked: true },
      { name: 'expiry', label: 'Expiry date (YYYY-MM-DD)', masked: true },
      { name: 'class', label: 'License class', optional: true },
    ],
  },
  'address.home': {
    sensitivity: 'sensitive',
    itemType: 'ADDRESS',
    fields: [
      { name: 'label', label: 'Label (e.g., Home)', optional: true },
      { name: 'line1', label: 'Address line 1' },
      { name: 'line2', label: 'Address line 2', optional: true },
      { name: 'city', label: 'City' },
      { name: 'state', label: 'State/Province' },
      { name: 'postal_code', label: 'Postal code' },
      { name: 'country_code', label: 'Country code (ISO-3166-1 alpha-2)' },
    ],
    transform: (data, scope) => {
      if (!data.label) {
        const label = scope.split('.')[1] || 'Home';
        return { ...data, label: label.charAt(0).toUpperCase() + label.slice(1) };
      }
      return data;
    },
  },
  'address.work': {
    sensitivity: 'sensitive',
    itemType: 'ADDRESS',
    fields: [
      { name: 'label', label: 'Label (e.g., Work)', optional: true },
      { name: 'line1', label: 'Address line 1' },
      { name: 'line2', label: 'Address line 2', optional: true },
      { name: 'city', label: 'City' },
      { name: 'state', label: 'State/Province' },
      { name: 'postal_code', label: 'Postal code' },
      { name: 'country_code', label: 'Country code (ISO-3166-1 alpha-2)' },
    ],
    transform: (data, scope) => {
      if (!data.label) {
        const label = scope.split('.')[1] || 'Work';
        return { ...data, label: label.charAt(0).toUpperCase() + label.slice(1) };
      }
      return data;
    },
  },
  'preferences.sizes': {
    sensitivity: 'standard',
    itemType: 'PREFERENCES',
    fields: [
      { name: 'shirt', label: 'Shirt size', optional: true },
      { name: 'pants', label: 'Pants size', optional: true },
      { name: 'shoe', label: 'Shoe size', optional: true },
      { name: 'shoe_unit', label: 'Shoe unit (US/UK/EU)', optional: true },
    ],
  },
  'preferences.brands': {
    sensitivity: 'standard',
    itemType: 'PREFERENCES',
    fields: [
      { name: 'preferred', label: 'Preferred brands (comma-separated)', array: true, optional: true },
      { name: 'avoided', label: 'Avoided brands (comma-separated)', array: true, optional: true },
    ],
  },
  'preferences.diet': {
    sensitivity: 'standard',
    itemType: 'PREFERENCES',
    fields: [
      { name: 'restrictions', label: 'Dietary restrictions (comma-separated)', array: true, optional: true },
      { name: 'allergies', label: 'Allergies (comma-separated)', array: true, optional: true },
    ],
  },
  'preferences.travel': {
    sensitivity: 'standard',
    itemType: 'PREFERENCES',
    fields: [
      { name: 'seat', label: 'Seat preference (e.g., window)', optional: true },
      { name: 'class', label: 'Travel class (economy/business)', optional: true },
      { name: 'meal', label: 'Meal preference', optional: true },
      { name: 'loyalty_programs', label: 'Loyalty programs (comma-separated)', array: true, optional: true },
      { name: 'hotel_preference', label: 'Hotel preferences (comma-separated)', array: true, optional: true },
    ],
  },
  'credentials.api': {
    sensitivity: 'critical',
    itemType: 'CREDENTIALS',
    fields: [
      { name: 'label', label: 'Label (e.g., OpenAI Production)' },
      { name: 'service', label: 'Service (e.g., openai)' },
      { name: 'key', label: 'API key', masked: true },
      { name: 'base_url', label: 'Base URL' },
      { name: 'auth_type', label: 'Auth type (bearer/api_key/basic/custom)' },
      { name: 'headers', label: 'Headers (JSON)', json: true, optional: true },
    ],
  },
  'health.profile': {
    sensitivity: 'sensitive',
    itemType: 'HEALTH',
    fields: [
      { name: 'blood_type', label: 'Blood type', optional: true },
      { name: 'conditions', label: 'Conditions (comma-separated)', array: true, optional: true },
      { name: 'medications', label: 'Medications (comma-separated)', array: true, optional: true },
      { name: 'emergency_contact_name', label: 'Emergency contact name', optional: true },
      { name: 'emergency_contact_phone', label: 'Emergency contact phone', optional: true },
      { name: 'emergency_contact_relationship', label: 'Emergency contact relationship', optional: true },
    ],
    transform: (data) => {
      const name = data.emergency_contact_name as string | undefined;
      const phone = data.emergency_contact_phone as string | undefined;
      const relationship = data.emergency_contact_relationship as string | undefined;
      const rest = { ...data } as Record<string, unknown>;
      delete rest.emergency_contact_name;
      delete rest.emergency_contact_phone;
      delete rest.emergency_contact_relationship;
      if (name || phone || relationship) {
        return {
          ...rest,
          emergency_contact: {
            name,
            phone,
            relationship,
          },
        };
      }
      return rest;
    },
  },
  'budget.default': {
    sensitivity: 'standard',
    itemType: 'BUDGET',
    fields: [
      { name: 'daily_limit', label: 'Daily limit (number)', optional: true },
      { name: 'per_tx_limit', label: 'Per-transaction limit (number)', optional: true },
      { name: 'currency', label: 'Currency (e.g., USD)', optional: true },
      { name: 'require_approval_above', label: 'Require approval above (number)', optional: true },
    ],
    transform: (data) => {
      const toNumber = (v: unknown) => (v === '' || v === undefined ? undefined : Number(v));
      return {
        ...data,
        daily_limit: toNumber(data.daily_limit),
        per_tx_limit: toNumber(data.per_tx_limit),
        require_approval_above: toNumber(data.require_approval_above),
      };
    },
  },
};
