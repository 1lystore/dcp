/**
 * Test setup - mock native modules that may not be available in CI.
 */

import { vi } from 'vitest';

const passwords = new Map<string, string>();

function key(service: string, account: string): string {
  return `${service}:${account}`;
}

vi.mock('keytar', () => ({
  default: {
    getPassword: vi.fn(async (service: string, account: string) =>
      passwords.get(key(service, account)) ?? null
    ),
    setPassword: vi.fn(async (service: string, account: string, password: string) => {
      passwords.set(key(service, account), password);
    }),
    deletePassword: vi.fn(async (service: string, account: string) =>
      passwords.delete(key(service, account))
    ),
  },
  getPassword: vi.fn(async (service: string, account: string) =>
    passwords.get(key(service, account)) ?? null
  ),
  setPassword: vi.fn(async (service: string, account: string, password: string) => {
    passwords.set(key(service, account), password);
  }),
  deletePassword: vi.fn(async (service: string, account: string) =>
    passwords.delete(key(service, account))
  ),
}));
