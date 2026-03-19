/**
 * DCP Server API Client
 * Communicates with the local DCP server at http://127.0.0.1:8421
 *
 * Owner Trust Model:
 * - Desktop app uses challenge-response auth with Ed25519 keypair
 * - Owner token is included in all requests to bypass consent for owner actions
 */

import { invoke } from '@tauri-apps/api/core';

const API_BASE = 'http://127.0.0.1:8421';

export interface HealthResponse {
  status: string;
  initialized: boolean;
  unlocked: boolean;
  version: string;
}

export interface Scope {
  scope: string;
  type: string;
  sensitivity: string;
  chain?: string;
  public_address?: string;
}

export interface Agent {
  id: string;
  agent_name: string;
  granted_scopes: string[];
  consent_mode: string;
  expires_at: string;
  created_at: string;
  last_used_at?: string;
}

export interface PendingConsent {
  id: string;
  agent_name: string;
  action: string;
  scope: string;
  details?: Record<string, unknown>;
  status: string;
  created_at: string;
  expires_at: string;
}

export interface AuditEvent {
  id: string;
  event_type: string;
  agent_name?: string;
  scope?: string;
  operation?: string;
  outcome: string;
  created_at: string;
  details?: Record<string, unknown>;
}

export interface TrustedService {
  service_id: string;
  name: string;
  public_key: string;
  scopes: string[];
  budget: {
    daily: number;
    currency: string;
    auto_approve_under: number;
  };
  trusted_at: string;
  connected_at?: string;
  enabled: boolean;
  verified: boolean;
}

export interface BudgetCheck {
  allowed: boolean;
  limits: {
    per_tx: number;
    daily: number;
    approval_threshold: number;
  };
  remaining: {
    daily: number;
    per_tx: number;
  };
  requires_approval: boolean;
  reason?: string;
}

export interface RelayInfo {
  vault_id: string;
  relay_url: string;
  hpke_public_key: string;
  pairing_token?: string | null;
  relay_connected: boolean;
}

export interface BudgetConfig {
  daily_budget: Record<string, number>;
  tx_limit: Record<string, number>;
  approval_threshold: Record<string, number>;
}

export interface KnownService {
  service_id: string;
  name: string;
  connect_url: string;
  auth_url: string;
  public_key: string;
  default_scopes: string[];
  verified: boolean;
  description?: string;
  icon_url?: string;
}

export interface PairingTokenResponse {
  token: string;
  expires_at: string;
  service_id: string;
  scopes: string[];
  budget: { daily: number; currency: string; auto_approve_under: number };
}

class ApiClient {
  private ownerToken: string | null = null;
  private ownerAuthInFlight: Promise<boolean> | null = null;

  /**
   * Set the owner token for authenticated requests
   * This bypasses consent for desktop app actions
   */
  setOwnerToken(token: string | null): void {
    this.ownerToken = token;
  }

  /**
   * Get the current owner token
   */
  getOwnerToken(): string | null {
    return this.ownerToken;
  }

  /**
   * Check if we have a valid owner token
   */
  hasOwnerToken(): boolean {
    return this.ownerToken !== null;
  }

  private async request<T>(path: string, options?: RequestInit, retry = false): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options?.headers as Record<string, string>),
    };

    // Include owner token if available (bypasses consent for owner)
    if (this.ownerToken) {
      headers['X-DCP-OWNER-TOKEN'] = this.ownerToken;
    }

    const res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
    });

    const data = await res.json();

    if (!res.ok) {
      const errorCode = data?.error?.code as string | undefined;
      const errorMessage = data?.error?.message || 'Request failed';

      if (!retry && errorCode === 'OWNER_AUTH_REQUIRED') {
        const ok = await this.ensureOwnerAuth();
        if (ok) {
          return this.request<T>(path, options, true);
        }
      }

      console.error('API: Request failed:', path, data);
      throw new Error(errorMessage);
    }

    return data;
  }

  private async ensureOwnerAuth(): Promise<boolean> {
    if (this.ownerAuthInFlight) {
      return this.ownerAuthInFlight;
    }

    this.ownerAuthInFlight = (async () => {
      try {
        const credentials = await invoke<{
          desktop_id: string;
          public_key: string;
          is_new: boolean;
        }>('get_or_create_desktop_credentials');

        if (credentials.is_new) {
          try {
            await invoke<boolean>('register_desktop', {
              desktopId: credentials.desktop_id,
              publicKey: credentials.public_key,
            });
          } catch (err) {
            console.error('Failed to register desktop:', err);
          }
        }

        try {
          const token = await invoke<string>('authenticate_owner');
          this.setOwnerToken(token);
          return true;
        } catch (err) {
          // Retry registration + auth in case registration was missed
          try {
            await invoke<boolean>('register_desktop', {
              desktopId: credentials.desktop_id,
              publicKey: credentials.public_key,
            });
            const token = await invoke<string>('authenticate_owner');
            this.setOwnerToken(token);
            return true;
          } catch (retryErr) {
            console.error('Owner auth retry failed:', retryErr);
            return false;
          }
        }
      } catch (err) {
        console.error('Owner auth failed:', err);
        return false;
      } finally {
        this.ownerAuthInFlight = null;
      }
    })();

    return this.ownerAuthInFlight;
  }

  async authenticateOwner(): Promise<boolean> {
    return this.ensureOwnerAuth();
  }

  async health(): Promise<HealthResponse> {
    return this.request('/health');
  }

  async unlock(passphrase: string): Promise<{ unlocked: boolean }> {
    return this.request('/v1/vault/unlock', {
      method: 'POST',
      body: JSON.stringify({ passphrase }),
    });
  }

  async lock(): Promise<{ locked: boolean }> {
    return this.request('/v1/vault/lock', {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  async getScopes(): Promise<{ scopes: Scope[] }> {
    return this.request('/scopes');
  }

  async getAgents(): Promise<{ agents: Agent[] }> {
    return this.request('/agents');
  }

  async getPendingConsents(): Promise<{ pending: PendingConsent[] }> {
    return this.request('/consent');
  }

  async approveConsent(id: string, session: boolean = false): Promise<{ approved: boolean; session_id?: string }> {
    return this.request(`/consent/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify({ session }),
    });
  }

  async denyConsent(id: string): Promise<{ denied: boolean }> {
    return this.request(`/consent/${id}/deny`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  async revokeAgent(agent: string): Promise<{ revoked: number }> {
    return this.request(`/revoke/${agent}`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  async revokeSession(id: string): Promise<{ revoked: boolean }> {
    return this.request(`/v1/vault/agents/${id}/revoke`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  async getActivity(limit: number = 100): Promise<{ events: AuditEvent[]; count: number }> {
    return this.request(`/v1/vault/activity?limit=${limit}`);
  }

  async getAddress(chain: string): Promise<{ chain: string; address: string }> {
    return this.request(`/address/${chain}`);
  }

  async checkBudget(amount: number, currency: string): Promise<BudgetCheck> {
    return this.request(`/budget/check?amount=${amount}&currency=${currency}`);
  }

  async getRelayInfo(): Promise<RelayInfo> {
    return this.request('/v1/relay/info');
  }

  async getBudgetConfig(): Promise<BudgetConfig> {
    return this.request('/v1/vault/budgets');
  }

  async updateBudgetConfig(payload: BudgetConfig): Promise<BudgetConfig & { updated: boolean }> {
    return this.request('/v1/vault/budgets', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getTrustedServices(): Promise<{ services: TrustedService[] }> {
    return this.request('/v1/services');
  }

  async getKnownServices(): Promise<{ services: KnownService[] }> {
    return this.request('/v1/services/known');
  }

  async addTrustedService(service: {
    service_id: string;
    name?: string;
    public_key: string;
    scopes: string[];
    budget: { daily: number; currency: string; auto_approve_under: number };
    enabled?: boolean;
    verified?: boolean;
  }): Promise<{ created: boolean; service: TrustedService }> {
    return this.request('/v1/services', {
      method: 'POST',
      body: JSON.stringify(service),
    });
  }

  async updateTrustedService(
    serviceId: string,
    updates: {
      name?: string;
      public_key?: string;
      scopes?: string[];
      budget?: { daily: number; currency: string; auto_approve_under: number };
      enabled?: boolean;
      verified?: boolean;
    }
  ): Promise<{ updated: boolean; service: TrustedService }> {
    return this.request(`/v1/services/${encodeURIComponent(serviceId)}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  }

  async revokeTrustedService(serviceId: string): Promise<{ revoked: boolean }> {
    return this.request(`/v1/services/${encodeURIComponent(serviceId)}`, {
      method: 'DELETE',
    });
  }

  async updateRelayConfig(relayUrl: string, pairingToken?: string): Promise<{ updated: boolean }> {
    return this.request('/v1/relay/config', {
      method: 'POST',
      body: JSON.stringify({
        relay_url: relayUrl,
        pairing_token: pairingToken,
      }),
    });
  }

  async createPairingToken(payload: {
    service_id: string;
    scopes: string[];
    budget: { daily: number; currency: string; auto_approve_under: number };
    ttl_seconds?: number;
  }): Promise<PairingTokenResponse> {
    return this.request('/v1/pairing/start', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async readData(scope: string, agentName: string = 'desktop-ui'): Promise<{ scope: string; data?: Record<string, unknown> }> {
    return this.request('/v1/vault/read', {
      method: 'POST',
      body: JSON.stringify({ scope, agent_name: agentName }),
    });
  }

  async writeData(scope: string, data: Record<string, unknown>, agentName: string = 'desktop-ui'): Promise<{ scope: string; created: boolean; updated: boolean }> {
    return this.request('/v1/vault/write', {
      method: 'POST',
      body: JSON.stringify({ scope, data, agent_name: agentName }),
    });
  }

  async deleteData(scope: string, agentName: string = 'desktop-ui'): Promise<{ scope: string; deleted: boolean }> {
    return this.request('/v1/vault/delete', {
      method: 'POST',
      body: JSON.stringify({ scope, agent_name: agentName }),
    });
  }
}

export const api = new ApiClient();
