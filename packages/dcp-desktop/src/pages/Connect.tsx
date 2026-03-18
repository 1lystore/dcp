import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-shell';
import { api, type RelayInfo, type KnownService } from '../api';

interface DesktopCredentials {
  desktop_id: string;
  public_key: string;
  is_new: boolean;
}

function normalizeServiceId(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 48);
}

function shellEscape(value: string): string {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`;
}

export default function Connect() {
  const navigate = useNavigate();
  const [info, setInfo] = useState<RelayInfo | null>(null);
  const [knownServices, setKnownServices] = useState<KnownService[]>([]);
  const [relayUrl, setRelayUrl] = useState('');
  const [vpsServiceId, setVpsServiceId] = useState('my-vps-agent');
  const [pairScopes, setPairScopes] = useState<string[]>(['sign:solana', 'budget:check']);
  const [pairBudgetDaily, setPairBudgetDaily] = useState('10');
  const [pairBudgetCurrency, setPairBudgetCurrency] = useState('USDC');
  const [pairAutoApprove, setPairAutoApprove] = useState('1');
  const [pairTtl, setPairTtl] = useState('600');
  const [pairResult, setPairResult] = useState<{ token: string; expires_at: string } | null>(null);
  const [pairingLoading, setPairingLoading] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const defaultRelayUrl = 'wss://relay.dcp.1ly.store';

  const ensureOwnerAuth = async (): Promise<boolean> => {
    try {
      const credentials = await invoke<DesktopCredentials>('get_or_create_desktop_credentials');
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
      const token = await invoke<string>('authenticate_owner');
      api.setOwnerToken(token);
      return true;
    } catch (err) {
      console.error('Owner authentication failed:', err);
      return false;
    }
  };

  const loadInfo = useCallback(async () => {
    try {
      const data = await api.getRelayInfo();
      setInfo(data);
      setRelayUrl(data.relay_url || '');
      setStatus(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load relay info';
      if (message.includes('Owner authentication required')) {
        const ok = await ensureOwnerAuth();
        if (ok) {
          try {
            const data = await api.getRelayInfo();
            setInfo(data);
            setRelayUrl(data.relay_url || '');
            setStatus(null);
            return;
          } catch (retryErr) {
            setStatus(retryErr instanceof Error ? retryErr.message : 'Failed to load relay info');
            return;
          }
        }
      }
      setStatus(message);
    }
  }, []);

  useEffect(() => {
    void loadInfo();
    loadKnownServices();
  }, [loadInfo]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      if (!api.hasOwnerToken()) return;
      void loadInfo();
    }, 5000);

    return () => window.clearInterval(interval);
  }, [loadInfo]);

  const loadKnownServices = async () => {
    try {
      const res = await api.getKnownServices();
      setKnownServices(res.services || []);
    } catch (err) {
      console.error('Failed to load known services:', err);
    }
  };

  const serviceId = useMemo(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get('service') || '';
  }, []);

  const selectedService = useMemo(
    () => knownServices.find((s) => s.service_id === serviceId),
    [knownServices, serviceId]
  );

  const handleOpenConnect = (targetServiceId: string) => {
    navigate(`/connect?service=${encodeURIComponent(targetServiceId)}`);
  };

  const save = async () => {
    setLoading(true);
    setStatus(null);
    try {
      await api.updateRelayConfig(relayUrl);
      await loadInfo();
      setStatus('Relay settings saved');
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Failed to save relay settings');
    } finally {
      setLoading(false);
    }
  };

  const bundle = info
    ? JSON.stringify(
        {
          vault_id: info.vault_id,
          relay_url: info.relay_url,
          hpke_public_key: info.hpke_public_key,
        },
        null,
        2
      )
    : '';

  const normalizedVpsServiceId = useMemo(
    () => normalizeServiceId(vpsServiceId) || 'my-vps-agent',
    [vpsServiceId]
  );
  const hasVpsCommand = Boolean(info && pairResult?.token);
  const vpsCommand = info && pairResult?.token
    ? `npx -y -p @dcprotocol/proxy dcp-proxy --pair ${shellEscape(pairResult.token)} --service-id ${shellEscape(normalizedVpsServiceId)} --vault ${shellEscape(info.vault_id)} --hpke-key ${shellEscape(info.hpke_public_key)} --relay ${shellEscape(info.relay_url || relayUrl || defaultRelayUrl)} --port 8420`
    : '';

  const pairingScopes = useMemo(() => ([
    {
      id: 'sign-solana',
      label: 'Sign Solana transactions',
      scope: 'sign:solana',
    },
    {
      id: 'sign-base',
      label: 'Sign Base transactions',
      scope: 'sign:base',
    },
    {
      id: 'sign-ethereum',
      label: 'Sign Ethereum transactions',
      scope: 'sign:ethereum',
    },
    {
      id: 'read-keys',
      label: 'Read API keys',
      scope: 'read:credentials.api.*',
    },
    {
      id: 'read-profile',
      label: 'Read identity',
      scope: 'read:identity.*',
    },
    {
      id: 'read-address',
      label: 'Read addresses',
      scope: 'read:address.*',
    },
    {
      id: 'budget-check',
      label: 'Budget checks',
      scope: 'budget:check',
    },
  ]), []);

  const togglePairScope = (scope: string) => {
    setPairScopes((prev) => (prev.includes(scope)
      ? prev.filter((s) => s !== scope)
      : [...prev, scope]));
  };

  const copyBundle = async () => {
    try {
      await navigator.clipboard.writeText(bundle);
      setStatus('Connection bundle copied');
    } catch {
      setStatus('Failed to copy bundle');
    }
  };

  const createPairingToken = async () => {
    if (!normalizedVpsServiceId) {
      setStatus('Give this VPS a short name first');
      return;
    }
    if (pairScopes.length === 0) {
      setStatus('Select at least one permission');
      return;
    }

    setPairingLoading(true);
    setStatus(null);

    try {
      const daily = Number(pairBudgetDaily);
      const autoApprove = Number(pairAutoApprove);
      const ttlSeconds = Number(pairTtl);

      const res = await api.createPairingToken({
        service_id: normalizedVpsServiceId,
        scopes: pairScopes,
        budget: {
          daily: Number.isNaN(daily) ? 10 : daily,
          currency: pairBudgetCurrency,
          auto_approve_under: Number.isNaN(autoApprove) ? 0 : autoApprove,
        },
        ttl_seconds: Number.isNaN(ttlSeconds) ? 600 : ttlSeconds,
      });

      setVpsServiceId(normalizedVpsServiceId);
      setPairResult({ token: res.token, expires_at: res.expires_at });
      setStatus('Pairing token generated');
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Failed to create pairing token');
    } finally {
      setPairingLoading(false);
    }
  };

  const copyVpsCommand = async () => {
    try {
      await navigator.clipboard.writeText(vpsCommand);
      setStatus('VPS setup command copied');
    } catch {
      setStatus('Failed to copy VPS command');
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h2>Connect</h2>
        <p className="muted">Connect your vault to trusted apps or your own remote agents.</p>
      </div>

      <div className="card">
        <h3>Quick Setup</h3>
        <p className="muted">Follow these steps once. Your vault will stay connected.</p>

        <div style={{ display: 'grid', gap: 16, marginTop: 12 }}>
          <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: 10, background: 'var(--bg-tertiary)' }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>1) Connect to the relay</div>
            <div className="muted small">We recommend the hosted relay for best reliability.</div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 10 }}>
              <button
                className="btn btn-primary"
                onClick={() => {
                  setRelayUrl(defaultRelayUrl);
                }}
                disabled={loading}
              >
                Use relay.dcp.1ly.store
              </button>
              <button className="btn btn-secondary" onClick={save} disabled={loading}>
                {loading ? 'Saving...' : 'Save Relay'}
              </button>
              {info && (
                <span className={`badge ${info.relay_connected ? 'ok' : 'warn'}`}>
                  {info.relay_connected ? 'Relay Connected' : 'Relay Disconnected'}
                </span>
              )}
            </div>
          </div>

          <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: 10, background: 'var(--bg-tertiary)' }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>2) Allow a service</div>
            <div className="muted small">
              Choose an app you trust and set its permissions once.
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 10 }}>
              <button className="btn btn-secondary" onClick={() => navigate('/settings')}>
                Manage Trusted Services
              </button>
            </div>
            {knownServices.length > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 10 }}>
                {knownServices.map((service) => (
                  <button
                    key={service.service_id}
                    className="btn btn-secondary"
                    onClick={() => handleOpenConnect(service.service_id)}
                  >
                    Set up {service.name}
                  </button>
                ))}
              </div>
            )}
          </div>

          <div style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: 10, background: 'var(--bg-tertiary)' }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>3) Run a remote agent (VPS)</div>
            <div className="muted small">
              Give your VPS a simple name, choose what it can do, then copy one command. Your agent talks to localhost on the VPS.
            </div>
            <div style={{ marginTop: 10 }}>
              <label className="label">Name this VPS</label>
              <input
                className="input"
                value={vpsServiceId}
                onChange={(e) => setVpsServiceId(normalizeServiceId(e.target.value))}
                placeholder="openclaw-vps"
              />
              <div className="muted small" style={{ marginTop: 6 }}>
                Use lowercase letters, numbers, and hyphens only.
              </div>
            </div>
            <div style={{ marginTop: 12 }}>
              <label className="label">Permissions</label>
              <div style={{ display: 'grid', gap: 8 }}>
                {pairingScopes.map((scopeOption) => (
                  <label key={scopeOption.id} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <input
                      type="checkbox"
                      checked={pairScopes.includes(scopeOption.scope)}
                      onChange={() => togglePairScope(scopeOption.scope)}
                    />
                    <span style={{ fontSize: 13 }}>{scopeOption.label}</span>
                  </label>
                ))}
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 12 }}>
              <div>
                <label className="label">Daily Budget</label>
                <input
                  className="input"
                  type="number"
                  min="0"
                  value={pairBudgetDaily}
                  onChange={(e) => setPairBudgetDaily(e.target.value)}
                />
              </div>
              <div>
                <label className="label">Currency</label>
                <select
                  className="input"
                  value={pairBudgetCurrency}
                  onChange={(e) => setPairBudgetCurrency(e.target.value)}
                >
                  <option value="USDC">USDC</option>
                  <option value="USDT">USDT</option>
                  <option value="SOL">SOL</option>
                  <option value="ETH">ETH</option>
                  <option value="BASE_ETH">BASE_ETH</option>
                </select>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 12 }}>
              <div>
                <label className="label">Auto-approve under</label>
                <input
                  className="input"
                  type="number"
                  min="0"
                  value={pairAutoApprove}
                  onChange={(e) => setPairAutoApprove(e.target.value)}
                />
              </div>
              <div>
                <label className="label">Token TTL (sec)</label>
                <input
                  className="input"
                  type="number"
                  min="60"
                  value={pairTtl}
                  onChange={(e) => setPairTtl(e.target.value)}
                />
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              <button className="btn btn-primary" onClick={createPairingToken} disabled={pairingLoading}>
                {pairingLoading ? 'Generating...' : 'Generate Pairing Token'}
              </button>
            </div>
            {pairResult && (
              <div className="muted small" style={{ marginTop: 8 }}>
                Pairing token ready. It expires at {new Date(pairResult.expires_at).toLocaleString()}.
              </div>
            )}
            <textarea
              className="input"
              readOnly
              rows={6}
              value={hasVpsCommand ? vpsCommand : 'Generate a pairing token to get your one-line VPS setup command.'}
              style={{ marginTop: 10 }}
            />
            <div className="muted small" style={{ marginTop: 6 }}>
              Run this once on the VPS. It uses Node.js 18+ and installs the DCP proxy automatically via npx.
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
              <button className="btn btn-secondary" onClick={copyVpsCommand} disabled={!hasVpsCommand}>
                Copy VPS Command
              </button>
            </div>
          </div>
        </div>

        {status && <div className="muted small" style={{ marginTop: 12 }}>{status}</div>}
      </div>

      {selectedService && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Set up {selectedService.name}</h3>
          <p className="muted">
            Use the links below to authenticate with {selectedService.name}, then paste the connection bundle if requested.
          </p>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button
              className="btn btn-primary"
              onClick={async () => {
                try {
                  await open(selectedService.auth_url);
                } catch (err) {
                  console.error('Failed to open auth URL:', err);
                  setStatus('Failed to open service login');
                }
              }}
            >
              Open {selectedService.name} Login
            </button>
            <button
              className="btn btn-secondary"
              onClick={async () => {
                try {
                  await open(selectedService.connect_url);
                } catch (err) {
                  console.error('Failed to open connect URL:', err);
                  setStatus('Failed to open service connect page');
                }
              }}
            >
              Open Connect Page
            </button>
          </div>
          <div className="muted small" style={{ marginTop: 8 }}>
            {selectedService.description || 'Follow the service instructions to attach your vault.'}
          </div>
        </div>
      )}

      <details className="card" style={{ marginTop: 16 }}>
        <summary style={{ cursor: 'pointer', fontWeight: 600 }}>Custom Relay (Advanced)</summary>
        <div style={{ marginTop: 12 }}>
          <div>
            <label className="label">Relay URL</label>
            <input
              className="input"
              value={relayUrl}
              onChange={(e) => setRelayUrl(e.target.value)}
              placeholder="wss://relay.dcprotocol.org"
            />
            <div className="muted small" style={{ marginTop: 6 }}>
              Only change this if you are using your own relay.
            </div>
          </div>
          <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
            <button className="btn btn-primary" onClick={save} disabled={loading}>
              {loading ? 'Saving...' : 'Save'}
            </button>
            {info && (
              <span className={`badge ${info.relay_connected ? 'ok' : 'warn'}`}>
                {info.relay_connected ? 'Relay Connected' : 'Relay Disconnected'}
              </span>
            )}
          </div>
        </div>
      </details>

      <details className="card" style={{ marginTop: 16 }}>
        <summary style={{ cursor: 'pointer', fontWeight: 600 }}>Connection Bundle (Advanced)</summary>
        <div style={{ marginTop: 12 }}>
          <p className="muted">
            Share this with your MCP tool once. It contains your vault ID and public key.
          </p>
          <textarea className="input" readOnly rows={10} value={bundle} />
          <div style={{ marginTop: 8 }}>
            <button className="btn" onClick={copyBundle} disabled={!bundle}>
              Copy Bundle
            </button>
          </div>
        </div>
      </details>
    </div>
  );
}
