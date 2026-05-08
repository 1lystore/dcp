import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, type Scope, type PendingConsent, type AgentConnection } from '../api';

export default function Home() {
  const navigate = useNavigate();
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [pendingConsents, setPendingConsents] = useState<PendingConsent[]>([]);
  const [agents, setAgents] = useState<AgentConnection[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [copiedAddress, setCopiedAddress] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [scopesRes, consentsRes, agentsRes] = await Promise.all([
        api.getScopes(),
        api.getPendingConsents(),
        api.getAgentConnections(),
      ]);
      setScopes(scopesRes.scopes);
      setPendingConsents(consentsRes.pending);
      setAgents(agentsRes.agents || []);
    } catch (err) {
      console.error('Failed to load home data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, [loadData]);

  const handleApprove = async (id: string, options: { session?: boolean; always?: boolean } = {}) => {
    setActionLoading(id);
    try {
      await api.approveConsent(id, options);
      await loadData();
    } catch (err) {
      console.error('Failed to approve:', err);
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeny = async (id: string) => {
    setActionLoading(id);
    try {
      await api.denyConsent(id);
      await loadData();
    } catch (err) {
      console.error('Failed to deny:', err);
    } finally {
      setActionLoading(null);
    }
  };

  const copyAddress = async (address: string) => {
    try {
      await navigator.clipboard.writeText(address);
      setCopiedAddress(address);
      setTimeout(() => setCopiedAddress(null), 2000);
    } catch {
      console.error('Failed to copy');
    }
  };

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
      </div>
    );
  }

  const wallets = scopes.filter(s => s.type === 'WALLET_KEY');
  const activeAgents = agents.filter(a => a.status === 'active');

  return (
    <div>
      {/* Pending Approvals - Always at top if any */}
      {pendingConsents.length > 0 && (
        <div className="card" style={{ borderColor: 'var(--warning)', borderWidth: '2px' }}>
          <div className="card-header">
            <div>
              <h2 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                Pending Approvals
                <span style={{
                  background: 'var(--warning)',
                  color: '#000',
                  padding: '2px 8px',
                  borderRadius: '12px',
                  fontSize: '12px',
                  fontWeight: 600,
                }}>{pendingConsents.length}</span>
              </h2>
              <p className="card-subtitle">Agents requesting access to your vault</p>
            </div>
          </div>

          {pendingConsents.map((consent) => {
            const details = consent.details || {};
            const isLoading = actionLoading === consent.id;

            return (
              <div key={consent.id} style={{
                padding: '16px',
                background: 'var(--bg-tertiary)',
                borderRadius: '10px',
                marginBottom: '12px',
                border: '1px solid var(--border)',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                  <div>
                    <span style={{ fontWeight: 600, fontSize: '14px' }}>{consent.agent_name}</span>
                    <span style={{ marginLeft: '8px', color: 'var(--text-secondary)' }}>
                      wants to <strong style={{ color: 'var(--accent)' }}>{consent.action}</strong>
                    </span>
                  </div>
                  <span style={{
                    fontSize: '11px',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    background: 'var(--bg-secondary)',
                    color: 'var(--text-muted)',
                  }}>
                    {new Date(consent.expires_at).toLocaleTimeString()}
                  </span>
                </div>

                <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                  <code style={{ color: 'var(--accent)', background: 'var(--bg-secondary)', padding: '2px 6px', borderRadius: '4px' }}>
                    {consent.scope}
                  </code>
                  {'amount' in details && 'currency' in details && (
                    <span style={{ marginLeft: '12px' }}>
                      Amount: <strong>{String(details.amount)} {String(details.currency)}</strong>
                    </span>
                  )}
                </div>

                <div style={{ display: 'flex', gap: '8px', marginTop: '12px', flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-success"
                    onClick={() => handleApprove(consent.id, {})}
                    disabled={isLoading}
                    style={{ padding: '8px 16px', fontSize: '13px' }}
                  >
                    {isLoading ? '...' : 'Approve Once'}
                  </button>
                  <button
                    className="btn btn-secondary"
                    onClick={() => handleApprove(consent.id, { session: true })}
                    disabled={isLoading}
                    style={{ padding: '8px 16px', fontSize: '13px' }}
                  >
                    Approve Session
                  </button>
                  <button
                    className="btn btn-primary"
                    onClick={() => handleApprove(consent.id, { always: true })}
                    disabled={isLoading}
                    style={{ padding: '8px 16px', fontSize: '13px' }}
                    title="Create a permanent rule to always allow this action"
                  >
                    Always Allow
                  </button>
                  <button
                    className="btn btn-danger"
                    onClick={() => handleDeny(consent.id)}
                    disabled={isLoading}
                    style={{ padding: '8px 16px', fontSize: '13px' }}
                  >
                    Deny
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Wallets */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Wallets</h2>
            <p className="card-subtitle">Your blockchain wallets</p>
          </div>
        </div>

        {wallets.length === 0 ? (
          <div className="empty-state">
            <p>No wallets configured</p>
          </div>
        ) : (
          <div style={{ display: 'grid', gap: '12px' }}>
            {wallets.map((wallet) => (
              <div
                key={wallet.scope}
                style={{
                  padding: '16px',
                  background: 'var(--bg-tertiary)',
                  borderRadius: '10px',
                  border: '1px solid var(--border)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div>
                  <div style={{
                    fontSize: '12px',
                    fontWeight: 600,
                    color: 'var(--accent)',
                    textTransform: 'uppercase',
                    marginBottom: '4px',
                  }}>
                    {wallet.chain}
                  </div>
                  <div style={{
                    fontFamily: 'monospace',
                    fontSize: '13px',
                    color: 'var(--text-secondary)',
                  }}>
                    {wallet.public_address?.slice(0, 8)}...{wallet.public_address?.slice(-6)}
                  </div>
                </div>
                <button
                  className="btn btn-secondary"
                  onClick={() => copyAddress(wallet.public_address || '')}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                >
                  {copiedAddress === wallet.public_address ? 'Copied!' : 'Copy'}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Quick Stats */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Overview</h2>
            <p className="card-subtitle">Vault status at a glance</p>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
          <div
            onClick={() => navigate('/connect')}
            style={{
              padding: '20px',
              background: 'var(--bg-tertiary)',
              borderRadius: '10px',
              textAlign: 'center',
              cursor: 'pointer',
              transition: 'background 0.2s',
            }}
          >
            <div style={{ fontSize: '28px', fontWeight: '700', color: 'var(--success)' }}>
              {activeAgents.length}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Connected Agents
            </div>
          </div>
          <div style={{
            padding: '20px',
            background: 'var(--bg-tertiary)',
            borderRadius: '10px',
            textAlign: 'center',
          }}>
            <div style={{ fontSize: '28px', fontWeight: '700', color: 'var(--accent)' }}>
              {wallets.length}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Wallets
            </div>
          </div>
          <div
            onClick={() => navigate('/activity')}
            style={{
              padding: '20px',
              background: 'var(--bg-tertiary)',
              borderRadius: '10px',
              textAlign: 'center',
              cursor: 'pointer',
              transition: 'background 0.2s',
            }}
          >
            <div style={{ fontSize: '28px', fontWeight: '700', color: 'var(--text-secondary)' }}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
              </svg>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              View Activity
            </div>
          </div>
        </div>
      </div>

      {/* Empty state hint if no agents connected */}
      {activeAgents.length === 0 && pendingConsents.length === 0 && (
        <div className="card" style={{ textAlign: 'center', padding: '32px' }}>
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="1.5" style={{ marginBottom: '16px' }}>
            <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/>
            <polyline points="10 17 15 12 10 7"/>
            <line x1="15" y1="12" x2="3" y2="12"/>
          </svg>
          <h3 style={{ marginBottom: '8px', color: 'var(--text-secondary)' }}>No agents connected</h3>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '16px' }}>
            Connect an AI assistant to start using your vault
          </p>
          <button className="btn btn-primary" onClick={() => navigate('/connect')}>
            Connect Agent
          </button>
        </div>
      )}
    </div>
  );
}
