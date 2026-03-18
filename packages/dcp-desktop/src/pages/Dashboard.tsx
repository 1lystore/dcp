import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, type Agent, type Scope, type PendingConsent } from '../api';

export default function Dashboard() {
  const navigate = useNavigate();
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [pendingConsents, setPendingConsents] = useState<PendingConsent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [scopesRes, agentsRes, consentsRes] = await Promise.all([
        api.getScopes(),
        api.getAgents(),
        api.getPendingConsents(),
      ]);
      setScopes(scopesRes.scopes);
      setAgents(agentsRes.agents);
      setPendingConsents(consentsRes.pending);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setLoading(false);
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

  return (
    <div>
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Vault Status</h2>
            <p className="card-subtitle">Your vault is unlocked and ready</p>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
          <div style={{ padding: '16px', background: 'var(--bg-tertiary)', borderRadius: '10px', textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: '700', color: 'var(--accent)' }}>{wallets.length}</div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Wallets</div>
          </div>
          <div style={{ padding: '16px', background: 'var(--bg-tertiary)', borderRadius: '10px', textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: '700', color: 'var(--success)' }}>{agents.length}</div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Active Sessions</div>
          </div>
          <div style={{ padding: '16px', background: 'var(--bg-tertiary)', borderRadius: '10px', textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: '700', color: pendingConsents.length > 0 ? 'var(--warning)' : 'var(--text-secondary)' }}>
              {pendingConsents.length}
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Pending Consents</div>
          </div>
        </div>

        {pendingConsents.length > 0 && (
          <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end' }}>
            <button className="btn btn-primary" onClick={() => navigate('/consent')}>
              Review Consents
            </button>
          </div>
        )}
      </div>

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
          wallets.map((wallet) => (
            <div key={wallet.scope} className="wallet-card">
              <div className="wallet-info">
                <div>
                  <div className="wallet-chain" style={{ textTransform: 'capitalize' }}>
                    {wallet.chain}
                  </div>
                  <div className="wallet-address">
                    {wallet.public_address}
                  </div>
                </div>
              </div>
              <span className="pill">{wallet.sensitivity}</span>
            </div>
          ))
        )}
      </div>

      {agents.length > 0 && (
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Active Agent Sessions</h2>
              <p className="card-subtitle">Currently authorized agents</p>
            </div>
          </div>

          {agents.map((agent) => (
            <div key={agent.id} className="consent-item">
              <div className="consent-header">
                <span className="consent-agent">{agent.agent_name}</span>
                <span className="pill">{agent.consent_mode}</span>
              </div>
              <div className="consent-details">
                Scopes: {agent.granted_scopes.join(', ')}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Expires: {new Date(agent.expires_at).toLocaleString()}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
