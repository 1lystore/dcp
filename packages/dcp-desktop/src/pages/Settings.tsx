import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, type Agent, type BudgetConfig, type AuditEvent } from '../api';

export default function Settings() {
  const navigate = useNavigate();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [budgetConfig, setBudgetConfig] = useState<BudgetConfig | null>(null);
  const [budgetLoading, setBudgetLoading] = useState(true);
  const [budgetSaving, setBudgetSaving] = useState(false);
  const [budgetError, setBudgetError] = useState<string | null>(null);
  const [activity, setActivity] = useState<AuditEvent[]>([]);
  const [activityLoading, setActivityLoading] = useState(true);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const currencyOptions = ['SOL', 'ETH', 'USDC', 'USDT', 'BASE_ETH'];

  useEffect(() => {
    loadAgents();
    loadBudgets();
    loadActivity();
  }, []);

  const loadAgents = async () => {
    try {
      const res = await api.getAgents();
      setAgents(res.agents);
    } catch (err) {
      console.error('Failed to load agents:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadBudgets = async () => {
    try {
      const res = await api.getBudgetConfig();
      setBudgetConfig(res);
      setBudgetError(null);
    } catch (err) {
      console.error('Failed to load budget config:', err);
      setBudgetError(err instanceof Error ? err.message : 'Failed to load');
    } finally {
      setBudgetLoading(false);
    }
  };

  const loadActivity = async () => {
    try {
      const res = await api.getActivity(20);
      setActivity(res.events);
    } catch (err) {
      console.error('Failed to load activity:', err);
    } finally {
      setActivityLoading(false);
    }
  };

  const handleBudgetChange = (
    type: keyof BudgetConfig,
    currency: string,
    value: string
  ) => {
    if (!budgetConfig) return;
    const parsed = Number(value);
    setBudgetConfig({
      ...budgetConfig,
      [type]: {
        ...budgetConfig[type],
        [currency]: Number.isNaN(parsed) ? 0 : parsed,
      },
    });
  };

  const handleSaveBudgets = async () => {
    if (!budgetConfig) return;
    setBudgetSaving(true);
    try {
      const updated = await api.updateBudgetConfig(budgetConfig);
      setBudgetConfig(updated);
      setBudgetError(null);
    } catch (err) {
      console.error('Failed to save budgets:', err);
      setBudgetError('Failed to save');
    } finally {
      setBudgetSaving(false);
    }
  };

  const handleRevokeSession = async (id: string) => {
    setRevoking(id);
    try {
      await api.revokeSession(id);
      await loadAgents();
    } catch (err) {
      console.error('Failed to revoke session:', err);
    } finally {
      setRevoking(null);
    }
  };

  const handleRevokeAgent = async (agentName: string) => {
    setRevoking(agentName);
    try {
      await api.revokeAgent(agentName);
      await loadAgents();
    } catch (err) {
      console.error('Failed to revoke agent:', err);
    } finally {
      setRevoking(null);
    }
  };

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
      </div>
    );
  }

  const agentGroups = agents.reduce((acc, agent) => {
    if (!acc[agent.agent_name]) acc[agent.agent_name] = [];
    acc[agent.agent_name].push(agent);
    return acc;
  }, {} as Record<string, Agent[]>);

  const eventIcons: Record<string, string> = {
    GRANT: '+',
    DENY: '-',
    EXECUTE: '*',
    READ: '.',
    REVOKE: 'x',
    CONFIG: '#',
    EXPIRE: '~',
  };

  return (
    <div>
      {/* Vault Info */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Settings</h2>
            <p className="card-subtitle">Manage your vault configuration</p>
          </div>
        </div>

        <div style={{
          padding: '12px 16px',
          background: 'var(--bg-tertiary)',
          borderRadius: '8px',
          fontSize: '13px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ color: 'var(--text-secondary)' }}>Vault Location</span>
            <code>~/.dcp</code>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--text-secondary)' }}>Server URL</span>
            <code>http://127.0.0.1:8421</code>
          </div>
        </div>
      </div>

      {/* Budgets - Simplified */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Spending Limits</h2>
            <p className="card-subtitle">Daily budgets and auto-approve thresholds</p>
          </div>
        </div>

        {budgetError && (
          <div style={{
            padding: '12px',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '8px',
            color: '#fca5a5',
            fontSize: '13px',
            marginBottom: '16px'
          }}>
            {budgetError}
          </div>
        )}

        {budgetLoading || !budgetConfig ? (
          <div className="loading">
            <div className="spinner" />
          </div>
        ) : (
          <div style={{ display: 'grid', gap: '12px' }}>
            {currencyOptions.map((currency) => (
              <div
                key={currency}
                style={{
                  padding: '12px 16px',
                  background: 'var(--bg-tertiary)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                }}
              >
                <div style={{ fontSize: '13px', fontWeight: 600, marginBottom: '8px' }}>{currency}</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                  <div>
                    <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Daily Limit</label>
                    <input
                      className="input"
                      type="number"
                      min="0"
                      value={budgetConfig.daily_budget[currency] ?? 0}
                      onChange={(e) => handleBudgetChange('daily_budget', currency, e.target.value)}
                      style={{ marginTop: '4px' }}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Per Transaction</label>
                    <input
                      className="input"
                      type="number"
                      min="0"
                      value={budgetConfig.tx_limit[currency] ?? 0}
                      onChange={(e) => handleBudgetChange('tx_limit', currency, e.target.value)}
                      style={{ marginTop: '4px' }}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Auto-approve under</label>
                    <input
                      className="input"
                      type="number"
                      min="0"
                      value={budgetConfig.approval_threshold[currency] ?? 0}
                      onChange={(e) => handleBudgetChange('approval_threshold', currency, e.target.value)}
                      style={{ marginTop: '4px' }}
                    />
                  </div>
                </div>
              </div>
            ))}
            <button
              className="btn btn-primary"
              onClick={handleSaveBudgets}
              disabled={budgetSaving}
              style={{ alignSelf: 'flex-start' }}
            >
              {budgetSaving ? 'Saving...' : 'Save Limits'}
            </button>
          </div>
        )}
      </div>

      {/* Active Sessions */}
      {agents.length > 0 && (
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Active Sessions</h2>
              <p className="card-subtitle">Authorized agent sessions</p>
            </div>
            <button className="btn btn-secondary" onClick={loadAgents}>
              Refresh
            </button>
          </div>

          {Object.entries(agentGroups).map(([agentName, sessions]) => (
            <div key={agentName} style={{ marginBottom: '16px' }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '8px'
              }}>
                <span style={{ fontSize: '14px', fontWeight: 600 }}>{agentName}</span>
                <button
                  className="btn btn-danger"
                  onClick={() => handleRevokeAgent(agentName)}
                  disabled={revoking === agentName}
                  style={{ padding: '4px 10px', fontSize: '12px' }}
                >
                  {revoking === agentName ? '...' : 'Revoke All'}
                </button>
              </div>

              {sessions.map((session) => (
                <div
                  key={session.id}
                  style={{
                    padding: '10px 14px',
                    background: 'var(--bg-tertiary)',
                    border: '1px solid var(--border)',
                    borderRadius: '8px',
                    marginBottom: '6px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      {session.granted_scopes.join(', ')}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                      Expires: {new Date(session.expires_at).toLocaleString()}
                    </div>
                  </div>
                  <button
                    className="btn btn-secondary"
                    onClick={() => handleRevokeSession(session.id)}
                    disabled={revoking === session.id}
                    style={{ padding: '4px 10px', fontSize: '11px' }}
                  >
                    Revoke
                  </button>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {/* Recent Activity */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Recent Activity</h2>
            <p className="card-subtitle">Last 20 events</p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button className="btn btn-secondary" onClick={loadActivity}>
              Refresh
            </button>
            <button className="btn btn-secondary" onClick={() => navigate('/activity')}>
              View All
            </button>
          </div>
        </div>

        {activityLoading ? (
          <div className="loading">
            <div className="spinner" />
          </div>
        ) : activity.length === 0 ? (
          <div className="empty-state">
            <p>No activity yet</p>
          </div>
        ) : (
          <div style={{ maxHeight: '300px', overflow: 'auto' }}>
            {activity.map((event) => (
              <div
                key={event.id}
                style={{
                  padding: '8px 12px',
                  borderBottom: '1px solid var(--border)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  fontSize: '12px',
                }}
              >
                <span style={{
                  width: '20px',
                  height: '20px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  background: 'var(--bg-tertiary)',
                  borderRadius: '4px',
                  fontFamily: 'monospace',
                  fontWeight: 600,
                }}>
                  {eventIcons[event.event_type] || '?'}
                </span>
                <div style={{ flex: 1 }}>
                  <span style={{ fontWeight: 500 }}>{event.event_type}</span>
                  {event.agent_name && (
                    <span style={{ color: 'var(--text-muted)', marginLeft: '8px' }}>
                      {event.agent_name}
                    </span>
                  )}
                  {event.scope && (
                    <span style={{ color: 'var(--text-muted)', marginLeft: '8px' }}>
                      {event.scope}
                    </span>
                  )}
                </div>
                <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                  {new Date(event.created_at).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Advanced Settings - Collapsed */}
      <div className="card">
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          style={{
            width: '100%',
            padding: '16px',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            color: 'inherit',
          }}
        >
          <span style={{ fontWeight: 600 }}>Advanced Settings</span>
          <span style={{ color: 'var(--text-muted)' }}>
            {showAdvanced ? '-' : '+'}
          </span>
        </button>

        {showAdvanced && (
          <div style={{ padding: '0 16px 16px' }}>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '12px' }}>
              For power users: trusted services, relay configuration, and manual overrides.
            </div>
            <div style={{ display: 'grid', gap: '8px' }}>
              <div style={{
                padding: '12px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
                fontSize: '13px',
              }}>
                <strong>Trusted Services:</strong> Manage which apps can access your vault without per-request consent.
                <div style={{ marginTop: '8px' }}>
                  <button className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '12px' }}>
                    Manage Services
                  </button>
                </div>
              </div>
              <div style={{
                padding: '12px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
                fontSize: '13px',
              }}>
                <strong>Relay Configuration:</strong> Custom relay server for remote agent connections.
                <div style={{ marginTop: '8px', fontSize: '12px', color: 'var(--text-muted)' }}>
                  Default: wss://relay.dcp.1ly.store
                </div>
              </div>
              <div style={{
                padding: '12px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
                fontSize: '13px',
              }}>
                <strong>Recovery Phrase:</strong> View your 12-word recovery phrase.
                <div style={{ marginTop: '8px' }}>
                  <button className="btn btn-danger" style={{ padding: '6px 12px', fontSize: '12px' }}>
                    Show Recovery Phrase
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
