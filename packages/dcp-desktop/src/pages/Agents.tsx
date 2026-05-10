import { useEffect, useState, useCallback } from 'react';
import { api, type AgentConnection, type StoredPairingClaim, type Scope, type BudgetConfig } from '../api';

// Common scope categories for quick selection
// Scopes must include the operation prefix (read:/write:/sign:) to match authorization checks
const SCOPE_PRESETS = {
  identity: ['read:identity.name', 'read:identity.email', 'read:identity.phone'],
  signing: ['sign:solana'],
  credentials: ['read:credentials.api.*'],
};

export default function Agents() {
  const [agents, setAgents] = useState<AgentConnection[]>([]);
  const [pendingClaims, setPendingClaims] = useState<StoredPairingClaim[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'active' | 'revoked'>('all');
  const [environmentFilter, setEnvironmentFilter] = useState<'all' | 'local' | 'vps'>('all');
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  // Edit modal state
  const [editAgent, setEditAgent] = useState<AgentConnection | null>(null);
  const [editScopes, setEditScopes] = useState<string[]>([]);
  const [editBudgetDaily, setEditBudgetDaily] = useState<number>(100);
  const [editBudgetCurrency, setEditBudgetCurrency] = useState<string>('USDC');
  const [editAutoApprove, setEditAutoApprove] = useState<number>(5);
  const [availableScopes, setAvailableScopes] = useState<Scope[]>([]);
  const [defaultBudget, setDefaultBudget] = useState<BudgetConfig | null>(null);
  const [editSaving, setEditSaving] = useState(false);

  const loadAgents = useCallback(async () => {
    try {
      const [agentsRes, claimsRes] = await Promise.all([
        api.getAgentConnections(),
        api.getPairingClaims().catch(() => ({ claims: [] })),
      ]);
      setAgents(agentsRes.agents || []);
      setPendingClaims(claimsRes.claims || []);
    } catch (err) {
      console.error('Failed to load agents:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAgents();
    const interval = setInterval(loadAgents, 5000);
    return () => clearInterval(interval);
  }, [loadAgents]);

  // Load available scopes and default budget for edit modal
  useEffect(() => {
    const loadEditData = async () => {
      try {
        const [scopesRes, budgetRes] = await Promise.all([
          api.getScopes(),
          api.getBudgetConfig().catch(() => null),
        ]);
        setAvailableScopes(scopesRes.scopes || []);
        setDefaultBudget(budgetRes);
      } catch (err) {
        console.error('Failed to load edit data:', err);
      }
    };
    loadEditData();
  }, []);

  const handleEditAgent = (agent: AgentConnection) => {
    setEditAgent(agent);
    setEditScopes([...agent.permission_scopes]);
    // Prefill budget from agent or use defaults from settings
    // Use || instead of ?? so 0 falls back to defaults (0 usually means "not configured")
    const agentBudget = agent.budget;
    const currency = agentBudget?.currency || 'USDC';
    setEditBudgetDaily(agentBudget?.daily || defaultBudget?.daily_budget?.[currency] || 5);
    setEditBudgetCurrency(currency);
    setEditAutoApprove(agentBudget?.auto_approve_under || defaultBudget?.approval_threshold?.[currency] || 0.0001);
  };

  const handleSaveEdit = async () => {
    if (!editAgent) return;
    setEditSaving(true);
    try {
      await api.updateAgentConnection(editAgent.agent_id, {
        permission_scopes: editScopes,
        budget: {
          daily: editBudgetDaily,
          currency: editBudgetCurrency,
          auto_approve_under: editAutoApprove,
        },
      });
      setStatusMessage('Permissions updated successfully');
      setEditAgent(null);
      await loadAgents();
      setTimeout(() => setStatusMessage(null), 3000);
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : 'Failed to update permissions');
    } finally {
      setEditSaving(false);
    }
  };

  const toggleScope = (scope: string) => {
    setEditScopes(prev =>
      prev.includes(scope) ? prev.filter(s => s !== scope) : [...prev, scope]
    );
  };

  const toggleScopePreset = (presetScopes: string[]) => {
    const allIncluded = presetScopes.every(s => editScopes.includes(s));
    if (allIncluded) {
      setEditScopes(prev => prev.filter(s => !presetScopes.includes(s)));
    } else {
      setEditScopes(prev => [...new Set([...prev, ...presetScopes])]);
    }
  };

  const getAgentStatus = (agent: AgentConnection): { status: string; color: string; label: string } => {
    if (agent.status === 'revoked' || agent.revoked_at) {
      return { status: 'revoked', color: 'var(--danger)', label: 'Revoked' };
    }
    if (!agent.last_seen_at) {
      return { status: 'pending', color: 'var(--text-muted)', label: 'Pending' };
    }
    const lastSeen = new Date(agent.last_seen_at).getTime();
    const diffSeconds = (Date.now() - lastSeen) / 1000;
    if (diffSeconds < 60) return { status: 'active', color: 'var(--success)', label: 'Connected' };
    if (diffSeconds < 3600) return { status: 'stale', color: 'var(--warning)', label: 'Stale' };
    if (diffSeconds < 86400) return { status: 'idle', color: 'var(--text-secondary)', label: 'Idle' };
    return { status: 'inactive', color: 'var(--text-muted)', label: 'Inactive' };
  };

  const getEnvironment = (agent: AgentConnection): { type: 'local' | 'vps' | 'sandbox'; icon: string; label: string } => {
    if (agent.agent_id.startsWith('vps_')) {
      return { type: 'vps', icon: '🌐', label: 'Remote' };
    }
    if (agent.mode === 'mcp') {
      return { type: 'local', icon: '💻', label: 'Local AI' };
    }
    if (agent.tier === 'free') {
      return { type: 'sandbox', icon: '🧪', label: 'Sandbox' };
    }
    return { type: 'vps', icon: '🌐', label: 'VPS' };
  };

  const handleRevoke = async (agentId: string) => {
    setActionLoading(agentId);
    try {
      await api.revokeAgentConnection(agentId);
      await loadAgents();
      setStatusMessage('Agent access revoked');
      setTimeout(() => setStatusMessage(null), 3000);
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : 'Failed to revoke agent');
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteClick = (agentId: string) => {
    setConfirmDelete(agentId);
  };

  const handleDeleteConfirm = async () => {
    if (!confirmDelete) return;
    const agentId = confirmDelete;
    setConfirmDelete(null);
    setActionLoading(agentId);
    try {
      await api.deleteAgentConnection(agentId);
      await loadAgents();
      setSelectedAgent(null);
      setStatusMessage('Agent deleted');
      setTimeout(() => setStatusMessage(null), 3000);
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : 'Failed to delete agent');
    } finally {
      setActionLoading(null);
    }
  };

  const handleApproveClaim = async (claimId: string) => {
    setActionLoading(claimId);
    try {
      const result = await api.approvePairingClaim(claimId);
      setStatusMessage(`Agent "${result.agent_name}" approved and connected`);
      await loadAgents();
      setTimeout(() => setStatusMessage(null), 3000);
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : 'Failed to approve claim');
    } finally {
      setActionLoading(null);
    }
  };

  const handleDenyClaim = async (claimId: string) => {
    setActionLoading(claimId);
    try {
      await api.denyPairingClaim(claimId);
      setStatusMessage('Pairing request denied');
      await loadAgents();
      setTimeout(() => setStatusMessage(null), 3000);
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : 'Failed to deny claim');
    } finally {
      setActionLoading(null);
    }
  };

  const formatLastSeen = (dateStr?: string): string => {
    if (!dateStr) return 'Never';
    const date = new Date(dateStr);
    const diffMs = Date.now() - date.getTime();
    const diffSeconds = Math.floor(diffMs / 1000);

    if (diffSeconds < 60) return 'Just now';
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)} min ago`;
    if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)} hours ago`;
    return date.toLocaleDateString();
  };

  const filteredAgents = agents.filter(agent => {
    const { status } = getAgentStatus(agent);
    const env = getEnvironment(agent);

    // Status filter
    if (filter === 'active' && status === 'revoked') return false;
    if (filter === 'revoked' && status !== 'revoked') return false;

    // Environment filter
    if (environmentFilter === 'local' && env.type !== 'local') return false;
    if (environmentFilter === 'vps' && env.type !== 'vps' && env.type !== 'sandbox') return false;

    return true;
  });

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
      </div>
    );
  }

  const selectedAgentData = selectedAgent ? agents.find(a => a.agent_id === selectedAgent) : null;

  return (
    <div className="page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>Agents</h2>
          <p className="muted">Manage AI agents connected to your vault</p>
        </div>
        <button className="btn btn-secondary" onClick={loadAgents}>
          Refresh
        </button>
      </div>

      {/* Stats Bar */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '12px',
        marginBottom: '20px',
      }}>
        <div style={{
          padding: '16px',
          background: 'var(--bg-tertiary)',
          borderRadius: '8px',
          textAlign: 'center',
        }}>
          <div style={{ fontSize: '24px', fontWeight: '700', color: 'var(--accent)' }}>
            {agents.length}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Total Agents</div>
        </div>
        <div style={{
          padding: '16px',
          background: 'var(--bg-tertiary)',
          borderRadius: '8px',
          textAlign: 'center',
        }}>
          <div style={{ fontSize: '24px', fontWeight: '700', color: 'var(--success)' }}>
            {agents.filter(a => getAgentStatus(a).status === 'active').length}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Active</div>
        </div>
        <div style={{
          padding: '16px',
          background: 'var(--bg-tertiary)',
          borderRadius: '8px',
          textAlign: 'center',
        }}>
          <div style={{ fontSize: '24px', fontWeight: '700', color: 'var(--text-secondary)' }}>
            {agents.filter(a => getEnvironment(a).type === 'local').length}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Local</div>
        </div>
        <div style={{
          padding: '16px',
          background: 'var(--bg-tertiary)',
          borderRadius: '8px',
          textAlign: 'center',
        }}>
          <div style={{ fontSize: '24px', fontWeight: '700', color: 'var(--text-secondary)' }}>
            {agents.filter(a => getEnvironment(a).type !== 'local').length}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Remote</div>
        </div>
      </div>

      {/* Pending Pairing Claims */}
      {pendingClaims.length > 0 && (
        <div style={{
          marginBottom: '20px',
          padding: '16px',
          background: 'linear-gradient(135deg, rgba(255, 170, 0, 0.15), rgba(255, 100, 0, 0.1))',
          border: '1px solid rgba(255, 170, 0, 0.3)',
          borderRadius: '12px',
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            marginBottom: '12px',
          }}>
            <span style={{ fontSize: '20px' }}>🔔</span>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600 }}>
              Pending VPS Agent Requests ({pendingClaims.length})
            </h3>
          </div>
          <p style={{
            fontSize: '13px',
            color: 'var(--text-secondary)',
            marginBottom: '16px',
          }}>
            A remote VPS agent is requesting to connect to your vault. Verify the hostname and verification phrase before approving.
          </p>

          <div style={{ display: 'grid', gap: '12px' }}>
            {pendingClaims.map((claim) => (
              <div
                key={claim.claim_id}
                style={{
                  padding: '16px',
                  background: 'var(--bg-secondary)',
                  borderRadius: '8px',
                  border: '1px solid var(--border)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                      <span style={{ fontSize: '16px' }}>🌐</span>
                      <span style={{ fontWeight: 600, fontSize: '15px' }}>
                        {claim.claim.agent_hostname}
                      </span>
                      <span style={{
                        fontSize: '11px',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        background: 'rgba(255, 170, 0, 0.2)',
                        color: '#ffaa00',
                      }}>
                        Pending
                      </span>
                    </div>

                    <div style={{
                      fontFamily: 'monospace',
                      fontSize: '18px',
                      fontWeight: 700,
                      padding: '8px 12px',
                      background: 'var(--bg-tertiary)',
                      borderRadius: '6px',
                      marginBottom: '8px',
                      display: 'inline-block',
                      letterSpacing: '2px',
                    }}>
                      {claim.verification_phrase}
                    </div>

                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Version: {claim.claim.agent_version} •
                      Requested: {new Date(claim.received_at).toLocaleTimeString()}
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      className="btn btn-primary"
                      style={{ padding: '8px 16px', fontSize: '13px' }}
                      onClick={() => handleApproveClaim(claim.claim_id)}
                      disabled={actionLoading === claim.claim_id}
                    >
                      {actionLoading === claim.claim_id ? '...' : 'Approve'}
                    </button>
                    <button
                      className="btn btn-danger"
                      style={{ padding: '8px 16px', fontSize: '13px' }}
                      onClick={() => handleDenyClaim(claim.claim_id)}
                      disabled={actionLoading === claim.claim_id}
                    >
                      {actionLoading === claim.claim_id ? '...' : 'Deny'}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div style={{ display: 'flex', gap: '16px', marginBottom: '20px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Status:</span>
          {(['all', 'active', 'revoked'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`btn ${filter === f ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '6px 12px', fontSize: '12px' }}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Environment:</span>
          {(['all', 'local', 'vps'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setEnvironmentFilter(f)}
              className={`btn ${environmentFilter === f ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '6px 12px', fontSize: '12px' }}
            >
              {f === 'vps' ? 'VPS/Remote' : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Status Message */}
      {statusMessage && (
        <div style={{
          padding: '12px 16px',
          background: 'var(--bg-tertiary)',
          borderRadius: '8px',
          marginBottom: '16px',
          fontSize: '13px',
          color: 'var(--text-secondary)',
        }}>
          {statusMessage}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: selectedAgentData ? '1fr 350px' : '1fr', gap: '20px' }}>
        {/* Agent List */}
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Connected Agents</h3>
              <p className="card-subtitle">{filteredAgents.length} agents</p>
            </div>
          </div>

          {filteredAgents.length === 0 ? (
            <div className="empty-state">
              <p>No agents match the current filters</p>
            </div>
          ) : (
            <div style={{ display: 'grid', gap: '8px' }}>
              {filteredAgents.map((agent) => {
                const { status, color, label } = getAgentStatus(agent);
                const env = getEnvironment(agent);
                const isSelected = selectedAgent === agent.agent_id;

                return (
                  <div
                    key={agent.agent_id}
                    onClick={() => setSelectedAgent(isSelected ? null : agent.agent_id)}
                    style={{
                      padding: '16px',
                      background: isSelected ? 'var(--bg-secondary)' : 'var(--bg-tertiary)',
                      border: `1px solid ${isSelected ? 'var(--accent)' : 'var(--border)'}`,
                      borderRadius: '8px',
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                          <span style={{ fontSize: '18px' }}>{env.icon}</span>
                          <span style={{ fontWeight: 600, fontSize: '15px' }}>
                            {agent.name || agent.agent_name}
                          </span>
                          <span style={{
                            fontSize: '11px',
                            padding: '2px 8px',
                            borderRadius: '4px',
                            background: color,
                            color: status === 'active' ? '#000' : '#fff',
                          }}>
                            {label}
                          </span>
                          <span style={{
                            fontSize: '11px',
                            padding: '2px 8px',
                            borderRadius: '4px',
                            background: 'var(--bg-secondary)',
                            color: 'var(--text-muted)',
                          }}>
                            {env.label}
                          </span>
                        </div>

                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginBottom: '8px' }}>
                          {agent.permission_scopes.slice(0, 4).map((scope) => (
                            <span
                              key={scope}
                              style={{
                                fontSize: '11px',
                                padding: '2px 6px',
                                borderRadius: '4px',
                                background: 'var(--bg-secondary)',
                                color: 'var(--text-secondary)',
                              }}
                            >
                              {scope.replace(':', ': ')}
                            </span>
                          ))}
                          {agent.permission_scopes.length > 4 && (
                            <span style={{
                              fontSize: '11px',
                              padding: '2px 6px',
                              borderRadius: '4px',
                              background: 'var(--bg-secondary)',
                              color: 'var(--text-muted)',
                            }}>
                              +{agent.permission_scopes.length - 4} more
                            </span>
                          )}
                        </div>

                        <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          Last seen: {formatLastSeen(agent.last_seen_at)}
                          {(agent.request_count ?? 0) > 0 && (
                            <span style={{ marginLeft: '12px' }}>
                              {agent.request_count} requests
                            </span>
                          )}
                        </div>
                      </div>

                      <div style={{ display: 'flex', gap: '6px' }} onClick={(e) => e.stopPropagation()}>
                        {status !== 'revoked' && (
                          <button
                            className="btn btn-secondary"
                            style={{ padding: '6px 10px', fontSize: '12px' }}
                            onClick={() => handleRevoke(agent.agent_id)}
                            disabled={actionLoading === agent.agent_id}
                          >
                            {actionLoading === agent.agent_id ? '...' : 'Revoke'}
                          </button>
                        )}
                        <button
                          className="btn btn-danger"
                          style={{ padding: '6px 10px', fontSize: '12px' }}
                          onClick={() => handleDeleteClick(agent.agent_id)}
                          disabled={actionLoading === agent.agent_id}
                        >
                          {actionLoading === agent.agent_id ? '...' : 'Delete'}
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Agent Detail Panel */}
        {selectedAgentData && (
          <div className="card" style={{ height: 'fit-content' }}>
            <div className="card-header">
              <div>
                <h3 className="card-title">{selectedAgentData.name || selectedAgentData.agent_name}</h3>
                <p className="card-subtitle">Agent Details</p>
              </div>
              <button
                className="btn btn-secondary"
                style={{ padding: '4px 8px', fontSize: '12px' }}
                onClick={() => setSelectedAgent(null)}
              >
                Close
              </button>
            </div>

            <div style={{ display: 'grid', gap: '16px' }}>
              {/* Status */}
              <div style={{
                padding: '12px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
              }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                  Status
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    background: getAgentStatus(selectedAgentData).color,
                  }} />
                  <span style={{ fontWeight: 600 }}>
                    {getAgentStatus(selectedAgentData).label}
                  </span>
                </div>
              </div>

              {/* Environment */}
              <div style={{
                padding: '12px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
              }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                  Environment
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>{getEnvironment(selectedAgentData).icon}</span>
                  <span>{getEnvironment(selectedAgentData).label}</span>
                  <span style={{
                    fontSize: '11px',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: 'var(--bg-secondary)',
                    color: 'var(--text-muted)',
                  }}>
                    {selectedAgentData.mode.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Permissions */}
              <div style={{
                padding: '12px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
              }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                  Permissions ({selectedAgentData.permission_scopes.length})
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                  {selectedAgentData.permission_scopes.map((scope) => (
                    <span
                      key={scope}
                      style={{
                        fontSize: '11px',
                        padding: '4px 8px',
                        borderRadius: '4px',
                        background: 'var(--bg-secondary)',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {scope}
                    </span>
                  ))}
                </div>
              </div>

              {/* Metadata */}
              <div style={{
                padding: '12px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
              }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                  Activity
                </div>
                <div style={{ display: 'grid', gap: '8px', fontSize: '13px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Paired</span>
                    <span>{new Date(selectedAgentData.paired_at).toLocaleDateString()}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Last Seen</span>
                    <span>{formatLastSeen(selectedAgentData.last_seen_at)}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Requests</span>
                    <span>{selectedAgentData.request_count ?? 0}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Tier</span>
                    <span style={{ textTransform: 'capitalize' }}>{selectedAgentData.tier}</span>
                  </div>
                </div>
              </div>

              {/* Budget */}
              {selectedAgentData.budget && (
                <div style={{
                  padding: '12px',
                  background: 'var(--bg-tertiary)',
                  borderRadius: '8px',
                }}>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                    Budget
                  </div>
                  <div style={{ display: 'grid', gap: '6px', fontSize: '13px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>Daily limit</span>
                      <span>{selectedAgentData.budget.daily} {selectedAgentData.budget.currency}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>Auto-approve under</span>
                      <span>{selectedAgentData.budget.auto_approve_under} {selectedAgentData.budget.currency}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Agent ID */}
              <div style={{
                padding: '12px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
              }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                  Agent ID
                </div>
                <code style={{
                  fontSize: '11px',
                  color: 'var(--text-secondary)',
                  wordBreak: 'break-all',
                }}>
                  {selectedAgentData.agent_id}
                </code>
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', gap: '8px', flexDirection: 'column' }}>
                {getAgentStatus(selectedAgentData).status !== 'revoked' && (
                  <button
                    className="btn btn-primary"
                    style={{ width: '100%' }}
                    onClick={() => handleEditAgent(selectedAgentData)}
                  >
                    Edit Permissions
                  </button>
                )}
                <div style={{ display: 'flex', gap: '8px' }}>
                  {getAgentStatus(selectedAgentData).status !== 'revoked' && (
                    <button
                      className="btn btn-secondary"
                      style={{ flex: 1 }}
                      onClick={() => handleRevoke(selectedAgentData.agent_id)}
                      disabled={actionLoading === selectedAgentData.agent_id}
                    >
                      {actionLoading === selectedAgentData.agent_id ? 'Revoking...' : 'Revoke'}
                    </button>
                  )}
                  <button
                    className="btn btn-danger"
                    style={{ flex: 1 }}
                    onClick={() => handleDeleteClick(selectedAgentData.agent_id)}
                    disabled={actionLoading === selectedAgentData.agent_id}
                  >
                    {actionLoading === selectedAgentData.agent_id ? 'Deleting...' : 'Delete'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Edit Permissions Modal */}
      {editAgent && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
        }}>
          <div style={{
            background: 'var(--bg-secondary)',
            borderRadius: '12px',
            padding: '24px',
            maxWidth: '500px',
            width: '90%',
            maxHeight: '80vh',
            overflow: 'auto',
            border: '1px solid var(--border)',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <h3 style={{ margin: 0, fontSize: '18px' }}>Edit Permissions</h3>
              <button
                className="btn btn-secondary"
                style={{ padding: '4px 8px', fontSize: '12px' }}
                onClick={() => setEditAgent(null)}
              >
                Close
              </button>
            </div>

            <div style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              {editAgent.name || editAgent.agent_name}
            </div>

            {/* Quick Presets */}
            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                Quick Presets
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                <button
                  className={`btn ${SCOPE_PRESETS.identity.every(s => editScopes.includes(s)) ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                  onClick={() => toggleScopePreset(SCOPE_PRESETS.identity)}
                >
                  Identity (name, email)
                </button>
                <button
                  className={`btn ${SCOPE_PRESETS.signing.some(s => editScopes.includes(s)) ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                  onClick={() => toggleScopePreset(SCOPE_PRESETS.signing)}
                >
                  Signing (crypto)
                </button>
                <button
                  className={`btn ${SCOPE_PRESETS.credentials.some(s => editScopes.includes(s)) ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                  onClick={() => toggleScopePreset(SCOPE_PRESETS.credentials)}
                >
                  API Credentials
                </button>
              </div>
            </div>

            {/* Scopes */}
            <div style={{ marginBottom: '20px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                Allowed Scopes ({editScopes.length} selected)
              </div>
              <div style={{
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
                padding: '12px',
                maxHeight: '200px',
                overflowY: 'auto',
              }}>
                {availableScopes.length === 0 ? (
                  <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                    No scopes available. Add data to your vault first.
                  </div>
                ) : (
                  <div style={{ display: 'grid', gap: '8px' }}>
                    {availableScopes.map(scope => (
                      <label
                        key={scope.scope}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '10px',
                          cursor: 'pointer',
                          padding: '6px 8px',
                          borderRadius: '6px',
                          background: editScopes.includes(scope.scope) ? 'var(--bg-secondary)' : 'transparent',
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={editScopes.includes(scope.scope)}
                          onChange={() => toggleScope(scope.scope)}
                          style={{ width: '16px', height: '16px' }}
                        />
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: '13px', fontWeight: 500 }}>{scope.scope}</div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                            {scope.type} • {scope.sensitivity}
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Budget Settings */}
            <div style={{ marginBottom: '20px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                Budget Settings
              </div>
              <div style={{
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
                padding: '12px',
                display: 'grid',
                gap: '12px',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <label style={{ flex: 1, fontSize: '13px' }}>Daily limit</label>
                  <input
                    type="number"
                    value={editBudgetDaily}
                    onChange={(e) => setEditBudgetDaily(Number(e.target.value))}
                    style={{
                      width: '100px',
                      padding: '8px',
                      borderRadius: '6px',
                      border: '1px solid var(--border)',
                      background: 'var(--bg-secondary)',
                      color: 'var(--text-primary)',
                      textAlign: 'right',
                    }}
                    min={0}
                  />
                  <select
                    value={editBudgetCurrency}
                    onChange={(e) => setEditBudgetCurrency(e.target.value)}
                    style={{
                      padding: '8px',
                      borderRadius: '6px',
                      border: '1px solid var(--border)',
                      background: 'var(--bg-secondary)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    <option value="SOL">SOL</option>
                    <option value="USDC">USDC</option>
                    <option value="USDT">USDT</option>
                    <option value="1LY">1LY</option>
                  </select>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <label style={{ flex: 1, fontSize: '13px' }}>Auto-approve under</label>
                  <input
                    type="number"
                    value={editAutoApprove}
                    onChange={(e) => setEditAutoApprove(Number(e.target.value))}
                    style={{
                      width: '100px',
                      padding: '8px',
                      borderRadius: '6px',
                      border: '1px solid var(--border)',
                      background: 'var(--bg-secondary)',
                      color: 'var(--text-primary)',
                      textAlign: 'right',
                    }}
                    min={0}
                  />
                  <span style={{ width: '60px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                    {editBudgetCurrency}
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  Transactions under the auto-approve threshold will be approved automatically.
                </div>
              </div>
            </div>

            {/* Actions */}
            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <button
                className="btn btn-secondary"
                onClick={() => setEditAgent(null)}
                disabled={editSaving}
              >
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={handleSaveEdit}
                disabled={editSaving}
              >
                {editSaving ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {confirmDelete && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
        }}>
          <div style={{
            background: 'var(--bg-secondary)',
            borderRadius: '12px',
            padding: '24px',
            maxWidth: '400px',
            width: '90%',
            border: '1px solid var(--border)',
          }}>
            <h3 style={{ margin: '0 0 12px 0', fontSize: '18px' }}>Delete Agent?</h3>
            <p style={{ margin: '0 0 20px 0', color: 'var(--text-secondary)', fontSize: '14px' }}>
              Are you sure you want to delete this agent? This action cannot be undone.
            </p>
            <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <button
                className="btn btn-secondary"
                onClick={() => setConfirmDelete(null)}
              >
                Cancel
              </button>
              <button
                className="btn btn-danger"
                onClick={handleDeleteConfirm}
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
