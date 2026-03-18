import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { open } from '@tauri-apps/plugin-shell';
import {
  api,
  type Agent,
  type TrustedService,
  type KnownService,
  type BudgetConfig,
} from '../api';

export default function Settings() {
  const navigate = useNavigate();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [services, setServices] = useState<TrustedService[]>([]);
  const [serviceLoading, setServiceLoading] = useState(true);
  const [serviceError, setServiceError] = useState<string | null>(null);
  const [serviceSaving, setServiceSaving] = useState(false);
  const [editingService, setEditingService] = useState<string | null>(null);
  const [knownServices, setKnownServices] = useState<KnownService[]>([]);
  const [selectedKnownService, setSelectedKnownService] = useState<string>('custom');
  const [budgetConfig, setBudgetConfig] = useState<BudgetConfig | null>(null);
  const [budgetLoading, setBudgetLoading] = useState(true);
  const [budgetSaving, setBudgetSaving] = useState(false);
  const [budgetError, setBudgetError] = useState<string | null>(null);
  const [serviceForm, setServiceForm] = useState({
    service_id: '',
    name: '',
    public_key: '',
    scopes: 'sign:solana',
    budget_daily: '10',
    budget_currency: 'USDC',
    auto_approve_under: '0',
    enabled: true,
    verified: false,
  });

  const currencyOptions = useMemo(() => ['SOL', 'ETH', 'USDC', 'USDT', 'BASE_ETH'], []);
  const scopePresets = useMemo(() => ([
    {
      id: 'sign-solana',
      label: 'Sign Solana transactions',
      scope: 'sign:solana',
      category: 'Signing',
      description: 'Allows signing Solana messages and transactions.',
    },
    {
      id: 'sign-base',
      label: 'Sign Base transactions',
      scope: 'sign:base',
      category: 'Signing',
      description: 'Allows signing Base (EVM) messages and transactions.',
    },
    {
      id: 'sign-ethereum',
      label: 'Sign Ethereum transactions',
      scope: 'sign:ethereum',
      category: 'Signing',
      description: 'Allows signing Ethereum (EVM) messages and transactions.',
    },
    {
      id: 'read-keys',
      label: 'Read API keys',
      scope: 'read:credentials.api.*',
      category: 'Read Data',
      description: 'Allows access to saved API keys.',
    },
    {
      id: 'read-profile',
      label: 'Read identity',
      scope: 'read:identity.*',
      category: 'Read Data',
      description: 'Name, email, phone, birthday.',
    },
    {
      id: 'read-address',
      label: 'Read addresses',
      scope: 'read:address.*',
      category: 'Read Data',
      description: 'Home and work addresses.',
    },
    {
      id: 'read-preferences',
      label: 'Read preferences',
      scope: 'read:preferences.*',
      category: 'Read Data',
      description: 'Sizes, diet, brands.',
    },
    {
      id: 'write-keys',
      label: 'Write API keys',
      scope: 'write:credentials.api.*',
      category: 'Write Data',
      description: 'Allows saving or updating API keys.',
    },
    {
      id: 'write-profile',
      label: 'Write identity',
      scope: 'write:identity.*',
      category: 'Write Data',
      description: 'Allows updating name/email/phone/birthday.',
    },
    {
      id: 'write-address',
      label: 'Write addresses',
      scope: 'write:address.*',
      category: 'Write Data',
      description: 'Allows updating addresses.',
    },
    {
      id: 'write-preferences',
      label: 'Write preferences',
      scope: 'write:preferences.*',
      category: 'Write Data',
      description: 'Allows updating preferences.',
    },
    {
      id: 'budget-check',
      label: 'Budget checks',
      scope: 'budget:check',
      category: 'Other',
      description: 'Allows checking remaining budget without signing.',
    },
  ]), []);
  const scopesList = useMemo(() => (
    serviceForm.scopes
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
  ), [serviceForm.scopes]);
  const scopeGroups = useMemo(() => {
    const groups: Record<string, typeof scopePresets> = {};
    scopePresets.forEach((preset) => {
      if (!groups[preset.category]) {
        groups[preset.category] = [];
      }
      groups[preset.category].push(preset);
    });
    return Object.entries(groups);
  }, [scopePresets]);
  const knownServiceMap = useMemo(() => {
    const map = new Map<string, KnownService>();
    knownServices.forEach((service) => map.set(service.service_id, service));
    return map;
  }, [knownServices]);

  useEffect(() => {
    loadAgents();
    loadServices();
    loadKnownServices();
    loadBudgets();
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

  const loadServices = async () => {
    try {
      const res = await api.getTrustedServices();
      setServices(res.services || []);
      setServiceError(null);
    } catch (err) {
      console.error('Failed to load trusted services:', err);
      const message = err instanceof Error ? err.message : 'Failed to load trusted services';
      setServiceError(message);
    } finally {
      setServiceLoading(false);
    }
  };

  const loadKnownServices = async () => {
    try {
      const res = await api.getKnownServices();
      setKnownServices(res.services || []);
    } catch (err) {
      console.error('Failed to load known services:', err);
    }
  };

  const loadBudgets = async () => {
    try {
      const res = await api.getBudgetConfig();
      setBudgetConfig(res);
      setBudgetError(null);
    } catch (err) {
      console.error('Failed to load budget config:', err);
      const message = err instanceof Error ? err.message : 'Failed to load budget configuration';
      setBudgetError(message);
    } finally {
      setBudgetLoading(false);
    }
  };

  const handleOwnerAuth = async () => {
    setServiceError(null);
    setBudgetError(null);
    const ok = await api.authenticateOwner();
    if (ok) {
      await Promise.all([loadServices(), loadBudgets()]);
    } else {
      setServiceError('Owner authentication failed. Restart the app and try again.');
      setBudgetError('Owner authentication failed. Restart the app and try again.');
    }
  };

  const resetServiceForm = () => {
    setEditingService(null);
    setSelectedKnownService('custom');
    setServiceForm({
      service_id: '',
      name: '',
      public_key: '',
      scopes: 'sign:solana',
      budget_daily: '10',
      budget_currency: 'USDC',
      auto_approve_under: '0',
      enabled: true,
      verified: false,
    });
  };

  const applyKnownService = (serviceId: string) => {
    setSelectedKnownService(serviceId);
    const known = knownServiceMap.get(serviceId);
    if (!known) {
      resetServiceForm();
      return;
    }
    setEditingService(null);
    setServiceForm({
      service_id: known.service_id,
      name: known.name,
      public_key: known.public_key,
      scopes: known.default_scopes.join(', '),
      budget_daily: '10',
      budget_currency: 'USDC',
      auto_approve_under: '0',
      enabled: true,
      verified: known.verified,
    });
  };

  const startEditService = (service: TrustedService) => {
    setEditingService(service.service_id);
    setSelectedKnownService('custom');
    setServiceForm({
      service_id: service.service_id,
      name: service.name,
      public_key: '',
      scopes: service.scopes.join(', '),
      budget_daily: String(service.budget.daily),
      budget_currency: service.budget.currency,
      auto_approve_under: String(service.budget.auto_approve_under ?? 0),
      enabled: service.enabled,
      verified: service.verified,
    });
  };

  const toggleScope = (scope: string) => {
    setServiceForm((prev) => {
      const existing = prev.scopes
        .split(',')
        .map((item) => item.trim())
        .filter((item) => item.length > 0);
      const hasScope = existing.includes(scope);
      const updated = hasScope
        ? existing.filter((item) => item !== scope)
        : [...existing, scope];
      return {
        ...prev,
        scopes: updated.join(', '),
      };
    });
  };

  const handleSaveService = async () => {
    setServiceSaving(true);
    try {
      const scopes = serviceForm.scopes
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);

      const budgetDaily = Number(serviceForm.budget_daily);
      const autoApprove = Number(serviceForm.auto_approve_under);

      if (!serviceForm.service_id.trim()) {
        throw new Error('Service ID is required');
      }
      if (!editingService && !serviceForm.public_key.trim()) {
        throw new Error('Public key is required');
      }
      if (scopes.length === 0) {
        throw new Error('At least one scope is required');
      }

      const payload = {
        service_id: serviceForm.service_id.trim(),
        name: serviceForm.name.trim() || serviceForm.service_id.trim(),
        public_key: serviceForm.public_key.trim(),
        scopes,
        budget: {
          daily: Number.isNaN(budgetDaily) ? 10 : budgetDaily,
          currency: serviceForm.budget_currency,
          auto_approve_under: Number.isNaN(autoApprove) ? 0 : autoApprove,
        },
        enabled: serviceForm.enabled,
        verified: serviceForm.verified,
      };

      if (editingService) {
        const updates: {
          name?: string;
          public_key?: string;
          scopes?: string[];
          budget?: { daily: number; currency: string; auto_approve_under: number };
          enabled?: boolean;
          verified?: boolean;
        } = {
          name: payload.name,
          scopes: payload.scopes,
          budget: payload.budget,
          enabled: payload.enabled,
          verified: payload.verified,
        };
        if (payload.public_key) {
          updates.public_key = payload.public_key;
        }
        await api.updateTrustedService(editingService, updates);
      } else {
        await api.addTrustedService(payload);
      }

      await loadServices();
      resetServiceForm();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save service';
      setServiceError(message);
    } finally {
      setServiceSaving(false);
    }
  };

  const handleRevokeService = async (serviceId: string) => {
    setServiceSaving(true);
    try {
      await api.revokeTrustedService(serviceId);
      await loadServices();
      if (editingService === serviceId) {
        resetServiceForm();
      }
    } catch (err) {
      console.error('Failed to revoke service:', err);
      setServiceError('Failed to revoke service');
    } finally {
      setServiceSaving(false);
    }
  };

  const handleOpenConnect = async (serviceId: string) => {
    const known = knownServiceMap.get(serviceId);
    if (known?.connect_url) {
      try {
        await open(known.connect_url);
      } catch (err) {
        console.error('Failed to open connect URL:', err);
      }
    }
    navigate(`/connect?service=${encodeURIComponent(serviceId)}`);
  };

  const handleBudgetChange = (
    type: keyof BudgetConfig,
    currency: string,
    value: string
  ) => {
    if (!budgetConfig) return;
    const parsed = Number(value);
    const updated = {
      ...budgetConfig,
      [type]: {
        ...budgetConfig[type],
        [currency]: Number.isNaN(parsed) ? 0 : parsed,
      },
    };
    setBudgetConfig(updated);
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
      setBudgetError('Failed to save budget configuration');
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

  return (
    <div>
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Settings</h2>
            <p className="card-subtitle">Manage your vault settings and sessions</p>
          </div>
        </div>

        <div style={{ marginBottom: '24px' }}>
          <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '12px' }}>
            Vault Information
          </h3>
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
              <code>http://127.0.0.1:8420</code>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Trusted Services</h2>
            <p className="card-subtitle">Grant remote agents access to your vault</p>
          </div>
          <button className="btn btn-secondary" onClick={loadServices}>
            Refresh
          </button>
        </div>

        {serviceError && (
          <div className="alert error" style={{ marginBottom: '12px', display: 'flex', justifyContent: 'space-between', gap: '12px', alignItems: 'center' }}>
            <span>{serviceError}</span>
            <button className="btn btn-secondary" onClick={handleOwnerAuth} style={{ padding: '4px 10px', fontSize: '12px' }}>
              Authenticate Owner
            </button>
          </div>
        )}

        <div style={{ marginBottom: '20px' }}>
          <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '12px' }}>
            {editingService ? `Edit ${editingService}` : 'Add Trusted Service'}
          </h3>

          {knownServices.length > 0 && !editingService && (
            <div className="form-group">
              <label className="form-label">Choose a verified service</label>
              <select
                className="input"
                value={selectedKnownService}
                onChange={(e) => applyKnownService(e.target.value)}
              >
                <option value="custom">Custom service</option>
                {knownServices.map((service) => (
                  <option key={service.service_id} value={service.service_id}>
                    {service.name}
                  </option>
                ))}
              </select>
              {selectedKnownService !== 'custom' && (
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>
                  Verified services use official public keys.
                </div>
              )}
            </div>
          )}

          <div className="form-group">
            <label className="form-label">Service ID</label>
            <input
              className="input"
              placeholder="1ly"
              value={serviceForm.service_id}
              disabled={!!editingService}
              onChange={(e) => setServiceForm({ ...serviceForm, service_id: e.target.value })}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Name (optional)</label>
            <input
              className="input"
              placeholder="1ly MCP"
              value={serviceForm.name}
              onChange={(e) => setServiceForm({ ...serviceForm, name: e.target.value })}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Public Key</label>
            <input
              className="input"
              placeholder="ed25519:..."
              value={serviceForm.public_key}
              onChange={(e) => setServiceForm({ ...serviceForm, public_key: e.target.value })}
            />
            {editingService && (
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px' }}>
                Leave blank to keep the current key.
              </div>
            )}
          </div>

          <div className="form-group">
            <label className="form-label">Permissions</label>
            <div
              style={{
                padding: '12px',
                border: '1px solid var(--border)',
                borderRadius: '10px',
                background: 'var(--bg-tertiary)',
                display: 'grid',
                gap: '12px',
              }}
            >
              {scopeGroups.map(([category, presets]) => (
                <div key={category} style={{ display: 'grid', gap: '8px' }}>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                    {category}
                  </div>
                  {presets.map((preset) => (
                    <label
                      key={preset.id}
                      style={{
                        display: 'flex',
                        gap: '10px',
                        alignItems: 'flex-start',
                        padding: '8px 10px',
                        borderRadius: '8px',
                        background: 'var(--bg-secondary)',
                        border: '1px solid var(--border)',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={scopesList.includes(preset.scope)}
                        onChange={() => toggleScope(preset.scope)}
                      />
                      <div>
                        <div style={{ fontSize: '13px', fontWeight: 600 }}>{preset.label}</div>
                        <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          {preset.description}
                        </div>
                      </div>
                    </label>
                  ))}
                </div>
              ))}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '8px' }}>
              Advanced scopes (optional)
            </div>
            <input
              className="input"
              placeholder="sign:solana, read:credentials.*"
              value={serviceForm.scopes}
              onChange={(e) => setServiceForm({ ...serviceForm, scopes: e.target.value })}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div className="form-group">
              <label className="form-label">Daily Budget</label>
              <input
                className="input"
                type="number"
                min="0"
                value={serviceForm.budget_daily}
                onChange={(e) => setServiceForm({ ...serviceForm, budget_daily: e.target.value })}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Currency</label>
              <select
                className="input"
                value={serviceForm.budget_currency}
                onChange={(e) => setServiceForm({ ...serviceForm, budget_currency: e.target.value })}
              >
                {currencyOptions.map((currency) => (
                  <option key={currency} value={currency}>{currency}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Auto-approve under</label>
            <input
              className="input"
              type="number"
              min="0"
              value={serviceForm.auto_approve_under}
              onChange={(e) => setServiceForm({ ...serviceForm, auto_approve_under: e.target.value })}
            />
          </div>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '16px' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
              <input
                type="checkbox"
                checked={serviceForm.enabled}
                onChange={(e) => setServiceForm({ ...serviceForm, enabled: e.target.checked })}
              />
              Enabled
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
              <input
                type="checkbox"
                checked={serviceForm.verified}
                onChange={(e) => setServiceForm({ ...serviceForm, verified: e.target.checked })}
              />
              Verified
            </label>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              className="btn btn-primary"
              onClick={handleSaveService}
              disabled={serviceSaving}
            >
              {serviceSaving ? 'Saving...' : editingService ? 'Update Service' : 'Trust Service'}
            </button>
            {editingService && (
              <button
                className="btn btn-secondary"
                onClick={resetServiceForm}
                disabled={serviceSaving}
              >
                Cancel
              </button>
            )}
          </div>
        </div>

        {serviceLoading ? (
          <div className="loading">
            <div className="spinner" />
          </div>
        ) : services.length === 0 ? (
          <div className="empty-state">
            <p>No trusted services yet</p>
          </div>
        ) : (
          services.map((service) => (
            <div
              key={service.service_id}
              style={{
                padding: '12px 16px',
                background: 'var(--bg-tertiary)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                marginBottom: '12px',
              }}
            >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ fontSize: '14px', fontWeight: 600 }}>
                      {service.name} <span style={{ color: 'var(--text-muted)' }}>({service.service_id})</span>
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Scopes: {service.scopes.join(', ')}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Budget: {service.budget.daily} {service.budget.currency}/day
                      {service.budget.auto_approve_under > 0
                        ? ` • Auto < ${service.budget.auto_approve_under} ${service.budget.currency}`
                        : ''}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Status: {service.enabled ? 'Enabled' : 'Disabled'} • {service.verified ? 'Verified' : 'Custom'}
                    </div>
                    {service.connected_at && (
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                        Connected: {new Date(service.connected_at).toLocaleString()}
                      </div>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      className="btn btn-secondary"
                      onClick={() => handleOpenConnect(service.service_id)}
                      disabled={serviceSaving}
                      style={{ padding: '4px 10px', fontSize: '12px' }}
                    >
                      Connect
                    </button>
                    <button
                      className="btn btn-secondary"
                      onClick={() => startEditService(service)}
                      disabled={serviceSaving}
                    style={{ padding: '4px 10px', fontSize: '12px' }}
                  >
                    Edit
                  </button>
                  <button
                    className="btn btn-danger"
                    onClick={() => handleRevokeService(service.service_id)}
                    disabled={serviceSaving}
                    style={{ padding: '4px 10px', fontSize: '12px' }}
                  >
                    Revoke
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Budgets & Limits</h2>
            <p className="card-subtitle">Set daily budgets and approval thresholds</p>
          </div>
          <button className="btn btn-secondary" onClick={loadBudgets}>
            Refresh
          </button>
        </div>

        {budgetError && (
          <div className="alert error" style={{ marginBottom: '12px', display: 'flex', justifyContent: 'space-between', gap: '12px', alignItems: 'center' }}>
            <span>{budgetError}</span>
            <button className="btn btn-secondary" onClick={handleOwnerAuth} style={{ padding: '4px 10px', fontSize: '12px' }}>
              Authenticate Owner
            </button>
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
                    <label className="form-label">Daily</label>
                    <input
                      className="input"
                      type="number"
                      min="0"
                      value={budgetConfig.daily_budget[currency] ?? 0}
                      onChange={(e) => handleBudgetChange('daily_budget', currency, e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="form-label">Per Tx</label>
                    <input
                      className="input"
                      type="number"
                      min="0"
                      value={budgetConfig.tx_limit[currency] ?? 0}
                      onChange={(e) => handleBudgetChange('tx_limit', currency, e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="form-label">Approve Under</label>
                    <input
                      className="input"
                      type="number"
                      min="0"
                      value={budgetConfig.approval_threshold[currency] ?? 0}
                      onChange={(e) => handleBudgetChange('approval_threshold', currency, e.target.value)}
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
              {budgetSaving ? 'Saving...' : 'Save Budgets'}
            </button>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Active Agent Sessions</h2>
            <p className="card-subtitle">Manage authorized agent sessions</p>
          </div>
          <button className="btn btn-secondary" onClick={loadAgents}>
            Refresh
          </button>
        </div>

        {agents.length === 0 ? (
          <div className="empty-state">
            <p>No active agent sessions</p>
          </div>
        ) : (
          Object.entries(agentGroups).map(([agentName, sessions]) => (
            <div key={agentName} style={{ marginBottom: '20px' }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '8px'
              }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600 }}>{agentName}</h3>
                <button
                  className="btn btn-danger"
                  onClick={() => handleRevokeAgent(agentName)}
                  disabled={revoking === agentName}
                  style={{ padding: '4px 10px', fontSize: '12px' }}
                >
                  {revoking === agentName ? 'Revoking...' : 'Revoke All'}
                </button>
              </div>

              {sessions.map((session) => (
                <div
                  key={session.id}
                  style={{
                    padding: '12px 16px',
                    background: 'var(--bg-tertiary)',
                    border: '1px solid var(--border)',
                    borderRadius: '8px',
                    marginBottom: '8px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        Session: {session.id.slice(0, 8)}...
                      </div>
                      <div style={{ fontSize: '13px', marginTop: '4px' }}>
                        Scopes: {session.granted_scopes.join(', ')}
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                        Mode: {session.consent_mode} • Expires: {new Date(session.expires_at).toLocaleString()}
                      </div>
                    </div>
                    <button
                      className="btn btn-secondary"
                      onClick={() => handleRevokeSession(session.id)}
                      disabled={revoking === session.id}
                      style={{ padding: '4px 10px', fontSize: '12px' }}
                    >
                      Revoke
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
