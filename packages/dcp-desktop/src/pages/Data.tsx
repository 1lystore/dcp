import { useEffect, useState } from 'react';
import { api, type Scope } from '../api';

// Field type definitions
interface BaseField {
  key: string;
  label: string;
  placeholder?: string;
}

interface TextField extends BaseField {
  type: 'text' | 'email' | 'tel' | 'password' | 'date';
}

interface SelectField extends BaseField {
  type: 'select';
  options: string[];
}

interface TagsField extends BaseField {
  type: 'tags';
}

type FieldDef = TextField | SelectField | TagsField;

interface DataTemplate {
  label: string;
  icon: string;
  fields: FieldDef[];
}

// Data categories with user-friendly forms
const DATA_TEMPLATES: Record<string, DataTemplate> = {
  'identity.name': {
    label: 'Your Name',
    icon: '👤',
    fields: [
      { key: 'first', label: 'First Name', type: 'text', placeholder: 'John' },
      { key: 'last', label: 'Last Name', type: 'text', placeholder: 'Doe' },
      { key: 'full', label: 'Full Name', type: 'text', placeholder: 'John Doe' },
    ]
  },
  'identity.email': {
    label: 'Email Address',
    icon: '📧',
    fields: [
      { key: 'email', label: 'Email', type: 'email', placeholder: 'john@example.com' },
    ]
  },
  'identity.phone': {
    label: 'Phone Number',
    icon: '📱',
    fields: [
      { key: 'country_code', label: 'Country Code', type: 'text', placeholder: '+1' },
      { key: 'number', label: 'Phone Number', type: 'tel', placeholder: '555-123-4567' },
    ]
  },
  'identity.birthday': {
    label: 'Birthday',
    icon: '🎂',
    fields: [
      { key: 'date', label: 'Date of Birth', type: 'date', placeholder: '' },
    ]
  },
  'address.home': {
    label: 'Home Address',
    icon: '🏠',
    fields: [
      { key: 'street', label: 'Street Address', type: 'text', placeholder: '123 Main St' },
      { key: 'city', label: 'City', type: 'text', placeholder: 'San Francisco' },
      { key: 'state', label: 'State/Province', type: 'text', placeholder: 'CA' },
      { key: 'zip', label: 'ZIP/Postal Code', type: 'text', placeholder: '94102' },
      { key: 'country', label: 'Country', type: 'text', placeholder: 'US' },
    ]
  },
  'address.work': {
    label: 'Work Address',
    icon: '🏢',
    fields: [
      { key: 'street', label: 'Street Address', type: 'text', placeholder: '456 Business Ave' },
      { key: 'city', label: 'City', type: 'text', placeholder: 'New York' },
      { key: 'state', label: 'State/Province', type: 'text', placeholder: 'NY' },
      { key: 'zip', label: 'ZIP/Postal Code', type: 'text', placeholder: '10001' },
      { key: 'country', label: 'Country', type: 'text', placeholder: 'US' },
    ]
  },
  'preferences.sizes': {
    label: 'Clothing Sizes',
    icon: '👕',
    fields: [
      { key: 'shirt', label: 'Shirt Size', type: 'select', options: ['XS', 'S', 'M', 'L', 'XL', 'XXL'] },
      { key: 'pants', label: 'Pants Size', type: 'text', placeholder: '32x32' },
      { key: 'shoe', label: 'Shoe Size', type: 'text', placeholder: '10' },
    ]
  },
  'preferences.diet': {
    label: 'Dietary Preferences',
    icon: '🥗',
    fields: [
      { key: 'restrictions', label: 'Dietary Restrictions', type: 'tags', placeholder: 'vegetarian, gluten-free' },
      { key: 'allergies', label: 'Allergies', type: 'tags', placeholder: 'peanuts, shellfish' },
      { key: 'preferences', label: 'Food Preferences', type: 'tags', placeholder: 'spicy, organic' },
    ]
  },
  'preferences.brands': {
    label: 'Brand Preferences',
    icon: '🏷️',
    fields: [
      { key: 'preferred', label: 'Favorite Brands', type: 'tags', placeholder: 'Nike, Apple' },
      { key: 'avoided', label: 'Brands to Avoid', type: 'tags', placeholder: '' },
    ]
  },
  'credentials.api': {
    label: 'API Credential',
    icon: '🔑',
    fields: [
      { key: 'label', label: 'Label/Name', type: 'text', placeholder: 'My OpenAI Key' },
      { key: 'service', label: 'Service ID (for scoping)', type: 'text', placeholder: 'openai, claude, stripe, etc.' },
      { key: 'key', label: 'API Key', type: 'password', placeholder: 'sk-...' },
      { key: 'base_url', label: 'Base URL (optional)', type: 'text', placeholder: 'https://api.openai.com' },
    ]
  },
};

type TemplateKey = string;

const normalizeVaultScope = (scopeKey: string) =>
  scopeKey.replace(/^(read|write|sign):/, '');

// Helper to get template for a scope (supports prefix matching for API credentials)
const getTemplateForScope = (scopeKey: string) => {
  const normalizedScope = normalizeVaultScope(scopeKey);
  // Direct match first
  if (DATA_TEMPLATES[normalizedScope]) {
    return DATA_TEMPLATES[normalizedScope];
  }
  // Check if it's an API credential (credentials.api.*)
  if (normalizedScope.startsWith('credentials.api.')) {
    return DATA_TEMPLATES['credentials.api'];
  }
  return null;
};

// Modal overlay styles
const modalOverlayStyle: React.CSSProperties = {
  position: 'fixed',
  inset: 0,
  background: 'rgba(0, 0, 0, 0.7)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  zIndex: 1000,
  padding: '20px',
};

const modalContentStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)',
  borderRadius: '16px',
  border: '1px solid var(--border)',
  maxWidth: '500px',
  width: '100%',
  maxHeight: '90vh',
  overflow: 'auto',
  boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
};

export default function Data() {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddMenu, setShowAddMenu] = useState(false);
  const [editingScope, setEditingScope] = useState<string | null>(null);
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [visibleSecretFields, setVisibleSecretFields] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    loadScopes();
  }, []);

  const loadScopes = async () => {
    try {
      const res = await api.getScopes();
      setScopes(res.scopes);
    } catch (err) {
      console.error('Failed to load scopes:', err);
    } finally {
      setLoading(false);
    }
  };

  const openEditor = async (scopeKey: string) => {
    const vaultScope = normalizeVaultScope(scopeKey);
    try {

      // Set editing state FIRST to open modal immediately
      setEditingScope(vaultScope);
      setShowAddMenu(false);
      setError(null);
      setSuccess(null);
      setFormData({}); // Start with empty form


      // If scope exists, try to load its data (but modal is already open)
      const existingScope = scopes.find(s => normalizeVaultScope(s.scope) === vaultScope);
      if (existingScope) {
        try {
          const res = await api.readData(vaultScope);
          if (res.data) {
            const template = getTemplateForScope(vaultScope);
            if (template) {
              const newFormData: Record<string, string> = {};
              template.fields.forEach(field => {
                const value = res.data?.[field.key];
                if (Array.isArray(value)) {
                  newFormData[field.key] = value.join(', ');
                } else {
                  newFormData[field.key] = value ? String(value) : '';
                }
              });
              setFormData(newFormData);
            } else {
              setFormData({ _json: JSON.stringify(res.data, null, 2) });
            }
          }
        } catch (err) {
          console.error('Failed to load data (modal still open):', err);
          // Don't close modal on error - just show empty form
        }
      }
    } catch (err) {
      console.error('openEditor error:', err);
      // Still try to open modal even on error
      setEditingScope(vaultScope);
      setFormData({});
    }
  };

  const closeEditor = () => {
    setEditingScope(null);
    setFormData({});
    setError(null);
    setSuccess(null);
    setDeleting(false);
    setVisibleSecretFields({});
  };

  const handleDelete = async () => {
    if (!editingScope) return;
    setDeleting(true);
    setError(null);
    setSuccess(null);
    try {
      await api.deleteData(editingScope);
      setSuccess('Deleted successfully');
      await loadScopes();
      setTimeout(() => closeEditor(), 500);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to delete';
      setError(msg);
    } finally {
      setDeleting(false);
    }
  };

  const handleSave = async () => {
    if (!editingScope) return;

    setError(null);
    setSuccess(null);
    setSaving(true);

    try {
      const template = getTemplateForScope(editingScope);
      let data: Record<string, unknown>;
      let finalScope = editingScope;

      if (template) {
        data = {};
        template.fields.forEach(field => {
          const value = formData[field.key]?.trim();
          if (value) {
            if (field.type === 'tags') {
              data[field.key] = value.split(',').map(s => s.trim()).filter(Boolean);
            } else {
              data[field.key] = value;
            }
          }
        });

        // For new API credentials, use service name in scope if provided
        if (editingScope.startsWith('credentials.api.') && !isExistingScope) {
          const serviceName = formData['service']?.trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
          if (serviceName) {
            finalScope = `credentials.api.${serviceName}`;
          }
        }
      } else {
        data = JSON.parse(formData._json || '{}');
      }

      await api.writeData(finalScope, data);
      setSuccess('Saved successfully!');
      await loadScopes();

      // Close modal after success
      setTimeout(() => {
        closeEditor();
      }, 500);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to save';
      setError(msg);
    } finally {
      setSaving(false);
    }
  };

  const handleFieldChange = (key: string, value: string) => {
    setFormData(prev => ({ ...prev, [key]: value }));
  };

  const toggleSecretField = (key: string) => {
    setVisibleSecretFields(prev => ({ ...prev, [key]: !prev[key] }));
  };

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
      </div>
    );
  }

  // Group by category with nice labels
  const categoryLabels: Record<string, string> = {
    identity: '👤 Identity',
    address: '📍 Addresses',
    preferences: '⚙️ Preferences',
    credentials: '🔑 Credentials',
    crypto: '💰 Wallets',
    health: '🏥 Health',
  };

  const groupedScopes = scopes.reduce((acc, scope) => {
    const normalizedScope = normalizeVaultScope(scope.scope);
    const category = normalizedScope.split('.')[0];
    if (!acc[category]) acc[category] = [];
    acc[category].push(scope);
    return acc;
  }, {} as Record<string, Scope[]>);

  const currentTemplate = editingScope ? getTemplateForScope(editingScope) : null;
  const isExistingScope = editingScope ? scopes.some((s) => s.scope === editingScope) : false;


  return (
    <div>
      {/* Main Data List */}
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Your Data</h2>
            <p className="card-subtitle">Personal information stored in your vault</p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button className="btn btn-primary" onClick={() => {
              setShowAddMenu(!showAddMenu);
            }}>
              + Add Data
            </button>
            <button className="btn btn-secondary" onClick={loadScopes}>
              Refresh
            </button>
          </div>
        </div>

        {/* Add Menu - Shows template options */}
        {showAddMenu && (
          <div style={{
            background: 'var(--bg-tertiary)',
            borderRadius: '12px',
            padding: '16px',
            marginBottom: '16px'
          }}>
            <h3 style={{ fontSize: '14px', marginBottom: '12px', color: 'var(--text-secondary)' }}>
              What would you like to add?
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '8px' }}>
              {Object.entries(DATA_TEMPLATES).map(([key, template]) => (
                <button
                  key={key}
                  onClick={() => {
                    // For API credentials, generate unique scope with timestamp
                    const scopeKey = key === 'credentials.api'
                      ? `credentials.api.${Date.now()}`
                      : key;
                    openEditor(scopeKey);
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    padding: '12px 16px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    textAlign: 'left',
                    color: 'var(--text-primary)',
                    transition: 'all 0.15s ease',
                  }}
                  onMouseOver={(e) => e.currentTarget.style.borderColor = 'var(--accent)'}
                  onMouseOut={(e) => e.currentTarget.style.borderColor = 'var(--border)'}
                >
                  <span style={{ fontSize: '20px' }}>{template.icon}</span>
                  <span style={{ fontSize: '13px', fontWeight: 500 }}>{template.label}</span>
                </button>
              ))}
            </div>
            <button
              className="btn btn-secondary"
              onClick={() => setShowAddMenu(false)}
              style={{ marginTop: '12px' }}
            >
              Cancel
            </button>
          </div>
        )}

        {/* Existing Data List */}
        {scopes.length === 0 && !showAddMenu ? (
          <div className="empty-state">
            <p style={{ fontSize: '40px', marginBottom: '12px' }}>📦</p>
            <p>No data stored yet</p>
            <p style={{ fontSize: '12px', marginTop: '8px', color: 'var(--text-muted)' }}>
              Click "+ Add Data" to store your first information
            </p>
          </div>
        ) : (
          Object.entries(groupedScopes).map(([category, items]) => (
            <div key={category} style={{ marginBottom: '20px' }}>
              <h3 style={{
                fontSize: '13px',
                color: 'var(--text-muted)',
                marginBottom: '8px',
              }}>
                {categoryLabels[category] || category}
              </h3>
              {items.map((scope) => {
                const templateKey = normalizeVaultScope(scope.scope) as TemplateKey;
                const template = getTemplateForScope(templateKey);
                const isWallet = scope.type === 'WALLET_KEY';
                const canEdit = !isWallet && scope.sensitivity !== 'critical';

                return (
                  <div
                    key={scope.scope}
                    onClick={() => {
                      if (canEdit) {
                        openEditor(scope.scope);
                      }
                    }}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '12px 16px',
                      background: 'transparent',
                      border: '1px solid var(--border)',
                      borderRadius: '8px',
                      marginBottom: '8px',
                      transition: 'all 0.15s ease',
                      cursor: canEdit ? 'pointer' : 'default',
                    }}
                    onMouseOver={(e) => {
                      if (canEdit) {
                        e.currentTarget.style.background = 'var(--bg-tertiary)';
                        e.currentTarget.style.borderColor = 'var(--accent)';
                      }
                    }}
                    onMouseOut={(e) => {
                      e.currentTarget.style.background = 'transparent';
                      e.currentTarget.style.borderColor = 'var(--border)';
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <span style={{ fontSize: '20px' }}>
                        {template?.icon || (isWallet ? '💰' : '📄')}
                      </span>
                      <div>
                        <div style={{ fontWeight: 500 }}>
                          {template?.label || templateKey}
                        </div>
                        {scope.public_address && (
                          <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                            {scope.public_address.slice(0, 10)}...{scope.public_address.slice(-8)}
                          </div>
                        )}
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="pill" style={{ fontSize: '10px' }}>{scope.sensitivity}</span>
                      {canEdit && (
                        <button
                          className="btn btn-secondary"
                          onClick={(e) => {
                            e.stopPropagation(); // Prevent row click
                            openEditor(scope.scope);
                          }}
                          style={{ padding: '6px 10px', fontSize: '12px' }}
                          title="Edit"
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
                            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
                          </svg>
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          ))
        )}
      </div>

      {/* Modal Editor */}
      {editingScope && (
        <div style={modalOverlayStyle} onClick={(e) => {
          if (e.target === e.currentTarget) closeEditor();
        }}>
          <div style={modalContentStyle}>
            <div style={{
              padding: '20px',
              borderBottom: '1px solid var(--border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontSize: '28px' }}>{currentTemplate?.icon || '📄'}</span>
                <div>
                  <h2 style={{ margin: 0, fontSize: '18px' }}>
                    {currentTemplate?.label || editingScope}
                  </h2>
                  <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-muted)' }}>
                    Fill in your information below
                  </p>
                </div>
              </div>
              <button
                onClick={closeEditor}
                style={{
                  background: 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  padding: '8px',
                  color: 'var(--text-muted)',
                  fontSize: '20px',
                }}
              >
                ×
              </button>
            </div>

            <div style={{ padding: '20px' }}>
              {error && (
                <div style={{
                  padding: '12px',
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: '8px',
                  color: '#fca5a5',
                  fontSize: '13px',
                  marginBottom: '16px'
                }}>
                  {error}
                </div>
              )}

              {success && (
                <div style={{
                  padding: '12px',
                  background: 'rgba(34, 197, 94, 0.1)',
                  border: '1px solid rgba(34, 197, 94, 0.3)',
                  borderRadius: '8px',
                  color: '#86efac',
                  fontSize: '13px',
                  marginBottom: '16px'
                }}>
                  {success}
                </div>
              )}

              {currentTemplate ? (
                // Template-based form
                currentTemplate.fields.map((field) => (
                  <div key={field.key} className="form-group">
                    <label className="form-label">{field.label}</label>
                    {field.type === 'select' ? (
                      <select
                        className="input"
                        value={formData[field.key] || ''}
                        onChange={(e) => handleFieldChange(field.key, e.target.value)}
                      >
                        <option value="">Select...</option>
                        {(field as SelectField).options.map((opt: string) => (
                          <option key={opt} value={opt}>{opt}</option>
                        ))}
                      </select>
                    ) : field.type === 'tags' ? (
                      <>
                        <input
                          type="text"
                          className="input"
                          placeholder={field.placeholder}
                          value={formData[field.key] || ''}
                          onChange={(e) => handleFieldChange(field.key, e.target.value)}
                        />
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                          Separate multiple items with commas
                        </div>
                      </>
                    ) : field.type === 'password' ? (
                      <div style={{ position: 'relative' }}>
                        <input
                          type={visibleSecretFields[field.key] ? 'text' : 'password'}
                          className="input"
                          placeholder={field.placeholder}
                          value={formData[field.key] || ''}
                          onChange={(e) => handleFieldChange(field.key, e.target.value)}
                          style={{ paddingRight: '42px' }}
                        />
                        <button
                          type="button"
                          onClick={() => toggleSecretField(field.key)}
                          title={visibleSecretFields[field.key] ? 'Hide value' : 'Show value'}
                          aria-label={visibleSecretFields[field.key] ? 'Hide value' : 'Show value'}
                          style={{
                            position: 'absolute',
                            right: '8px',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            width: '28px',
                            height: '28px',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            background: 'transparent',
                            border: 'none',
                            color: 'var(--text-muted)',
                            cursor: 'pointer',
                            padding: 0,
                          }}
                        >
                          {visibleSecretFields[field.key] ? (
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M17.94 17.94A10.94 10.94 0 0 1 12 20C7 20 2.73 16.89 1 12c.8-2.27 2.27-4.22 4.14-5.61" />
                              <path d="M9.9 4.24A10.64 10.64 0 0 1 12 4c5 0 9.27 3.11 11 8a11.5 11.5 0 0 1-2.18 3.54" />
                              <path d="M14.12 14.12A3 3 0 0 1 9.88 9.88" />
                              <path d="M1 1l22 22" />
                            </svg>
                          ) : (
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                              <circle cx="12" cy="12" r="3" />
                            </svg>
                          )}
                        </button>
                      </div>
                    ) : (
                      <input
                        type={field.type}
                        className="input"
                        placeholder={field.placeholder}
                        value={formData[field.key] || ''}
                        onChange={(e) => handleFieldChange(field.key, e.target.value)}
                      />
                    )}
                  </div>
                ))
              ) : (
                // JSON editor for custom scopes
                <div className="form-group">
                  <label className="form-label">Data (JSON)</label>
                  <textarea
                    className="input"
                    style={{ minHeight: '200px', fontFamily: 'monospace', fontSize: '13px' }}
                    value={formData._json || '{\n  \n}'}
                    onChange={(e) => handleFieldChange('_json', e.target.value)}
                  />
                </div>
              )}

              <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
                <button
                  className="btn btn-primary"
                  onClick={handleSave}
                  disabled={saving}
                  style={{ flex: 1 }}
                >
                  {saving ? 'Saving...' : '💾 Save'}
                </button>
                {isExistingScope && (
                  <button
                    className="btn btn-danger"
                    onClick={handleDelete}
                    disabled={deleting}
                    style={{ flex: 1 }}
                  >
                    {deleting ? 'Deleting...' : 'Delete'}
                  </button>
                )}
                <button
                  className="btn btn-secondary"
                  onClick={closeEditor}
                  style={{ flex: 1 }}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
