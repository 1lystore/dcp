import { useEffect, useState, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { api, type PendingConsent } from '../api';

export default function Consent() {
  const [consents, setConsents] = useState<PendingConsent[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const knownConsents = useRef<Set<string>>(new Set());

  const loadConsents = useCallback(async () => {
    try {
      const res = await api.getPendingConsents();
      setConsents(res.pending);

      // Notify on new consents
      const currentIds = new Set(res.pending.map((c) => c.id));
      res.pending.forEach((consent) => {
        if (!knownConsents.current.has(consent.id)) {
          const details = consent.details || {};
          const amount = 'amount' in details && 'currency' in details
            ? `${details.amount} ${details.currency}`
            : undefined;
          const title = 'DCP Vault: Consent Required';
          const body = `${consent.agent_name} wants to ${consent.action}${amount ? ` (${amount})` : ''}`;
          invoke('show_notification', { title, body }).catch(() => {});
        }
      });
      knownConsents.current = currentIds;
    } catch (err) {
      console.error('Failed to load consents:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadConsents();
    const interval = setInterval(loadConsents, 3000);
    return () => clearInterval(interval);
  }, [loadConsents]);

  const handleApprove = async (id: string, session: boolean) => {
    setActionLoading(id);
    setError(null);
    try {
      await api.approveConsent(id, session);
      await loadConsents();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to approve';
      setError(msg);
      console.error('Failed to approve consent:', err);
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeny = async (id: string) => {
    setActionLoading(id);
    setError(null);
    try {
      await api.denyConsent(id);
      await loadConsents();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to deny';
      setError(msg);
      console.error('Failed to deny consent:', err);
    } finally {
      setActionLoading(null);
    }
  };

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
      </div>
    );
  }

  return (
    <div>
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Pending Consent Requests</h2>
            <p className="card-subtitle">Approve or deny agent requests for vault access</p>
          </div>
          <button className="btn btn-secondary" onClick={loadConsents}>
            Refresh
          </button>
        </div>

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
            Error: {error}
          </div>
        )}

        {consents.length === 0 ? (
          <div className="empty-state">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ marginBottom: '16px', opacity: 0.5 }}>
              <path d="M9 11l3 3L22 4"/>
              <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
            </svg>
            <p>No pending consent requests</p>
            <p style={{ fontSize: '12px', marginTop: '8px' }}>
              When an agent requests access to your vault, it will appear here
            </p>
          </div>
        ) : (
          consents.map((consent) => {
            const details = consent.details || {};
            const isLoading = actionLoading === consent.id;

            return (
              <div key={consent.id} className="consent-item">
                <div className="consent-header">
                  <div>
                    <span className="consent-agent">{consent.agent_name}</span>
                    <span style={{ marginLeft: '8px', color: 'var(--text-secondary)' }}>
                      wants to <strong>{consent.action}</strong>
                    </span>
                  </div>
                  <span className="pill">{consent.status}</span>
                </div>

                <div className="consent-details">
                  <div>Scope: <code style={{ color: 'var(--accent)' }}>{consent.scope}</code></div>
                  {'amount' in details && 'currency' in details && (
                    <div style={{ marginTop: '4px' }}>
                      Amount: <strong>{String(details.amount)} {String(details.currency)}</strong>
                    </div>
                  )}
                  {'chain' in details && (
                    <div style={{ marginTop: '4px' }}>
                      Chain: <span style={{ textTransform: 'capitalize' }}>{String(details.chain)}</span>
                    </div>
                  )}
                  {'recipient' in details && (
                    <div style={{ marginTop: '4px' }}>
                      Recipient: <code>{String(details.recipient)}</code>
                    </div>
                  )}
                  {'purpose' in details && (
                    <div style={{ marginTop: '4px' }}>
                      Purpose: {String(details.purpose)}
                    </div>
                  )}
                  {'description' in details && (
                    <div style={{ marginTop: '4px' }}>
                      {String(details.description)}
                    </div>
                  )}
                </div>

                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                  Expires: {new Date(consent.expires_at).toLocaleTimeString()}
                </div>

                <div className="consent-actions">
                  <button
                    className="btn btn-success"
                    onClick={() => handleApprove(consent.id, false)}
                    disabled={isLoading}
                  >
                    {isLoading ? 'Processing...' : 'Approve Once'}
                  </button>
                  <button
                    className="btn btn-secondary"
                    onClick={() => handleApprove(consent.id, true)}
                    disabled={isLoading}
                  >
                    Approve Session
                  </button>
                  <button
                    className="btn btn-danger"
                    onClick={() => handleDeny(consent.id)}
                    disabled={isLoading}
                  >
                    Deny
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
