import { useState } from 'react';

interface UnlockProps {
  onUnlock: (passphrase: string) => Promise<void>;
  onSetupNew: () => Promise<void>;
}

export default function Unlock({ onUnlock, onSetupNew }: UnlockProps) {
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [resetLoading, setResetLoading] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passphrase) {
      setError('Please enter your passphrase');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await onUnlock(passphrase);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to unlock vault');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app" style={{ justifyContent: 'center', alignItems: 'center', padding: '24px' }}>
      <div style={{ width: '100%', maxWidth: '400px' }}>
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ marginBottom: '16px' }}>
            <path d="M12 2L3 7V12C3 16.97 6.84 21.56 12 23C17.16 21.56 21 16.97 21 12V7L12 2Z" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            <rect x="8" y="10" width="8" height="7" rx="1" stroke="var(--accent)" strokeWidth="2"/>
            <path d="M10 10V8C10 6.89543 10.8954 6 12 6C13.1046 6 14 6.89543 14 8V10" stroke="var(--accent)" strokeWidth="2"/>
          </svg>
          <h1 style={{ fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>DCP Vault</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Enter your passphrase to unlock</p>
        </div>

        <div className="card">
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">Passphrase</label>
              <input
                type="password"
                className="input"
                placeholder="Enter your passphrase"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                autoFocus
              />
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
                {error}
              </div>
            )}

            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading}
              style={{ width: '100%' }}
            >
              {loading ? 'Unlocking...' : 'Unlock Vault'}
            </button>
          </form>
        </div>

        <div style={{ textAlign: 'center', marginTop: '24px' }}>
          {!confirmReset && (
            <button
              onClick={() => setConfirmReset(true)}
              disabled={resetLoading}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                fontSize: '13px'
              }}
            >
              Create a new vault instead
            </button>
          )}

          {confirmReset && (
            <div className="card" style={{ marginTop: '12px', textAlign: 'left' }}>
              <div className="warning-box" style={{ marginTop: 0 }}>
                <span className="warning-icon">⚠️</span>
                <span className="warning-text">
                  This will delete your existing vault and all stored data. This cannot be undone.
                </span>
              </div>
              <div style={{ display: 'flex', gap: '12px', marginTop: '12px' }}>
                <button
                  className="btn btn-secondary"
                  onClick={() => setConfirmReset(false)}
                  disabled={resetLoading}
                  style={{ flex: 1 }}
                >
                  Cancel
                </button>
                <button
                  className="btn btn-primary"
                  onClick={async () => {
                    setResetLoading(true);
                    setError(null);
                    try {
                      await onSetupNew();
                    } catch (err) {
                      setError(err instanceof Error ? err.message : 'Failed to reset vault');
                    } finally {
                      setResetLoading(false);
                      setConfirmReset(false);
                    }
                  }}
                  disabled={resetLoading}
                  style={{ flex: 1 }}
                >
                  {resetLoading ? 'Resetting...' : 'Delete and Create New'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
