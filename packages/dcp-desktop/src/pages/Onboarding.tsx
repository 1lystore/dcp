import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface OnboardingProps {
  onBegin?: () => void;
  onComplete: () => void;
}

type Step = 'welcome' | 'passphrase' | 'recovery' | 'confirm' | 'wallets' | 'complete';

export default function Onboarding({ onBegin, onComplete }: OnboardingProps) {
  const [step, setStep] = useState<Step>('welcome');
  const [passphrase, setPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [recoveryPhrase, setRecoveryPhrase] = useState<string[]>([]);
  const [confirmationWords, setConfirmationWords] = useState<Record<number, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [wallets, setWallets] = useState<{ chain: string; address: string }[]>([]);
  const [began, setBegan] = useState(false);
  const [copied, setCopied] = useState(false);

  const getPasswordStrength = (pwd: string): 'weak' | 'fair' | 'good' | 'strong' => {
    if (pwd.length < 8) return 'weak';
    if (pwd.length < 12) return 'fair';
    if (pwd.length < 16 || !/[A-Z]/.test(pwd) || !/[0-9]/.test(pwd)) return 'good';
    return 'strong';
  };

  const strength = getPasswordStrength(passphrase);

  const handleCreateVault = async () => {
    if (passphrase !== confirmPassphrase) {
      setError('Passphrases do not match');
      return;
    }
    if (passphrase.length < 8) {
      setError('Passphrase must be at least 8 characters');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Call Tauri backend to initialize vault
      const result = await invoke<{ recovery_phrase: string[] }>('init_vault', { passphrase });
      setRecoveryPhrase(result.recovery_phrase);
      setStep('recovery');
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : typeof err === 'string'
            ? err
            : err && typeof err === 'object' && 'message' in err
              ? String((err as { message?: unknown }).message)
              : 'Failed to create vault';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleConfirmRecovery = () => {
    // Check if selected words are correct
    const indicesToCheck = Object.keys(confirmationWords).map(Number);
    for (const idx of indicesToCheck) {
      if (confirmationWords[idx]?.toLowerCase() !== recoveryPhrase[idx]?.toLowerCase()) {
        setError('One or more words are incorrect. Please check and try again.');
        return;
      }
    }
    setStep('wallets');
    createWallets();
  };

  const createWallets = async () => {
    setLoading(true);
    setError(null);

    try {
      // Create Solana wallet
      const result = await invoke<{ wallets: { chain: string; address: string }[] }>('create_wallets', {
        passphrase,
      });
      setWallets(result.wallets);
      setStep('complete');
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : typeof err === 'string'
            ? err
            : err && typeof err === 'object' && 'message' in err
              ? String((err as { message?: unknown }).message)
              : 'Failed to create wallets';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  // Select 3 random indices to confirm
  const confirmIndices = [2, 5, 9]; // 3rd, 6th, 10th word (0-indexed)

  useEffect(() => {
    if (!began) {
      setBegan(true);
      onBegin?.();
    }
  }, [began, onBegin]);

  return (
    <div className="app" style={{ justifyContent: 'center', alignItems: 'center', padding: '24px' }}>
      <div style={{ width: '100%', maxWidth: '500px' }}>
        {/* Welcome */}
        {step === 'welcome' && (
          <>
            <div style={{ textAlign: 'center', marginBottom: '32px' }}>
              <svg width="64" height="64" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ marginBottom: '16px' }}>
                <path d="M12 2L3 7V12C3 16.97 6.84 21.56 12 23C17.16 21.56 21 16.97 21 12V7L12 2Z" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M9 12L11 14L15 10" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <h1 style={{ fontSize: '28px', fontWeight: 700, marginBottom: '8px' }}>Welcome to DCP Vault</h1>
              <p style={{ color: 'var(--text-secondary)', fontSize: '15px' }}>
                Your secure personal data vault for AI agents
              </p>
            </div>

            <div className="card">
              <h3 style={{ marginBottom: '16px' }}>What you'll set up:</h3>
              <ul style={{ listStyle: 'none', padding: 0 }}>
                <li style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                  <span style={{ color: 'var(--accent)' }}>✓</span>
                  A secure passphrase to protect your vault
                </li>
                <li style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                  <span style={{ color: 'var(--accent)' }}>✓</span>
                  A 12-word recovery phrase for backup
                </li>
                <li style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span style={{ color: 'var(--accent)' }}>✓</span>
                  Blockchain wallet (Solana)
                </li>
              </ul>
            </div>

            <button
              className="btn btn-primary"
              onClick={() => setStep('passphrase')}
              style={{ width: '100%', marginTop: '16px' }}
            >
              Get Started
            </button>
          </>
        )}

        {/* Passphrase */}
        {step === 'passphrase' && (
          <>
            <div style={{ textAlign: 'center', marginBottom: '32px' }}>
              <h2 style={{ fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>Create Passphrase</h2>
              <p style={{ color: 'var(--text-secondary)' }}>
                Choose a strong passphrase to protect your vault
              </p>
            </div>

            <div className="card">
              <div className="form-group">
                <label className="form-label">Passphrase</label>
                <input
                  type="password"
                  className="input"
                  placeholder="Enter a strong passphrase"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                />
                <div className="strength-meter">
                  <div className={`strength-fill strength-${strength}`} />
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Strength: {strength}
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Confirm Passphrase</label>
                <input
                  type="password"
                  className="input"
                  placeholder="Confirm your passphrase"
                  value={confirmPassphrase}
                  onChange={(e) => setConfirmPassphrase(e.target.value)}
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

              <div className="warning-box">
                <span className="warning-icon">⚠️</span>
                <span className="warning-text">
                  Your passphrase is never stored. If you forget it, you'll need your recovery phrase to restore access.
                </span>
              </div>

              <div style={{ display: 'flex', gap: '12px', marginTop: '16px' }}>
                <button
                  className="btn btn-secondary"
                  onClick={() => setStep('welcome')}
                  style={{ flex: 1 }}
                >
                  Back
                </button>
                <button
                  className="btn btn-primary"
                  onClick={handleCreateVault}
                  disabled={loading || !passphrase || !confirmPassphrase}
                  style={{ flex: 1 }}
                >
                  {loading ? 'Creating...' : 'Continue'}
                </button>
              </div>
            </div>
          </>
        )}

        {/* Recovery Phrase */}
        {step === 'recovery' && (
          <>
            <div style={{ textAlign: 'center', marginBottom: '32px' }}>
              <h2 style={{ fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>Recovery Phrase</h2>
              <p style={{ color: 'var(--text-secondary)' }}>
                Write down these 12 words in order and keep them safe
              </p>
            </div>

            <div className="card">
              <div className="warning-box" style={{ marginTop: 0 }}>
                <span className="warning-icon">⚠️</span>
                <span className="warning-text">
                  <strong>Important:</strong> This is your only backup. Never share it with anyone. Store it securely offline.
                </span>
              </div>

              <div className="recovery-phrase">
                {recoveryPhrase.map((word, index) => (
                  <div key={index} className="recovery-word">
                    <span className="recovery-word-index">{index + 1}.</span>
                    <span>{word}</span>
                  </div>
                ))}
              </div>

              <button
                className="btn btn-secondary"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(recoveryPhrase.join(' '));
                    setCopied(true);
                    setTimeout(() => setCopied(false), 1500);
                  } catch {
                    setError('Failed to copy recovery phrase. Please copy manually.');
                  }
                }}
                style={{ width: '100%', marginTop: '12px' }}
              >
                {copied ? 'Copied' : 'Copy Phrase'}
              </button>

              <button
                className="btn btn-primary"
                onClick={() => setStep('confirm')}
                style={{ width: '100%', marginTop: '16px' }}
              >
                I've Written It Down
              </button>
            </div>
          </>
        )}

        {/* Confirm Recovery */}
        {step === 'confirm' && (
          <>
            <div style={{ textAlign: 'center', marginBottom: '32px' }}>
              <h2 style={{ fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>Confirm Recovery Phrase</h2>
              <p style={{ color: 'var(--text-secondary)' }}>
                Enter the requested words to confirm you've saved your phrase
              </p>
            </div>

            <div className="card">
              {confirmIndices.map((idx) => (
                <div key={idx} className="form-group">
                  <label className="form-label">Word #{idx + 1}</label>
                  <input
                    type="text"
                    className="input"
                    placeholder={`Enter word #${idx + 1}`}
                    value={confirmationWords[idx] || ''}
                    onChange={(e) => setConfirmationWords({ ...confirmationWords, [idx]: e.target.value })}
                  />
                </div>
              ))}

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

              <div style={{ display: 'flex', gap: '12px', marginTop: '16px' }}>
                <button
                  className="btn btn-secondary"
                  onClick={() => {
                    setError(null);
                    setStep('recovery');
                  }}
                  style={{ flex: 1 }}
                >
                  Back
                </button>
                <button
                  className="btn btn-primary"
                  onClick={handleConfirmRecovery}
                  disabled={confirmIndices.some(idx => !confirmationWords[idx])}
                  style={{ flex: 1 }}
                >
                  Confirm
                </button>
              </div>
            </div>
          </>
        )}

        {/* Wallets */}
        {step === 'wallets' && (
          <>
            <div style={{ textAlign: 'center', marginBottom: '32px' }}>
              <h2 style={{ fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>Creating Wallets</h2>
              <p style={{ color: 'var(--text-secondary)' }}>
                Setting up your blockchain wallets...
              </p>
            </div>

            <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
              <div className="spinner" style={{ margin: '0 auto 16px' }} />
              <p>Please wait...</p>
            </div>
          </>
        )}

        {/* Complete */}
        {step === 'complete' && (
          <>
            <div style={{ textAlign: 'center', marginBottom: '32px' }}>
              <div style={{
                width: '64px',
                height: '64px',
                borderRadius: '50%',
                background: 'rgba(34, 197, 94, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 16px',
                color: 'var(--success)',
                fontSize: '32px'
              }}>
                ✓
              </div>
              <h2 style={{ fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>Vault Created!</h2>
              <p style={{ color: 'var(--text-secondary)' }}>
                Your DCP Vault is ready to use
              </p>
            </div>

            <div className="card">
              <h3 style={{ marginBottom: '16px' }}>Your Wallets</h3>
              {wallets.map((wallet) => (
                <div key={wallet.chain} className="wallet-card">
                  <div className="wallet-info">
                    <div>
                      <div className="wallet-chain" style={{ textTransform: 'capitalize' }}>
                        {wallet.chain}
                      </div>
                      <div className="wallet-address">
                        {wallet.address}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <button
              className="btn btn-primary"
              onClick={onComplete}
              style={{ width: '100%', marginTop: '16px' }}
            >
              Open Vault
            </button>
          </>
        )}
      </div>
    </div>
  );
}
