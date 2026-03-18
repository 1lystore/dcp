import { useEffect, useState, useCallback, useRef } from 'react';
import { Routes, Route, NavLink, useNavigate } from 'react-router-dom';
import { invoke } from '@tauri-apps/api/core';
import { api, type HealthResponse } from './api';

import Dashboard from './pages/Dashboard';
import Consent from './pages/Consent';
import Data from './pages/Data';
import Activity from './pages/Activity';
import Settings from './pages/Settings';
import Connect from './pages/Connect';
import Onboarding from './pages/Onboarding';
import Unlock from './pages/Unlock';

type AppState = 'loading' | 'no-server' | 'no-vault' | 'locked' | 'unlocked';

interface DesktopCredentials {
  desktop_id: string;
  public_key: string;
  is_new: boolean;
}

export default function App() {
  const [appState, setAppState] = useState<AppState>('loading');
  const [_health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ownerAuthenticated, setOwnerAuthenticated] = useState(false);
  const [onboardingActive, setOnboardingActive] = useState(false);
  const [forceOnboarding, setForceOnboarding] = useState(false);
  const navigate = useNavigate();
  const authAttempted = useRef(false);
  const onboardingLock = useRef(false);

  // Authenticate as owner (challenge-response with Ed25519 keypair)
  const authenticateOwner = useCallback(async () => {
    if (authAttempted.current) {
      return;
    }
    authAttempted.current = true;
    let authenticated = false;

    try {
      // Step 1: Get or create desktop credentials
      const credentials = await invoke<DesktopCredentials>('get_or_create_desktop_credentials');

      // Step 2: Register with server if new credentials
      if (credentials.is_new) {
        try {
          await invoke<boolean>('register_desktop', {
            desktop_id: credentials.desktop_id,
            public_key: credentials.public_key,
          });
        } catch (err) {
          console.error('Failed to register desktop:', err);
          // Continue anyway - might already be registered
        }
      }

      // Step 3: Authenticate to get owner token
      try {
        const token = await invoke<string>('authenticate_owner');
        api.setOwnerToken(token);
        setOwnerAuthenticated(true);
        authenticated = true;
      } catch (err) {
        console.error('Owner authentication failed:', err);
        // Try to register and authenticate again
        try {
          await invoke<boolean>('register_desktop', {
            desktop_id: credentials.desktop_id,
            public_key: credentials.public_key,
          });
          const token = await invoke<string>('authenticate_owner');
          api.setOwnerToken(token);
          setOwnerAuthenticated(true);
          authenticated = true;
        } catch (retryErr) {
          console.error('Owner auth retry failed:', retryErr);
          // Continue without owner mode - will require consent
        }
      }
    } catch (err) {
      console.error('Failed to get desktop credentials:', err);
    }

    if (!authenticated) {
      // Allow future retries (e.g., if server was not ready yet)
      authAttempted.current = false;
    }
  }, []);

  const checkServer = useCallback(async () => {
    try {
      const h = await api.health();
      setHealth(h);
      setError(null);

      if (forceOnboarding || onboardingLock.current || onboardingActive || appState === 'no-vault') {
        return;
      }

      if (!h.initialized) {
        setAppState('no-vault');
        api.setOwnerToken(null);
        setOwnerAuthenticated(false);
        authAttempted.current = false;
        return;
      }

      if (h.unlocked) {
        setAppState('unlocked');
        // Authenticate as owner when vault is unlocked
        if (!ownerAuthenticated) {
          void authenticateOwner();
        }
      } else {
        setAppState('locked');
        // Clear owner token when locked
        api.setOwnerToken(null);
        setOwnerAuthenticated(false);
        authAttempted.current = false;
      }
    } catch (err) {
      // Server not running - try to start it
      try {
        await invoke('start_server');
        // Wait a bit and retry
        setTimeout(checkServer, 1000);
      } catch {
        setAppState('no-server');
        setError('Could not start DCP server');
      }
    }
  }, [ownerAuthenticated, authenticateOwner]);

  useEffect(() => {
    checkServer();
    // Poll health every 5 seconds
    const interval = setInterval(checkServer, 5000);
    return () => clearInterval(interval);
  }, [checkServer]);

  useEffect(() => {
    if (appState === 'no-vault') {
      setOnboardingActive(true);
      onboardingLock.current = true;
    }
  }, [appState]);

  const handleUnlock = async (passphrase: string) => {
    try {
      await api.unlock(passphrase);
      await checkServer();
      navigate('/');
    } catch (err) {
      throw err;
    }
  };

  const handleLock = async () => {
    try {
      await api.lock();
      // Clear owner token on lock
      api.setOwnerToken(null);
      setOwnerAuthenticated(false);
      authAttempted.current = false;
      await invoke('clear_owner_token');
      await checkServer();
    } catch (err) {
      console.error('Failed to lock vault:', err);
    }
  };

  const handleResetVault = async () => {
    try {
      setOnboardingActive(true);
      onboardingLock.current = true;
      setForceOnboarding(true);
      await invoke('reset_vault');
      api.setOwnerToken(null);
      setOwnerAuthenticated(false);
      authAttempted.current = false;
      setAppState('no-vault');
    } catch (err) {
      console.error('Failed to reset vault:', err);
      setError('Failed to reset vault');
      setOnboardingActive(false);
      setForceOnboarding(false);
    }
  };

  const handleOnboardingComplete = () => {
    setOnboardingActive(false);
    onboardingLock.current = false;
    setForceOnboarding(false);
    checkServer();
    navigate('/');
  };

  // Loading state
  if (appState === 'loading') {
    return (
      <div className="app">
        <div className="loading">
          <div className="spinner" />
        </div>
      </div>
    );
  }

  // Server not running
  if (appState === 'no-server') {
    return (
      <div className="app">
        <div className="main-content">
          <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
            <h2 style={{ marginBottom: '16px' }}>Starting DCP Server...</h2>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '24px' }}>
              {error || 'Please wait while the server starts.'}
            </p>
            <button className="btn btn-primary" onClick={checkServer}>
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  // No vault initialized - show onboarding
  if (forceOnboarding || appState === 'no-vault') {
    return (
      <Onboarding
        onBegin={() => {
          setOnboardingActive(true);
          onboardingLock.current = true;
        }}
        onComplete={handleOnboardingComplete}
      />
    );
  }

  // Vault is locked
  if (appState === 'locked') {
    return <Unlock onUnlock={handleUnlock} onSetupNew={handleResetVault} />;
  }

  // Main app - vault is unlocked
  return (
    <div className="app">
      <header className="header">
        <div className="header-title">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 2L3 7V12C3 16.97 6.84 21.56 12 23C17.16 21.56 21 16.97 21 12V7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M9 12L11 14L15 10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          <h1>DCP Vault</h1>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className="status-badge unlocked">
            <span className="status-dot unlocked" />
            Unlocked
          </span>
          <button className="btn btn-secondary" onClick={handleLock} style={{ padding: '6px 12px' }}>
            Lock
          </button>
        </div>
      </header>

      <main className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/consent" element={<Consent />} />
          <Route path="/data" element={<Data />} />
          <Route path="/activity" element={<Activity />} />
          <Route path="/connect" element={<Connect />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>

      <nav className="nav">
        <NavLink to="/" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
            <polyline points="9 22 9 12 15 12 15 22"/>
          </svg>
          Dashboard
        </NavLink>
        <NavLink to="/consent" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M9 11l3 3L22 4"/>
            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
          </svg>
          Consent
        </NavLink>
        <NavLink to="/data" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <ellipse cx="12" cy="5" rx="9" ry="3"/>
            <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
          </svg>
          Data
        </NavLink>
        <NavLink to="/activity" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
          Activity
        </NavLink>
        <NavLink to="/connect" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M7 8a4 4 0 0 1 8 0"/>
            <rect x="3" y="12" width="18" height="9" rx="2"/>
            <path d="M12 16v2"/>
          </svg>
          Connect
        </NavLink>
        <NavLink to="/settings" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="3"/>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
          </svg>
          Settings
        </NavLink>
      </nav>
    </div>
  );
}
