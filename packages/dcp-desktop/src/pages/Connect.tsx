import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { open } from '@tauri-apps/plugin-shell';
import { api, type AgentConnection, type RelayInfo, type VpsPairingInviteResponse } from '../api';

// MCP status interface
interface McpStatus {
  running: boolean;
  unlocked: boolean;
}

// Local MCP agent status
interface LocalMcpStatus {
  configured: boolean;
  config_exists: boolean;
  connection_status: string;
  agent_id: string;
}

type Tab = 'local' | 'remote' | 'telegram';

const TELEGRAM_BOT_USERNAME = 'dcpagentBot';

interface TelegramConfig {
  configured: boolean;
  enabled?: boolean;
  chat_id?: string;
  paired_at?: string;
}

// Check if Telegram is fully paired (not just pending)
const isTelegramPaired = (config: TelegramConfig | null): boolean => {
  return !!(config?.configured && config?.enabled && config?.paired_at);
};

// Local AI agent types with their config instructions
type LocalAgentType = 'claude-desktop' | 'cursor' | 'vscode' | 'openclaw' | 'other';
const LOCAL_AGENT_TYPES: { id: LocalAgentType; label: string; configPath: string }[] = [
  { id: 'claude-desktop', label: 'Claude Desktop', configPath: 'Settings → Developer → Add MCP Server' },
  { id: 'cursor', label: 'Cursor', configPath: 'Cursor Settings → MCP → Add new global MCP server' },
  { id: 'vscode', label: 'VS Code', configPath: 'Cmd+Shift+P → "MCP: Add Server"' },
  { id: 'openclaw', label: 'OpenClaw', configPath: '~/.openclaw/openclaw.json' },
  { id: 'other', label: 'Other MCP Client', configPath: 'Check your app documentation' },
];

export default function Connect() {
  const [activeTab, setActiveTab] = useState<Tab>('local');

  // Relay state
  const [relayInfo, setRelayInfo] = useState<RelayInfo | null>(null);
  const [relayLoading, setRelayLoading] = useState(true);

  // Local AI / MCP state
  const [selectedAgentType, setSelectedAgentType] = useState<LocalAgentType>('claude-desktop');
  const [mcpConfigCopied, setMcpConfigCopied] = useState(false);
  const [mcpStatus, setMcpStatus] = useState<McpStatus | null>(null);
  const [localMcpStatus, setLocalMcpStatus] = useState<LocalMcpStatus | null>(null);
  const [localMcpSetupLoading, setLocalMcpSetupLoading] = useState(false);

  // Remote Agent state
  const [agentName, setAgentName] = useState('');
  const [pairResult, setPairResult] = useState<VpsPairingInviteResponse | null>(null);
  const [pairingLoading, setPairingLoading] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  // Telegram state
  const [telegramConfig, setTelegramConfig] = useState<TelegramConfig | null>(null);
  const [telegramLoading, setTelegramLoading] = useState(true);
  const [telegramCode, setTelegramCode] = useState<string | null>(null);
  const [telegramCodeExpires, setTelegramCodeExpires] = useState<string | null>(null);
  const [telegramPairing, setTelegramPairing] = useState(false);
  const [telegramTesting, setTelegramTesting] = useState(false);
  const telegramCodeRef = useRef<string | null>(null);

  // Connected agents state (for summary display)
  const [agentConnections, setAgentConnections] = useState<AgentConnection[]>([]);
  const [connectionsLoading, setConnectionsLoading] = useState(true);

  const getAgentDisplayStatus = (agent: AgentConnection): { status: string; color: string } => {
    if (agent.status === 'revoked' || agent.revoked_at) {
      return { status: 'revoked', color: 'var(--danger)' };
    }
    if (!agent.last_seen_at) {
      return { status: 'pending', color: 'var(--text-muted)' };
    }
    const lastSeen = new Date(agent.last_seen_at).getTime();
    const diffSeconds = (Date.now() - lastSeen) / 1000;
    if (diffSeconds < 60) return { status: 'active', color: 'var(--success)' };
    if (diffSeconds < 86400) return { status: 'stale', color: 'var(--warning)' };
    return { status: 'inactive', color: 'var(--text-muted)' };
  };

  const loadRelayInfo = useCallback(async () => {
    try {
      const data = await api.getRelayInfo();
      setRelayInfo(data);
    } catch (err) {
      console.error('Failed to load relay info:', err);
    } finally {
      setRelayLoading(false);
    }
  }, []);

  const loadAgentConnections = useCallback(async () => {
    try {
      const res = await api.getAgentConnections();
      setAgentConnections(res.agents || []);
    } catch (err) {
      console.error('Failed to load agent connections:', err);
    } finally {
      setConnectionsLoading(false);
    }
  }, []);

  const loadTelegramConfig = useCallback(async () => {
    try {
      const config = await api.getTelegramConfig();
      setTelegramConfig(config);
    } catch (err) {
      console.error('Failed to load telegram config:', err);
    } finally {
      setTelegramLoading(false);
    }
  }, []);

  const loadMcpStatus = useCallback(async () => {
    try {
      // Check vault health - if vault is unlocked, MCP can work
      const health = await api.health();
      // MCP is "running" if vault is initialized, "unlocked" if vault is unlocked
      setMcpStatus({
        running: health.initialized,
        unlocked: health.unlocked,
      });
    } catch (err) {
      console.error('Failed to load MCP status:', err);
      setMcpStatus(null);
    }
  }, []);

  const loadLocalMcpStatus = useCallback(async () => {
    try {
      const status = await api.getLocalMcpStatus();
      setLocalMcpStatus(status);
    } catch (err) {
      console.error('Failed to load local MCP status:', err);
      setLocalMcpStatus(null);
    }
  }, []);

  const setupLocalMcp = useCallback(async () => {
    setLocalMcpSetupLoading(true);
    try {
      const result = await api.setupLocalMcp(selectedAgentType);
      if (result.success) {
        setStatus(`${result.agent_name} agent added successfully`);
        await loadLocalMcpStatus();
        await loadAgentConnections();
      }
    } catch (err) {
      console.error('Failed to setup local MCP:', err);
      setStatus(err instanceof Error ? err.message : 'Failed to setup local MCP');
    } finally {
      setLocalMcpSetupLoading(false);
    }
  }, [loadLocalMcpStatus, loadAgentConnections, selectedAgentType]);

  // Separate function to check pairing status with cloud
  const checkTelegramPairing = useCallback(async () => {
    try {
      const status = await api.getTelegramPairingStatus();
      if (status.paired) {
        // Cloud confirmed pairing - now get updated local config
        const config = await api.getTelegramConfig();
        setTelegramConfig(config);
        setTelegramCode(null);
        setTelegramCodeExpires(null);
        return true;
      }
      return false;
    } catch (err) {
      console.error('Failed to check telegram pairing:', err);
      return false;
    }
  }, []);

  useEffect(() => {
    void loadRelayInfo();
    void loadAgentConnections();
    void loadTelegramConfig();
    void loadMcpStatus();
    void loadLocalMcpStatus();
  }, [loadAgentConnections, loadRelayInfo, loadTelegramConfig, loadMcpStatus, loadLocalMcpStatus]);

  // Removed auto-setup - user must explicitly click "Add Agent" button (per protocol spec Task 6.2)

  // Keep ref in sync with state
  useEffect(() => {
    telegramCodeRef.current = telegramCode;
  }, [telegramCode]);

  // Separate polling effect - uses ref to avoid re-creating interval
  useEffect(() => {
    const interval = window.setInterval(() => {
      if (!api.hasOwnerToken()) return;
      void loadAgentConnections();
      void loadRelayInfo();
      void loadMcpStatus();
      void loadLocalMcpStatus();
      // Check telegram pairing status if code was generated
      if (telegramCodeRef.current) {
        void checkTelegramPairing();
      }
    }, 5000);
    return () => window.clearInterval(interval);
  }, [loadAgentConnections, loadRelayInfo, loadMcpStatus, loadLocalMcpStatus, checkTelegramPairing]);

  const createVpsInvite = async () => {
    const name = agentName.trim();
    if (!name) {
      setStatus('Give your agent a name');
      return;
    }

    setPairingLoading(true);
    setStatus(null);

    try {
      const res = await api.createVpsPairingInvite({
        agent_name: name,
        ttl_ms: 3600000, // 1 hour
      });
      setPairResult(res);
      setStatus(`VPS invite generated for "${res.agent_name}"`);
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Failed to create VPS invite');
    } finally {
      setPairingLoading(false);
    }
  };

  const copyToken = async () => {
    if (!pairResult?.token) return;
    try {
      await navigator.clipboard.writeText(pairResult.token);
      setStatus('Token copied!');
    } catch {
      setStatus('Failed to copy');
    }
  };

  // Agent ID mapping
  const agentIdMap: Record<LocalAgentType, string> = {
    'claude-desktop': 'agent_claude_desktop',
    'cursor': 'agent_cursor',
    'vscode': 'agent_vscode',
    'openclaw': 'agent_openclaw_local',
    'other': 'agent_local_mcp',
  };

  // MCP config for the selected agent type (uses npx for zero-install)
  const mcpConfig = useMemo(() => {
    const serverConfig = {
      command: 'npx',
      args: ['-y', '@dcprotocol/agent', 'run', '--mode', 'mcp', '--agent', agentIdMap[selectedAgentType]],
    };

    if (selectedAgentType === 'openclaw') {
      return `openclaw mcp set dcp '${JSON.stringify(serverConfig)}'`;
    }

    return JSON.stringify({
      mcpServers: {
        dcp: serverConfig,
      },
    }, null, 2);
  }, [selectedAgentType]);

  const copyMcpConfig = async () => {
    try {
      await navigator.clipboard.writeText(mcpConfig);
      setMcpConfigCopied(true);
      setTimeout(() => setMcpConfigCopied(false), 2000);
    } catch {
      setStatus('Failed to copy');
    }
  };

  // Generate one-click install deep link for Cursor/VS Code
  const getInstallDeepLink = useMemo(() => {
    const serverConfig = {
      command: 'npx',
      args: ['-y', '@dcprotocol/agent', 'run', '--mode', 'mcp', '--agent', agentIdMap[selectedAgentType]],
    };

    if (selectedAgentType === 'cursor') {
      // Cursor: cursor://anysphere.cursor-deeplink/mcp/install?name=X&config=BASE64
      const configBase64 = btoa(JSON.stringify(serverConfig));
      return `cursor://anysphere.cursor-deeplink/mcp/install?name=dcp&config=${configBase64}`;
    }

    if (selectedAgentType === 'vscode') {
      // VS Code: vscode:mcp/install?URL_ENCODED_JSON
      const configWithName = { name: 'dcp', ...serverConfig };
      return `vscode:mcp/install?${encodeURIComponent(JSON.stringify(configWithName))}`;
    }

    return null;
  }, [selectedAgentType]);

  // Telegram handlers
  const startTelegramPairing = async (forceNew = false) => {
    // If we have an active code that hasn't expired, reuse it
    if (!forceNew && telegramCode && telegramCodeExpires) {
      const expiresAt = new Date(telegramCodeExpires).getTime();
      if (expiresAt > Date.now()) {
        // Code still valid, just show it again
        return;
      }
    }

    setTelegramPairing(true);
    try {
      const res = await api.startTelegramPairing();
      setTelegramCode(res.code);
      setTelegramCodeExpires(res.expires_at);
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Failed to start pairing');
    } finally {
      setTelegramPairing(false);
    }
  };

  const sendTelegramTest = async () => {
    setTelegramTesting(true);
    try {
      await api.sendTelegramTest();
      setStatus('Test notification sent!');
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Failed to send test');
    } finally {
      setTelegramTesting(false);
    }
  };

  const unlinkTelegram = async () => {
    try {
      await api.unlinkTelegram();
      setTelegramConfig(null);
      setTelegramCode(null);
      setStatus('Telegram unlinked');
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Failed to unlink');
    }
  };

  const tabs = [
    { id: 'local' as Tab, label: 'Local AI', icon: '💻' },
    { id: 'remote' as Tab, label: 'Remote Agent', icon: '🌐' },
    { id: 'telegram' as Tab, label: 'Telegram', icon: '📱' },
  ];

  return (
    <div className="page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>Connect</h2>
          <p className="muted">Connect AI assistants to your vault</p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          {/* MCP Status Badge */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 12px',
            background: localMcpStatus?.configured && mcpStatus?.unlocked
              ? 'rgba(34, 197, 94, 0.1)'
              : localMcpStatus?.configured || mcpStatus?.running
                ? 'rgba(234, 179, 8, 0.1)'
                : 'rgba(100, 100, 100, 0.1)',
            border: `1px solid ${localMcpStatus?.configured && mcpStatus?.unlocked
              ? 'var(--success)'
              : localMcpStatus?.configured || mcpStatus?.running
                ? 'var(--warning)'
                : 'var(--text-muted)'}`,
            borderRadius: '8px',
          }}>
            <span style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: localMcpStatus?.configured && mcpStatus?.unlocked
                ? 'var(--success)'
                : localMcpStatus?.configured || mcpStatus?.running
                  ? 'var(--warning)'
                  : 'var(--text-muted)',
            }} />
            <span style={{ fontSize: '13px' }}>
              {localMcpStatus?.configured && mcpStatus?.unlocked
                ? 'MCP Ready'
                : localMcpStatus?.configured
                  ? 'MCP Locked'
                  : mcpStatus?.running
                    ? 'MCP Setup Needed'
                    : 'MCP Offline'}
            </span>
          </div>
          {/* Relay Status Badge */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 12px',
            background: relayInfo?.relay_connected ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
            border: `1px solid ${relayInfo?.relay_connected ? 'var(--success)' : 'var(--danger)'}`,
            borderRadius: '8px',
          }}>
            <span style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: relayInfo?.relay_connected ? 'var(--success)' : 'var(--danger)',
            }} />
            <span style={{ fontSize: '13px' }}>
              {relayLoading ? 'Checking...' : relayInfo?.relay_connected ? 'Relay Connected' : 'Relay Offline'}
            </span>
          </div>
        </div>
      </div>

      {/* Tab Selector */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '20px' }}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`btn ${activeTab === tab.id ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '10px 20px', fontSize: '14px' }}
          >
            <span style={{ marginRight: '8px' }}>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Local AI Tab */}
      {activeTab === 'local' && (
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Local AI Agent</h3>
              <p className="card-subtitle">Connect a local AI assistant to your vault</p>
            </div>
          </div>

          <div style={{ display: 'grid', gap: '16px' }}>
            {/* Status Section */}
            {localMcpStatus?.configured && (
              <div style={{
                padding: '16px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
                border: `1px solid ${mcpStatus?.unlocked ? 'var(--success)' : 'var(--warning)'}`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{
                    width: '10px',
                    height: '10px',
                    borderRadius: '50%',
                    background: mcpStatus?.unlocked ? 'var(--success)' : 'var(--warning)',
                  }} />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '14px' }}>
                      {mcpStatus?.unlocked ? 'Local Agent Ready' : 'Vault Locked'}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {mcpStatus?.unlocked
                        ? 'Your vault is unlocked and ready for AI access'
                        : 'Unlock your vault to allow AI access'}
                    </div>
                  </div>
                  {mcpStatus?.unlocked && <span style={{ marginLeft: 'auto', fontSize: '20px' }}>✓</span>}
                </div>
              </div>
            )}

            {/* Step 1: Choose Agent Type */}
            <div style={{
              padding: '16px',
              background: 'var(--bg-tertiary)',
              borderRadius: '8px',
              border: '1px solid var(--border)'
            }}>
              <div style={{ fontSize: '14px', fontWeight: 600, marginBottom: '12px' }}>
                1. Choose your AI assistant
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
                {LOCAL_AGENT_TYPES.map((agent) => (
                  <button
                    key={agent.id}
                    onClick={() => setSelectedAgentType(agent.id)}
                    className={`btn ${selectedAgentType === agent.id ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ padding: '12px', fontSize: '13px', textAlign: 'left' }}
                  >
                    {agent.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Step 2: Copy Config */}
            <div style={{
              padding: '16px',
              background: 'var(--bg-tertiary)',
              borderRadius: '8px',
              border: '1px solid var(--border)'
            }}>
              <div style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>
                2. Add to your MCP config
              </div>

              {/* One-click install for Cursor/VS Code */}
              {getInstallDeepLink && (
                <div style={{ marginBottom: '16px' }}>
                  <button
                    onClick={() => open(getInstallDeepLink)}
                    className="btn btn-primary"
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '8px',
                      width: '100%',
                      justifyContent: 'center',
                      padding: '12px',
                    }}
                  >
                    ⚡ One-Click Install in {LOCAL_AGENT_TYPES.find(a => a.id === selectedAgentType)?.label}
                  </button>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textAlign: 'center', marginTop: '8px' }}>
                    or copy config manually below
                  </div>
                </div>
              )}

              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                <code>{LOCAL_AGENT_TYPES.find(a => a.id === selectedAgentType)?.configPath}</code>
              </div>
              <pre style={{
                background: 'var(--bg-secondary)',
                padding: '12px',
                borderRadius: '6px',
                fontSize: '12px',
                overflow: 'auto',
                margin: '0 0 12px 0'
              }}>
                {mcpConfig}
              </pre>
              <button className="btn btn-primary" onClick={copyMcpConfig}>
                {mcpConfigCopied ? 'Copied!' : 'Copy Config'}
              </button>
            </div>

            {/* Step 3: Add Agent - always show so users can add multiple agents */}
            <div style={{
              padding: '16px',
              background: 'var(--bg-tertiary)',
              borderRadius: '8px',
              border: '1px solid var(--border)'
            }}>
              <div style={{ fontSize: '14px', fontWeight: 600, marginBottom: '12px' }}>
                3. Register local agent
              </div>
              <button
                className="btn btn-primary"
                onClick={setupLocalMcp}
                disabled={localMcpSetupLoading}
                style={{ width: '100%' }}
              >
                {localMcpSetupLoading ? 'Adding Agent...' : `Add ${LOCAL_AGENT_TYPES.find(a => a.id === selectedAgentType)?.label} Agent`}
              </button>
            </div>

            <div style={{
              padding: '12px 16px',
              background: 'rgba(59, 130, 246, 0.1)',
              border: '1px solid rgba(59, 130, 246, 0.3)',
              borderRadius: '8px',
              fontSize: '13px',
            }}>
              <strong>Important:</strong> Keep this DCP Vault app open and unlocked while using your AI assistant.
            </div>
          </div>
        </div>
      )}

      {/* Remote Agent Tab */}
      {activeTab === 'remote' && (
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Remote Agent - VPS / OpenClaw</h3>
              <p className="card-subtitle">Generate an invite token for remote VPS agents</p>
            </div>
          </div>

          {!pairResult ? (
            <div style={{ display: 'grid', gap: '16px' }}>
              <div>
                <label className="label">Agent Name</label>
                <input
                  className="input"
                  value={agentName}
                  onChange={(e) => setAgentName(e.target.value)}
                  placeholder="e.g., my-trading-bot"
                />
              </div>

              <div style={{
                padding: '12px 16px',
                background: 'rgba(59, 130, 246, 0.1)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '8px',
                fontSize: '13px',
              }}>
                <strong>How it works:</strong> Generate an invite token, run it on your VPS, then verify the pairing phrase displayed on both sides.
                You'll set permissions when approving the connection.
              </div>

              <button
                className="btn btn-primary"
                onClick={createVpsInvite}
                disabled={pairingLoading || !agentName.trim()}
              >
                {pairingLoading ? 'Generating...' : 'Generate VPS Invite'}
              </button>
            </div>
          ) : (
            <div style={{ display: 'grid', gap: '16px' }}>
              <div style={{
                padding: '20px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
                border: '1px solid var(--success)',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--success)', marginBottom: '8px' }}>
                  VPS Invite Generated!
                </div>
                <div style={{ fontSize: '13px' }}>
                  Agent: <strong>{pairResult.agent_name}</strong>
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Expires: {new Date(pairResult.expires_at).toLocaleTimeString()}
                </div>
              </div>

              <div style={{
                padding: '16px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
              }}>
                <div style={{ fontSize: '13px', fontWeight: 600, marginBottom: '8px' }}>
                  Run on your VPS:
                </div>
                <pre style={{
                  background: 'var(--bg-secondary)',
                  padding: '12px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  overflow: 'auto',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  margin: 0,
                }}>
{`sudo npx --yes @dcprotocol/agent install-service '${pairResult.token}'`}
                </pre>
              </div>

              <div style={{
                padding: '12px 16px',
                background: 'rgba(234, 179, 8, 0.1)',
                border: '1px solid var(--warning)',
                borderRadius: '8px',
                fontSize: '13px',
                color: 'var(--warning)',
              }}>
                ⏳ After running, a pairing request will appear on the <strong>Agents</strong> page. Verify the phrase matches before approving!
              </div>

              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <button
                  className="btn btn-primary"
                  onClick={async () => {
                    await navigator.clipboard.writeText(`sudo npx --yes @dcprotocol/agent install-service '${pairResult.token}'`);
                    setStatus('Command copied!');
                  }}
                >
                  Copy Command
                </button>
                <button className="btn btn-secondary" onClick={copyToken}>
                  Copy Token Only
                </button>
                <button className="btn btn-secondary" onClick={() => {
                  setPairResult(null);
                  setAgentName('');
                }}>
                  Create Another
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Telegram Tab */}
      {activeTab === 'telegram' && (
        <div className="card">
          <div className="card-header">
            <div>
              <h3 className="card-title">Telegram Notifications</h3>
              <p className="card-subtitle">Get notified when agents need approval</p>
            </div>
          </div>

          {telegramLoading ? (
            <div style={{ padding: '20px', textAlign: 'center' }}>
              <div className="spinner" />
            </div>
          ) : isTelegramPaired(telegramConfig) ? (
            // Already paired
            <div style={{ display: 'grid', gap: '16px' }}>
              <div style={{
                padding: '20px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
                border: '1px solid var(--success)',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
              }}>
                <span style={{ fontSize: '24px' }}>✓</span>
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--success)' }}>Telegram Connected</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Paired {telegramConfig?.paired_at ? new Date(telegramConfig.paired_at).toLocaleDateString() : 'recently'}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  className="btn btn-secondary"
                  onClick={sendTelegramTest}
                  disabled={telegramTesting}
                >
                  {telegramTesting ? 'Sending...' : 'Send Test Notification'}
                </button>
                <button className="btn btn-danger" onClick={unlinkTelegram}>
                  Unlink Telegram
                </button>
              </div>
            </div>
          ) : telegramCode ? (
            // Pairing in progress
            <div style={{ display: 'grid', gap: '16px' }}>
              <div style={{
                padding: '24px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
                textAlign: 'center',
              }}>
                <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '12px' }}>
                  Pair with Telegram:
                </div>
                <div style={{
                  fontSize: '32px',
                  fontWeight: 700,
                  fontFamily: 'monospace',
                  letterSpacing: '8px',
                  color: 'var(--accent)',
                  marginBottom: '8px',
                }}>
                  {telegramCode}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Expires {telegramCodeExpires ? new Date(telegramCodeExpires).toLocaleTimeString() : 'soon'}
                </div>
              </div>

              <a
                href={`https://t.me/${TELEGRAM_BOT_USERNAME}?start=pair_${telegramCode}`}
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-primary"
                style={{ textAlign: 'center', textDecoration: 'none' }}
              >
                Open Telegram
              </a>

              <div style={{
                padding: '12px 16px',
                background: 'rgba(234, 179, 8, 0.1)',
                border: '1px solid var(--warning)',
                borderRadius: '8px',
                fontSize: '13px',
                color: 'var(--warning)',
                textAlign: 'center',
              }}>
                Waiting for Telegram pairing. If Telegram does not complete it automatically, send /pair {telegramCode}.
              </div>

              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <button
                  className="btn btn-secondary"
                  onClick={checkTelegramPairing}
                  style={{ flex: 1 }}
                >
                  🔄 Refresh Status
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() => startTelegramPairing(true)}
                  disabled={telegramPairing}
                  style={{ flex: 1 }}
                >
                  🔑 Get New Code
                </button>
              </div>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  setTelegramCode(null);
                  setTelegramCodeExpires(null);
                }}
                style={{ width: '100%', opacity: 0.7 }}
              >
                Cancel
              </button>
            </div>
          ) : (
            // Not paired
            <div style={{ display: 'grid', gap: '16px' }}>
              <div style={{
                padding: '24px',
                background: 'var(--bg-tertiary)',
                borderRadius: '8px',
                textAlign: 'center',
              }}>
                <div style={{ fontSize: '48px', marginBottom: '16px' }}>📱</div>
                <div style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                  Connect Telegram to receive notifications when agents need approval.
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Perfect for approving requests on the go.
                </div>
              </div>

              <button
                className="btn btn-primary"
                onClick={() => startTelegramPairing(false)}
                disabled={telegramPairing}
                style={{ padding: '12px 24px' }}
              >
                {telegramPairing ? 'Generating Code...' : 'Connect Telegram'}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Status Message */}
      {status && (
        <div style={{
          padding: '12px 16px',
          background: 'var(--bg-tertiary)',
          borderRadius: '8px',
          fontSize: '13px',
          color: 'var(--text-secondary)',
          marginTop: '16px',
        }}>
          {status}
        </div>
      )}

      {/* Connected Agents Summary */}
      <div className="card" style={{ marginTop: '20px' }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '16px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '50%',
              background: 'var(--bg-tertiary)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2">
                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                <circle cx="9" cy="7" r="4"/>
                <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
                <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
              </svg>
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '15px' }}>
                {connectionsLoading ? '...' : agentConnections.length} Connected Agents
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                {connectionsLoading
                  ? 'Loading...'
                  : agentConnections.filter(a => getAgentDisplayStatus(a).status === 'active').length + ' active'}
              </div>
            </div>
          </div>
          <a
            href="/agents"
            onClick={(e) => {
              e.preventDefault();
              window.location.href = '/agents';
            }}
            className="btn btn-primary"
            style={{ textDecoration: 'none' }}
          >
            Manage Agents
          </a>
        </div>
      </div>
    </div>
  );
}
