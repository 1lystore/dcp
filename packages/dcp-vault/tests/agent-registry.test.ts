import { describe, it, expect, beforeEach } from 'vitest';
import { InMemoryAgentRegistry, type NewAgentRecord } from '../src/policy/agent-registry.js';

describe('AgentRegistry', () => {
  let registry: InMemoryAgentRegistry;

  beforeEach(() => {
    registry = new InMemoryAgentRegistry();
  });

  const createTestAgent = (overrides: Partial<NewAgentRecord> = {}): NewAgentRecord => ({
    agent_id: 'agent-' + Math.random().toString(36).slice(2),
    display_name: 'Test Agent',
    environment: 'local',
    public_key: 'test-public-key-base64',
    fingerprint: 'test-fingerprint-' + Math.random().toString(36).slice(2),
    status: 'pending',
    created_at: new Date().toISOString(),
    paired_at: null,
    ...overrides,
  });

  describe('register', () => {
    it('should register a new agent', async () => {
      const agent = createTestAgent();
      await registry.register(agent);

      const retrieved = await registry.get(agent.agent_id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.agent_id).toBe(agent.agent_id);
      expect(retrieved?.display_name).toBe('Test Agent');
      expect(retrieved?.status).toBe('pending');
      expect(retrieved?.request_count).toBe(0);
    });

    it('should initialize request_count to 0', async () => {
      const agent = createTestAgent();
      await registry.register(agent);

      const retrieved = await registry.get(agent.agent_id);
      expect(retrieved?.request_count).toBe(0);
    });
  });

  describe('get', () => {
    it('should return null for non-existent agent', async () => {
      const result = await registry.get('non-existent-id');
      expect(result).toBeNull();
    });

    it('should return the agent when found', async () => {
      const agent = createTestAgent();
      await registry.register(agent);

      const result = await registry.get(agent.agent_id);
      expect(result).not.toBeNull();
      expect(result?.agent_id).toBe(agent.agent_id);
    });
  });

  describe('getByFingerprint', () => {
    it('should find agent by fingerprint', async () => {
      const agent = createTestAgent({ fingerprint: 'unique-fingerprint-123' });
      await registry.register(agent);

      const result = await registry.getByFingerprint('unique-fingerprint-123');
      expect(result).not.toBeNull();
      expect(result?.agent_id).toBe(agent.agent_id);
    });

    it('should return null for unknown fingerprint', async () => {
      const result = await registry.getByFingerprint('unknown-fingerprint');
      expect(result).toBeNull();
    });
  });

  describe('updateStatus', () => {
    it('should update agent status', async () => {
      const agent = createTestAgent({ status: 'pending' });
      await registry.register(agent);

      await registry.updateStatus(agent.agent_id, 'connected');

      const retrieved = await registry.get(agent.agent_id);
      expect(retrieved?.status).toBe('connected');
    });

    it('should set paired_at when status changes to connected', async () => {
      const agent = createTestAgent({ status: 'pending', paired_at: null });
      await registry.register(agent);

      await registry.updateStatus(agent.agent_id, 'connected');

      const retrieved = await registry.get(agent.agent_id);
      expect(retrieved?.status).toBe('connected');
      expect(retrieved?.paired_at).not.toBeNull();
    });

    it('should set revoked_at when status changes to revoked', async () => {
      const agent = createTestAgent({ status: 'connected' });
      await registry.register(agent);

      await registry.updateStatus(agent.agent_id, 'revoked');

      const retrieved = await registry.get(agent.agent_id);
      expect(retrieved?.status).toBe('revoked');
      expect(retrieved?.revoked_at).not.toBeNull();
    });
  });

  describe('revoke', () => {
    it('should revoke an agent', async () => {
      const agent = createTestAgent({ status: 'connected' });
      await registry.register(agent);

      await registry.revoke(agent.agent_id);

      const retrieved = await registry.get(agent.agent_id);
      expect(retrieved?.status).toBe('revoked');
    });
  });

  describe('updateLastSeen', () => {
    it('should update last_seen timestamp', async () => {
      const agent = createTestAgent();
      await registry.register(agent);

      const before = await registry.get(agent.agent_id);
      expect(before?.last_seen).toBeNull();

      await registry.updateLastSeen(agent.agent_id);

      const after = await registry.get(agent.agent_id);
      expect(after?.last_seen).not.toBeNull();
    });
  });

  describe('incrementRequestCount', () => {
    it('should increment the request count', async () => {
      const agent = createTestAgent();
      await registry.register(agent);

      await registry.incrementRequestCount(agent.agent_id);
      await registry.incrementRequestCount(agent.agent_id);
      await registry.incrementRequestCount(agent.agent_id);

      const retrieved = await registry.get(agent.agent_id);
      expect(retrieved?.request_count).toBe(3);
    });
  });

  describe('list', () => {
    it('should list all agents', async () => {
      await registry.register(createTestAgent());
      await registry.register(createTestAgent());
      await registry.register(createTestAgent());

      const agents = await registry.list();
      expect(agents).toHaveLength(3);
    });

    it('should filter by status', async () => {
      await registry.register(createTestAgent({ status: 'pending' }));
      await registry.register(createTestAgent({ status: 'connected' }));
      await registry.register(createTestAgent({ status: 'connected' }));
      await registry.register(createTestAgent({ status: 'revoked' }));

      const pending = await registry.list('pending');
      expect(pending).toHaveLength(1);

      const connected = await registry.list('connected');
      expect(connected).toHaveLength(2);

      const revoked = await registry.list('revoked');
      expect(revoked).toHaveLength(1);
    });
  });

  describe('listActive', () => {
    it('should exclude revoked agents', async () => {
      await registry.register(createTestAgent({ status: 'pending' }));
      await registry.register(createTestAgent({ status: 'connected' }));
      await registry.register(createTestAgent({ status: 'revoked' }));

      const active = await registry.listActive();
      expect(active).toHaveLength(2);
      expect(active.every(a => a.status !== 'revoked')).toBe(true);
    });
  });

  describe('delete', () => {
    it('should delete an agent', async () => {
      const agent = createTestAgent();
      await registry.register(agent);

      expect(await registry.exists(agent.agent_id)).toBe(true);

      await registry.delete(agent.agent_id);

      expect(await registry.exists(agent.agent_id)).toBe(false);
    });
  });

  describe('exists', () => {
    it('should return true for existing agent', async () => {
      const agent = createTestAgent();
      await registry.register(agent);

      expect(await registry.exists(agent.agent_id)).toBe(true);
    });

    it('should return false for non-existent agent', async () => {
      expect(await registry.exists('non-existent')).toBe(false);
    });
  });
});
