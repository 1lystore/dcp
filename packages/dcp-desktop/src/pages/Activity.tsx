import { useEffect, useState, useMemo } from 'react';
import { api, type AuditEvent } from '../api';

const eventIcons: Record<string, string> = {
  GRANT: '✓',
  DENY: '✗',
  EXECUTE: '⚡',
  READ: '📖',
  REVOKE: '🚫',
  CONFIG: '⚙️',
  EXPIRE: '⏱️',
  SIGN: '✍️',
  UNLOCK: '🔓',
  LOCK: '🔒',
};

const eventColors: Record<string, string> = {
  GRANT: 'var(--success)',
  DENY: 'var(--danger)',
  EXECUTE: 'var(--accent)',
  READ: 'var(--text-secondary)',
  REVOKE: 'var(--warning)',
  CONFIG: 'var(--text-secondary)',
  EXPIRE: 'var(--text-muted)',
  SIGN: 'var(--accent)',
  UNLOCK: 'var(--success)',
  LOCK: 'var(--warning)',
};

export default function Activity() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [agentFilter, setAgentFilter] = useState<string>('all');
  const [surfaceFilter, setSurfaceFilter] = useState<string>('all');

  useEffect(() => {
    loadActivity();
  }, []);

  const loadActivity = async () => {
    setLoading(true);
    try {
      const res = await api.getActivity(100);
      setEvents(res.events);
    } catch (err) {
      console.error('Failed to load activity:', err);
    } finally {
      setLoading(false);
    }
  };

  // Get unique agents from events
  const agents = useMemo(() => {
    const agentNames = new Set<string>();
    events.forEach(e => {
      if (e.agent_name) agentNames.add(e.agent_name);
    });
    return ['all', ...Array.from(agentNames).sort()];
  }, [events]);

  // Get unique surfaces from events (if available in details)
  const surfaces = useMemo(() => {
    const surfaceSet = new Set<string>();
    events.forEach(e => {
      const surface = e.details?.surface as string | undefined;
      if (surface) surfaceSet.add(surface);
    });
    return surfaceSet.size > 0 ? ['all', ...Array.from(surfaceSet).sort()] : [];
  }, [events]);

  // Event types
  const eventTypes = useMemo(() => {
    return ['all', ...new Set(events.map(e => e.event_type))];
  }, [events]);

  // Filter events
  const filteredEvents = useMemo(() => {
    return events.filter(event => {
      // Type filter
      if (typeFilter !== 'all' && event.event_type !== typeFilter) return false;
      // Agent filter
      if (agentFilter !== 'all' && event.agent_name !== agentFilter) return false;
      // Surface filter (if available in details)
      if (surfaceFilter !== 'all') {
        const surface = event.details?.surface as string | undefined;
        if (surface !== surfaceFilter) return false;
      }
      return true;
    });
  }, [events, typeFilter, agentFilter, surfaceFilter]);

  const clearFilters = () => {
    setTypeFilter('all');
    setAgentFilter('all');
    setSurfaceFilter('all');
  };

  const hasActiveFilters = typeFilter !== 'all' || agentFilter !== 'all' || surfaceFilter !== 'all';

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
      </div>
    );
  }

  return (
    <div className="page">
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Activity Log</h2>
            <p className="card-subtitle">
              {filteredEvents.length} of {events.length} events
              {hasActiveFilters && ' (filtered)'}
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            {hasActiveFilters && (
              <button className="btn btn-secondary" onClick={clearFilters} style={{ fontSize: '12px' }}>
                Clear Filters
              </button>
            )}
            <button className="btn btn-secondary" onClick={loadActivity}>
              Refresh
            </button>
          </div>
        </div>

        {/* Filters */}
        <div style={{ display: 'grid', gap: '12px', marginBottom: '20px' }}>
          {/* Event Type Filter */}
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '6px' }}>
              Event Type
            </div>
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
              {eventTypes.map((type) => (
                <button
                  key={type}
                  onClick={() => setTypeFilter(type)}
                  className={`btn ${typeFilter === type ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '4px 10px', fontSize: '11px' }}
                >
                  {type === 'all' ? 'All Types' : type}
                </button>
              ))}
            </div>
          </div>

          {/* Agent Filter */}
          {agents.length > 1 && (
            <div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '6px' }}>
                Agent
              </div>
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {agents.map((agent) => (
                  <button
                    key={agent}
                    onClick={() => setAgentFilter(agent)}
                    className={`btn ${agentFilter === agent ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ padding: '4px 10px', fontSize: '11px' }}
                  >
                    {agent === 'all' ? 'All Agents' : agent}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Surface Filter (Desktop/Telegram) - only show if data has surface info */}
          {surfaces.length > 0 && (
            <div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '6px' }}>
                Approval Surface
              </div>
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {surfaces.map((surface) => (
                  <button
                    key={surface}
                    onClick={() => setSurfaceFilter(surface)}
                    className={`btn ${surfaceFilter === surface ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ padding: '4px 10px', fontSize: '11px' }}
                  >
                    {surface === 'all' ? 'All Surfaces' : surface}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Events List */}
        {filteredEvents.length === 0 ? (
          <div className="empty-state">
            <p>{hasActiveFilters ? 'No events match the current filters' : 'No activity recorded'}</p>
          </div>
        ) : (
          <div>
            {filteredEvents.map((event) => (
              <div key={event.id} className="audit-item">
                <div
                  className="audit-icon"
                  style={{ color: eventColors[event.event_type] || 'var(--text-secondary)' }}
                >
                  {eventIcons[event.event_type] || '•'}
                </div>
                <div className="audit-content">
                  <div className="audit-title">
                    <span style={{ color: eventColors[event.event_type] }}>
                      {event.event_type}
                    </span>
                    {event.operation && (
                      <span style={{ color: 'var(--text-secondary)', marginLeft: '8px' }}>
                        {event.operation}
                      </span>
                    )}
                    {typeof event.details?.surface === 'string' && (
                      <span style={{
                        fontSize: '10px',
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: 'var(--bg-secondary)',
                        color: 'var(--text-muted)',
                        marginLeft: '8px',
                      }}>
                        {event.details.surface as string}
                      </span>
                    )}
                  </div>
                  <div className="audit-details">
                    {event.agent_name && <span>Agent: {event.agent_name}</span>}
                    {event.scope && <span> • Scope: {event.scope}</span>}
                    {event.outcome && event.outcome !== 'success' && (
                      <span style={{ color: 'var(--danger)' }}> • {event.outcome}</span>
                    )}
                  </div>
                </div>
                <div className="audit-time">
                  {new Date(event.created_at).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
