import { useEffect, useState } from 'react';
import { api, type AuditEvent } from '../api';

const eventIcons: Record<string, string> = {
  GRANT: '✓',
  DENY: '✗',
  EXECUTE: '⚡',
  READ: '📖',
  REVOKE: '🚫',
  CONFIG: '⚙️',
  EXPIRE: '⏱️',
};

const eventColors: Record<string, string> = {
  GRANT: 'var(--success)',
  DENY: 'var(--danger)',
  EXECUTE: 'var(--accent)',
  READ: 'var(--text-secondary)',
  REVOKE: 'var(--warning)',
  CONFIG: 'var(--text-secondary)',
  EXPIRE: 'var(--text-muted)',
};

export default function Activity() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>('all');

  useEffect(() => {
    loadActivity();
  }, []);

  const loadActivity = async () => {
    try {
      const res = await api.getActivity(100);
      setEvents(res.events);
    } catch (err) {
      console.error('Failed to load activity:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
      </div>
    );
  }

  const filteredEvents = filter === 'all'
    ? events
    : events.filter(e => e.event_type === filter);

  const eventTypes = ['all', ...new Set(events.map(e => e.event_type))];

  return (
    <div>
      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Activity Log</h2>
            <p className="card-subtitle">Recent vault operations and events</p>
          </div>
          <button className="btn btn-secondary" onClick={loadActivity}>
            Refresh
          </button>
        </div>

        <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
          {eventTypes.map((type) => (
            <button
              key={type}
              onClick={() => setFilter(type)}
              className={`btn ${filter === type ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '6px 12px', fontSize: '12px' }}
            >
              {type === 'all' ? 'All' : type}
            </button>
          ))}
        </div>

        {filteredEvents.length === 0 ? (
          <div className="empty-state">
            <p>No activity recorded</p>
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
                  </div>
                  <div className="audit-details">
                    {event.agent_name && <span>Agent: {event.agent_name}</span>}
                    {event.scope && <span> • Scope: {event.scope}</span>}
                    {event.outcome && event.outcome !== 'success' && (
                      <span> • Outcome: {event.outcome}</span>
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
