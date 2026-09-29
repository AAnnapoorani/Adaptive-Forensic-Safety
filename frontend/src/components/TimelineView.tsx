import React, { useState } from 'react';
import type { TimelineEvent } from '../types';
import { Clock, Cpu, Network, FileText, ShieldAlert, Flag, Filter } from 'lucide-react';
import { formatDateTime } from '../utils/date';

interface TimelineViewProps {
  events: TimelineEvent[];
}

export const TimelineView: React.FC<TimelineViewProps> = ({ events }) => {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [filterRound, setFilterRound] = useState<number | 'ALL'>('ALL');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'PROCESS_CREATED': return <Cpu size={15} color="#38bdf8" />;
      case 'NETWORK_SOCKET_ACTIVE': return <Network size={15} color="#06b6d4" />;
      case 'FILE_MODIFIED': return <FileText size={15} color="#a855f7" />;
      case 'SYSTEM_EVENT_LOG': return <ShieldAlert size={15} color="#f59e0b" />;
      case 'WORKFLOW_ROUND_STARTED':
      case 'WORKFLOW_ROUND_COMPLETED':
        return <Flag size={15} color="#10b981" />;
      default: return <Clock size={15} color="#94a3b8" />;
    }
  };

  const filteredEvents = events.filter(e => {
    if (filterType !== 'ALL' && e.event_type !== filterType) return false;
    if (filterRound !== 'ALL' && e.round_number !== filterRound) return false;
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Controls & Filter Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, padding: '12px 18px', background: 'var(--bg-item)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 13 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)' }}>
            <Filter size={15} />
            <span>Event Category:</span>
          </div>
          <select
            value={filterType}
            onChange={e => setFilterType(e.target.value)}
            style={{ background: 'var(--bg-input)', color: 'var(--text-main)', border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '6px 12px', fontSize: 13 }}
          >
            <option value="ALL">All Event Types</option>
            <option value="PROCESS_CREATED">Process Creations</option>
            <option value="NETWORK_SOCKET_ACTIVE">Network Sockets</option>
            <option value="FILE_MODIFIED">File Activity</option>
            <option value="SYSTEM_EVENT_LOG">System Event Logs</option>
            <option value="WORKFLOW_ROUND_STARTED">Investigation Milestones</option>
          </select>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)', marginLeft: 8 }}>
            <span>Round:</span>
          </div>
          <select
            value={filterRound}
            onChange={e => setFilterRound(e.target.value === 'ALL' ? 'ALL' : Number(e.target.value))}
            style={{ background: 'var(--bg-input)', color: 'var(--text-main)', border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '6px 12px', fontSize: 13 }}
          >
            <option value="ALL">All Rounds</option>
            <option value={1}>Round 1</option>
            <option value={2}>Round 2</option>
            <option value={3}>Round 3</option>
          </select>
        </div>

        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          Showing <strong>{filteredEvents.length}</strong> of {events.length} timeline events
        </div>
      </div>

      {/* Timeline Stream */}
      <div className="glass-panel" style={{ padding: '24px 30px' }}>
        {filteredEvents.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-dim)' }}>
            No timeline events match the selected filters.
          </div>
        ) : (
          <div style={{ position: 'relative', borderLeft: '2px solid var(--border-subtle)', marginLeft: 16, paddingLeft: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
            {filteredEvents.map(ev => {
              const isExpanded = expandedId === ev.id;
              const isMilestone = ev.event_type.startsWith('WORKFLOW_ROUND');

              return (
                <div key={ev.id} style={{ position: 'relative' }}>
                  {/* Timeline Node Point */}
                  <div style={{
                    position: 'absolute',
                    left: -33,
                    top: 4,
                    width: 16,
                    height: 16,
                    borderRadius: '50%',
                    background: isMilestone ? 'var(--accent-emerald)' : 'var(--bg-card)',
                    border: `2px solid ${isMilestone ? 'var(--accent-emerald)' : 'var(--accent-blue)'}`,
                    boxShadow: isMilestone ? '0 0 8px rgba(5, 150, 105, 0.4)' : '0 0 6px rgba(2, 132, 199, 0.3)'
                  }} />

                  {/* Event Card */}
                  <div
                    style={{
                      background: isMilestone ? 'var(--active-live-bg)' : 'var(--bg-item)',
                      border: isMilestone ? '1px solid var(--active-live-border)' : '1px solid var(--border-subtle)',
                      borderRadius: 8,
                      padding: '12px 16px',
                      cursor: ev.details && Object.keys(ev.details).length > 0 ? 'pointer' : 'default',
                      transition: 'all 0.15s ease'
                    }}
                    onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8, marginBottom: 6 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        {getEventIcon(ev.event_type)}
                        <span style={{ fontSize: 13, fontWeight: 600, color: isMilestone ? 'var(--accent-emerald)' : 'var(--text-main)' }}>
                          {ev.event_type.replace(/_/g, ' ')}
                        </span>
                        <span className="badge badge-neutral" style={{ fontSize: 10 }}>{ev.source}</span>
                        <span className="badge badge-in-progress" style={{ fontSize: 10 }}>Round {ev.round_number}</span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-dim)', fontFamily: 'monospace' }}>
                        <Clock size={12} />
                        <span>{formatDateTime(ev.timestamp)}</span>
                      </div>
                    </div>

                    <div style={{ fontSize: 13, color: 'var(--text-main)', lineHeight: 1.4 }}>
                      {ev.description}
                    </div>

                    {/* Expandable JSON details */}
                    {isExpanded && ev.details && Object.keys(ev.details).length > 0 && (
                      <div style={{ marginTop: 12, paddingTop: 10, borderTop: '1px solid var(--border-subtle)' }}>
                        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 6 }}>EXTRACTED TELEMETRY DETAILS:</div>
                        <pre style={{
                          background: 'var(--bg-code)',
                          padding: 10,
                          borderRadius: 6,
                          fontSize: 12,
                          color: 'var(--text-code)',
                          overflowX: 'auto',
                          maxHeight: 220
                        }}>
                          {JSON.stringify(ev.details, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
