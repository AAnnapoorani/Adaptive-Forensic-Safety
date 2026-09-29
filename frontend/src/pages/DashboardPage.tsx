import React, { useState, useEffect, useRef } from 'react';
import type { InvestigationSummary, Machine } from '../types';
import { api } from '../services/api';
import {
  Server, RefreshCw, Zap, ArrowRight, Activity, Radio,
  AlertTriangle, Laptop, ShieldCheck, Play
} from 'lucide-react';
import { formatDateTime } from '../utils/date';

interface DashboardPageProps {
  onOpenInvestigation: (id: string) => void;
  onNewInvestigation: (machineId?: string) => void;
  onOpenMachine: (machineId: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  onOpenInvestigation,
  onNewInvestigation,
  onOpenMachine
}) => {
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [machines, setMachines] = useState<Machine[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [sseConnected, setSseConnected] = useState(false);
  const [activeAlertCount, setActiveAlertCount] = useState(0);
  const [currentTime, setCurrentTime] = useState(Date.now());
  const eventSourceRef = useRef<EventSource | null>(null);

  const loadData = async (_showSpinner: boolean = true) => {
    setIsRefreshing(true);
    try {
      const [invData, macData] = await Promise.all([
        api.listInvestigations(),
        api.getMachines()
      ]);
      setInvestigations(invData);
      setMachines(macData);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  // 1. Initial Load & Periodic relative timer tick
  useEffect(() => {
    loadData(true);

    const timer = setInterval(() => {
      setCurrentTime(Date.now());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  // 2. Connect to Server-Sent Events (SSE) for Live Real-Time Telemetry
  useEffect(() => {
    const streamUrl = api.getStreamUrl();
    let es: EventSource | null = null;

    try {
      es = new EventSource(streamUrl);
      eventSourceRef.current = es;

      es.onopen = () => {
        setSseConnected(true);
      };

      es.onerror = () => {
        setSseConnected(false);
      };

      // Handle real-time telemetry updates from physical agents
      es.addEventListener('telemetry_update', (e: MessageEvent) => {
        try {
          const payload = JSON.parse(e.data);
          const data = payload.data || payload;
          const targetId = data.machine_id;

          setMachines(prev => {
            const idx = prev.findIndex(m => m.id === targetId || m.machine_id === targetId);
            const nowIso = data.last_seen || new Date().toISOString();

            if (idx >= 0) {
              const updated = [...prev];
              updated[idx] = {
                ...updated[idx],
                hostname: data.hostname || updated[idx].hostname,
                os_type: data.os_type || updated[idx].os_type,
                os_name: data.os_name || updated[idx].os_name,
                os_version: data.os_version || updated[idx].os_version,
                status: 'ONLINE',
                last_seen: nowIso,
                latest_metrics: data.metrics || updated[idx].latest_metrics
              };
              return updated;
            } else {
              // New machine registered live
              return [
                ...prev,
                {
                  id: targetId,
                  machine_id: targetId,
                  hostname: data.hostname || targetId,
                  os_type: data.os_type || 'Windows',
                  os_name: data.os_name || 'Windows',
                  os_version: data.os_version,
                  status: 'ONLINE',
                  last_seen: nowIso,
                  latest_metrics: data.metrics
                }
              ];
            }
          });
        } catch {
          // parse error
        }
      });

      // Handle forensic alerts
      es.addEventListener('forensic_event', () => {
        setActiveAlertCount(prev => prev + 1);
      });

      // Handle machine registration
      es.addEventListener('machine_registered', (e: MessageEvent) => {
        try {
          const payload = JSON.parse(e.data);
          const data = payload.data || payload;
          setMachines(prev => {
            if (prev.some(m => m.id === data.machine_id || m.machine_id === data.machine_id)) {
              return prev.map(m => (m.id === data.machine_id || m.machine_id === data.machine_id) ? { ...m, status: 'ONLINE', last_seen: data.last_seen } : m);
            }
            return [...prev, {
              id: data.machine_id,
              machine_id: data.machine_id,
              hostname: data.hostname,
              os_type: data.os_type,
              os_name: data.os_name,
              os_version: data.os_version,
              status: 'ONLINE',
              last_seen: data.last_seen
            }];
          });
        } catch {
          // ignore
        }
      });
    } catch (err) {
      console.warn('SSE connection initialization skipped:', err);
    }

    return () => {
      if (es) es.close();
    };
  }, []);

  // Helper to compute seconds ago and dynamic online status
  const getMachineLiveState = (m: Machine) => {
    if (!m.last_seen) return { isOnline: false, text: 'never' };
    const lastSeenMs = new Date(m.last_seen).getTime();
    const diffSec = Math.max(Math.floor((currentTime - lastSeenMs) / 1000), 0);
    const isOnline = diffSec <= 20;

    let text = `${diffSec}s ago`;
    if (diffSec >= 60) {
      const min = Math.floor(diffSec / 60);
      text = `${min}m ago`;
    }
    return { isOnline, text };
  };

  // Metrics summary counts
  const totalMachines = machines.length;
  const onlineCount = machines.filter(m => getMachineLiveState(m).isOnline).length;
  const offlineCount = totalMachines - onlineCount;
  const windowsCount = machines.filter(m => (m.os_type || '').toLowerCase().includes('win')).length;
  const linuxCount = machines.filter(m => (m.os_type || '').toLowerCase().includes('linux')).length;

  return (
    <div className="container" style={{ paddingBottom: 60 }}>
      {/* Top Banner */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20, flexWrap: 'wrap', gap: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: 24, fontWeight: 800, color: 'var(--text-main)', letterSpacing: '-0.02em', margin: 0 }}>
              SUVADU Forensic Command Dashboard
            </h1>
            <span className={`badge ${sseConnected ? 'badge-completed' : 'badge-warning'}`} style={{ fontSize: 10, display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: sseConnected ? '#10b981' : '#f59e0b', display: 'inline-block' }} />
              {sseConnected ? 'LIVE SSE STREAM' : 'CONNECTING SSE...'}
            </span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
            Multi-Machine Physical Host Telemetry &bull; Persistent Hardware Identity &bull; Real-Time Security Monitoring
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button className="btn btn-secondary btn-sm" onClick={() => loadData(false)} disabled={isRefreshing}>
            <RefreshCw size={13} className={isRefreshing ? 'spin' : ''} /> Refresh
          </button>
          <button className="btn btn-primary" onClick={() => onNewInvestigation()}>
            <Play size={14} /> Start Investigation
          </button>
        </div>
      </div>

      {/* Multi-Machine Global Forensic Statistics Bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 12, marginBottom: 24 }}>
        <div className="glass-panel" style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ padding: 10, borderRadius: 8, background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8' }}>
            <Server size={20} />
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Total Machines</div>
            <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-main)', fontFamily: 'monospace' }}>{totalMachines}</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ padding: 10, borderRadius: 8, background: 'rgba(16, 185, 129, 0.1)', color: '#10b981' }}>
            <Activity size={20} />
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Online</div>
            <div style={{ fontSize: 22, fontWeight: 800, color: '#10b981', fontFamily: 'monospace' }}>{onlineCount}</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ padding: 10, borderRadius: 8, background: 'rgba(100, 116, 139, 0.1)', color: '#64748b' }}>
            <Radio size={20} />
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Offline</div>
            <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-dim)', fontFamily: 'monospace' }}>{offlineCount}</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ padding: 10, borderRadius: 8, background: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6' }}>
            <Laptop size={20} />
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Windows Hosts</div>
            <div style={{ fontSize: 22, fontWeight: 800, color: '#3b82f6', fontFamily: 'monospace' }}>{windowsCount}</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ padding: 10, borderRadius: 8, background: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b' }}>
            <ShieldCheck size={20} />
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Linux Hosts</div>
            <div style={{ fontSize: 22, fontWeight: 800, color: '#f59e0b', fontFamily: 'monospace' }}>{linuxCount}</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ padding: 10, borderRadius: 8, background: 'rgba(244, 63, 94, 0.1)', color: '#f43f5e' }}>
            <AlertTriangle size={20} />
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Active Alerts</div>
            <div style={{ fontSize: 22, fontWeight: 800, color: '#f43f5e', fontFamily: 'monospace' }}>{activeAlertCount}</div>
          </div>
        </div>
      </div>

      {/* SECTION 1: Target Physical Machines Live Grid */}
      <div className="glass-panel" style={{ padding: 20, marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)', margin: 0 }}>
              Physical Machines & Telemetry Fleet
            </h2>
            <span className="badge badge-neutral" style={{ fontSize: 11 }}>{machines.length} registered</span>
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>
            Click any machine row to open deep-dive telemetry & process inspection
          </span>
        </div>

        {machines.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-dim)' }}>
            <Server size={32} style={{ marginBottom: 12, opacity: 0.5 }} />
            <div>No machines currently registered. Run the SUVADU local agent on a machine to connect:</div>
            <code style={{ display: 'inline-block', marginTop: 10, padding: '6px 12px', background: 'var(--bg-item)', borderRadius: 6, fontSize: 12 }}>
              python agent/jocky_agent.py --server http://localhost:8000
            </code>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table" style={{ width: '100%', fontSize: 12 }}>
              <thead>
                <tr>
                  <th>Machine / Hostname</th>
                  <th>Operating System</th>
                  <th>Status</th>
                  <th>Live CPU</th>
                  <th>Live RAM</th>
                  <th>Disk</th>
                  <th>Network Bandwidth</th>
                  <th>Last Seen</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {machines.map(m => {
                  const { isOnline, text: lastSeenText } = getMachineLiveState(m);
                  const telem = m.latest_metrics;
                  const isWindows = (m.os_type || '').toLowerCase().includes('win');

                  return (
                    <tr
                      key={m.id}
                      style={{ cursor: 'pointer', transition: 'background-color 0.15s ease' }}
                      onClick={() => onOpenMachine(m.machine_id || m.id)}
                    >
                      {/* Hostname & Stable Machine ID */}
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                          <span style={{ fontWeight: 700, color: 'var(--text-main)', fontSize: 13 }}>
                            {m.hostname}
                          </span>
                          <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--accent-blue)' }}>
                            {m.machine_id || m.id}
                          </span>
                        </div>
                      </td>

                      {/* OS Badge with Platform differentiation */}
                      <td>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 8px', borderRadius: 6, background: isWindows ? 'rgba(59, 130, 246, 0.1)' : 'rgba(245, 158, 11, 0.1)', color: isWindows ? '#60a5fa' : '#fbbf24', fontSize: 11, fontWeight: 600 }}>
                          <span>{isWindows ? '\u229e' : '\u2318'}</span>
                          <span>{m.os_type}</span>
                          <span style={{ fontSize: 10, opacity: 0.8, color: 'var(--text-muted)' }}>{m.os_version?.split(' ')[1] || ''}</span>
                        </div>
                      </td>

                      {/* Live Online / Offline Heartbeat */}
                      <td>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 8px', borderRadius: 12, background: isOnline ? 'rgba(16, 185, 129, 0.12)' : 'rgba(100, 116, 139, 0.12)', border: `1px solid ${isOnline ? 'rgba(16, 185, 129, 0.3)' : 'rgba(100, 116, 139, 0.2)'}` }}>
                          <span style={{ width: 6, height: 6, borderRadius: '50%', background: isOnline ? '#10b981' : '#64748b' }} />
                          <span style={{ fontSize: 11, fontWeight: 700, color: isOnline ? '#10b981' : '#94a3b8' }}>
                            {isOnline ? 'ONLINE' : 'OFFLINE'}
                          </span>
                        </div>
                      </td>

                      {/* CPU Bar */}
                      <td>
                        {telem && isOnline ? (
                          <div style={{ width: 100 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, fontFamily: 'monospace', color: '#38bdf8' }}>
                              <span>{telem.cpu_percent}%</span>
                            </div>
                            <div style={{ height: 4, background: 'rgba(255,255,255,0.08)', borderRadius: 2, overflow: 'hidden', marginTop: 2 }}>
                              <div style={{ width: `${Math.min(telem.cpu_percent, 100)}%`, height: '100%', background: '#38bdf8' }} />
                            </div>
                          </div>
                        ) : (
                          <span style={{ color: 'var(--text-dim)' }}>--</span>
                        )}
                      </td>

                      {/* RAM Bar */}
                      <td>
                        {telem && isOnline ? (
                          <div style={{ width: 100 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, fontFamily: 'monospace', color: '#818cf8' }}>
                              <span>{telem.memory_percent}%</span>
                            </div>
                            <div style={{ height: 4, background: 'rgba(255,255,255,0.08)', borderRadius: 2, overflow: 'hidden', marginTop: 2 }}>
                              <div style={{ width: `${Math.min(telem.memory_percent, 100)}%`, height: '100%', background: '#818cf8' }} />
                            </div>
                          </div>
                        ) : (
                          <span style={{ color: 'var(--text-dim)' }}>--</span>
                        )}
                      </td>

                      {/* Disk Bar */}
                      <td>
                        {telem && isOnline ? (
                          <div style={{ width: 90 }}>
                            <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#34d399' }}>{telem.disk_percent}%</span>
                          </div>
                        ) : (
                          <span style={{ color: 'var(--text-dim)' }}>--</span>
                        )}
                      </td>

                      {/* Network upload / download speed */}
                      <td>
                        {telem && isOnline ? (
                          <div style={{ fontFamily: 'monospace', fontSize: 11, color: '#fbbf24' }}>
                            <span>&uarr;{(telem.network_upload_speed / 1024).toFixed(0)}K</span>{' '}
                            <span>&darr;{(telem.network_download_speed / 1024).toFixed(0)}K</span>
                          </div>
                        ) : (
                          <span style={{ color: 'var(--text-dim)' }}>--</span>
                        )}
                      </td>

                      {/* Dynamic Last Seen */}
                      <td>
                        <span style={{ fontSize: 11, color: isOnline ? 'var(--text-main)' : 'var(--text-dim)', fontFamily: 'monospace' }}>
                          {lastSeenText}
                        </span>
                      </td>

                      {/* Actions */}
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: 6 }} onClick={e => e.stopPropagation()}>
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => onOpenMachine(m.machine_id || m.id)}
                            style={{ fontSize: 11, padding: '4px 8px' }}
                          >
                            Inspect <ArrowRight size={11} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* SECTION 2: Recent Investigations Table */}
      <div className="glass-panel" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)', margin: 0 }}>
            Recent Forensic Investigations
          </h2>
          <span className="badge badge-neutral" style={{ fontSize: 11 }}>{investigations.length} cases</span>
        </div>

        {investigations.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '30px 20px', color: 'var(--text-dim)' }}>
            No investigations run yet. Click "Start Investigation" to compile a SUVADU DSL script.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table" style={{ width: '100%', fontSize: 12 }}>
              <thead>
                <tr>
                  <th>Case ID</th>
                  <th>Forensic Intent</th>
                  <th>Target Host</th>
                  <th>Status</th>
                  <th>Rounds</th>
                  <th>Evidence</th>
                  <th>Escalation</th>
                  <th>Created At</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {investigations.map(inv => (
                  <tr key={inv.id}>
                    <td style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--accent-blue)' }}>
                      {inv.id}
                    </td>
                    <td style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {inv.intent || 'Live System Triage'}
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-muted)' }}>
                      {inv.machine_id}
                    </td>
                    <td>
                      <span className={`badge ${inv.status === 'COMPLETED' ? 'badge-completed' : inv.status === 'IN_PROGRESS' ? 'badge-in-progress' : 'badge-neutral'}`}>
                        {inv.status}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'monospace' }}>{inv.current_round} / {inv.total_rounds}</td>
                    <td style={{ fontFamily: 'monospace' }}>{inv.artifact_count || 0}</td>
                    <td>
                      {inv.escalation_triggered ? (
                        <span className="badge badge-warning" style={{ fontSize: 10 }}>
                          <Zap size={10} /> Escalated
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>Standard</span>
                      )}
                    </td>
                    <td style={{ fontFamily: 'monospace', color: 'var(--text-dim)', fontSize: 11 }}>
                      {formatDateTime(inv.created_at)}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button className="btn btn-secondary btn-sm" onClick={() => onOpenInvestigation(inv.id)} style={{ fontSize: 11, padding: '4px 8px' }}>
                        View <ArrowRight size={11} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
