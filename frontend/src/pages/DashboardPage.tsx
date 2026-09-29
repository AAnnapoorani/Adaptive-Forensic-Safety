import React, { useState, useEffect } from 'react';
import type { InvestigationSummary, Machine } from '../types';
import { api } from '../services/api';
import { StatsCards } from '../components/StatsCards';
import { PlusCircle, ArrowRight, Server, RefreshCw, Zap, Clock } from 'lucide-react';
import { formatDateTime, formatTime } from '../utils/date';

interface DashboardPageProps {
  onOpenInvestigation: (id: string) => void;
  onNewInvestigation: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onOpenInvestigation, onNewInvestigation }) => {
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [machines, setMachines] = useState<Machine[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);

  const loadData = async (showSpinner: boolean = true) => {
    if (showSpinner) setLoading(true);
    setIsRefreshing(true);
    try {
      const [invData, macData] = await Promise.all([
        api.listInvestigations(),
        api.getMachines()
      ]);
      setInvestigations(invData);
      setMachines(macData);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      if (showSpinner) setLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData(true);
  }, []);

  // Auto-refresh when any case is active or executing
  useEffect(() => {
    const hasActive = investigations.some(i => i.status === 'IN_PROGRESS' || i.status === 'CREATED');
    if (!hasActive) return;

    const interval = setInterval(() => {
      loadData(false);
    }, 2500);

    return () => clearInterval(interval);
  }, [investigations]);

  const activeCount = investigations.filter(i => i.status === 'IN_PROGRESS').length;
  const completedCount = investigations.filter(i => i.status === 'COMPLETED').length;
  const totalArtifacts = investigations.reduce((sum, i) => sum + (i.artifact_count || 0), 0);

  return (
    <div className="container">
      {/* Welcome Banner */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24, flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 10 }}>
            Forensic Investigation Command Console
          </h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
            Adaptive Intent-to-Workflow Compilation &bull; Real-Time Evidence Gathering &bull; Immutable Provenance
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 12, color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <Clock size={12} /> Synced: {formatTime(lastUpdated.toISOString())}
          </span>
          <button className="btn btn-secondary btn-sm" onClick={() => loadData(false)} disabled={isRefreshing}>
            <RefreshCw size={13} className={isRefreshing ? 'spin' : ''} /> Refresh
          </button>
          <button className="btn btn-primary" onClick={onNewInvestigation}>
            <PlusCircle size={15} /> Start Investigation
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <StatsCards
        totalInvestigations={investigations.length}
        activeInvestigations={activeCount}
        completedInvestigations={completedCount}
        totalArtifacts={totalArtifacts}
        registeredMachines={machines.length}
      />

      {/* Main Grid: Recent Cases & Registered Machines */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 24 }}>
        {/* Recent Cases */}
        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-main)' }}>Recent Investigations</h3>
            <span className="badge badge-neutral">{investigations.length} total</span>
          </div>

          {loading ? (
            <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
              Loading investigation ledger...
            </div>
          ) : investigations.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
              No investigations recorded yet. Click <strong>Start Investigation</strong> to launch your first triage.
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Case ID</th>
                    <th>Investigation Intent</th>
                    <th>Status</th>
                    <th>Rounds</th>
                    <th>Artifacts</th>
                    <th>Adaptive Escalation</th>
                    <th>Initiated (Local Time)</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {investigations.map(inv => (
                    <tr key={inv.id}>
                      <td>
                        <span style={{ fontWeight: 600, color: 'var(--accent-blue)', fontFamily: 'monospace' }}>
                          {inv.id}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontWeight: 500, color: 'var(--text-main)' }}>{inv.intent}</span>
                      </td>
                      <td>
                        <span className={`badge ${inv.status === 'COMPLETED' ? 'badge-completed' : inv.status === 'IN_PROGRESS' ? 'badge-in-progress' : 'badge-neutral'}`}>
                          {inv.status}
                        </span>
                      </td>
                      <td>
                        <span className="badge badge-neutral">
                          {inv.total_rounds} {inv.total_rounds === 1 ? 'Round' : 'Rounds'}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{inv.artifact_count}</span>
                      </td>
                      <td>
                        {inv.escalation_triggered ? (
                          <span className="badge badge-warning" style={{ fontSize: 10 }}>
                            <Zap size={10} /> Escalated
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-dim)', fontSize: 12 }}>Standard</span>
                        )}
                      </td>
                      <td>
                        <span style={{ fontSize: 12, color: 'var(--text-dim)', fontFamily: 'monospace' }}>
                          {formatDateTime(inv.created_at)}
                        </span>
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => onOpenInvestigation(inv.id)}
                        >
                          Open <ArrowRight size={12} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Registered Machines Panel */}
        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Server size={18} color="var(--accent-blue)" /> Target Machines
            </h3>
            <span className="badge badge-neutral">{machines.length} active</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {machines.map(m => (
              <div
                key={m.id}
                style={{
                  background: 'var(--bg-item)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 8,
                  padding: 12
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-main)', fontSize: 13 }}>{m.hostname}</span>
                  <span className="badge badge-completed" style={{ fontSize: 9 }}>ONLINE</span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <div>IP: <code style={{ color: 'var(--text-main)' }}>{m.ip_address}</code></div>
                  <div>OS: {m.os_name} {m.os_version} ({m.architecture})</div>
                  <div>ID: <span style={{ fontFamily: 'monospace', color: 'var(--text-dim)' }}>{m.id}</span></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
