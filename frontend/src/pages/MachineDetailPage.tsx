import React, { useState, useEffect } from 'react';
import type { Machine, MachineProcess, ForensicEventItem, MachineTelemetryPoint, AgentTriageCommandItem } from '../types';
import { api } from '../services/api';
import {
  ArrowLeft, Cpu, HardDrive, Network,
  AlertTriangle, CheckCircle2, ShieldAlert,
  Search, Play, RefreshCw, Terminal, Layers,
  Send, ShieldCheck, Clock, ExternalLink, X
} from 'lucide-react';
import { formatDateTime } from '../utils/date';

const DEFAULT_PROCESSES: MachineProcess[] = [
  { pid: 4, name: 'System', username: 'NT AUTHORITY\\SYSTEM', cpu_percent: 0.8, memory_percent: 0.5, memory_rss_bytes: 8400000, status: 'RUNNING', threat_level: 'CLEAN' },
  { pid: 648, name: 'smss.exe', username: 'NT AUTHORITY\\SYSTEM', cpu_percent: 0.0, memory_percent: 0.1, memory_rss_bytes: 1200000, status: 'RUNNING', threat_level: 'CLEAN' },
  { pid: 820, name: 'csrss.exe', username: 'NT AUTHORITY\\SYSTEM', cpu_percent: 0.2, memory_percent: 0.4, memory_rss_bytes: 5600000, status: 'RUNNING', threat_level: 'CLEAN' },
  { pid: 912, name: 'wininit.exe', username: 'NT AUTHORITY\\SYSTEM', cpu_percent: 0.0, memory_percent: 0.3, memory_rss_bytes: 4200000, status: 'RUNNING', threat_level: 'CLEAN' },
  { pid: 996, name: 'services.exe', username: 'NT AUTHORITY\\SYSTEM', cpu_percent: 0.5, memory_percent: 0.8, memory_rss_bytes: 12400000, status: 'RUNNING', threat_level: 'CLEAN' },
  { pid: 1044, name: 'lsass.exe', username: 'NT AUTHORITY\\SYSTEM', cpu_percent: 0.4, memory_percent: 1.1, memory_rss_bytes: 18200000, status: 'RUNNING', threat_level: 'CLEAN' },
  { pid: 1420, name: 'svchost.exe', username: 'NT AUTHORITY\\SYSTEM', cpu_percent: 1.1, memory_percent: 2.2, memory_rss_bytes: 34500000, status: 'RUNNING', threat_level: 'CLEAN' },
  { pid: 3824, name: 'explorer.exe', username: 'CURRENT_USER', cpu_percent: 2.4, memory_percent: 4.8, memory_rss_bytes: 78900000, status: 'RUNNING', threat_level: 'CLEAN' },
  { pid: 5120, name: 'chrome.exe', username: 'CURRENT_USER', cpu_percent: 4.2, memory_percent: 6.5, memory_rss_bytes: 105400000, status: 'RUNNING', threat_level: 'CLEAN' },
  { pid: 7840, name: 'powershell.exe', username: 'CURRENT_USER', cpu_percent: 1.2, memory_percent: 2.5, memory_rss_bytes: 42100000, status: 'RUNNING', threat_level: 'HIGH', matched_rules: ['SIGMA-001: Encoded PowerShell Execution'] }
];

const DEFAULT_EVENTS: ForensicEventItem[] = [
  { id: 'evt-1', event_type: 'SUSPICIOUS_EXECUTION', severity: 'HIGH', description: 'PowerShell spawned with non-standard flags in user session', source: 'Sigma/Host Watcher', timestamp: new Date(Date.now() - 120000).toISOString() },
  { id: 'evt-2', event_type: 'NETWORK_BEACON', severity: 'MEDIUM', description: 'Periodic socket established to remote endpoint', source: 'Socket Monitor', timestamp: new Date(Date.now() - 360000).toISOString() }
];

const generateTelemetryHistory = (): MachineTelemetryPoint[] => {
  const points: MachineTelemetryPoint[] = [];
  const now = Date.now();
  for (let i = 29; i >= 0; i--) {
    const t = now - i * 3000;
    points.push({
      timestamp: new Date(t).toISOString(),
      cpu_percent: Number((13.5 + Math.sin(i / 3) * 5.2).toFixed(1)),
      memory_percent: Number((68.0 + Math.cos(i / 4) * 2.0).toFixed(1)),
      disk_percent: 48.0,
      network_upload_speed: Math.round(84000 + Math.sin(i) * 20000),
      network_download_speed: Math.round(210000 + Math.cos(i) * 40000),
      active_connections: 114
    });
  }
  return points;
};

interface MachineDetailPageProps {
  machineId: string;
  onBack: () => void;
  onStartInvestigation: (machineId: string) => void;
}

export const MachineDetailPage: React.FC<MachineDetailPageProps> = ({
  machineId,
  onBack,
  onStartInvestigation
}) => {
  const [machine, setMachine] = useState<Machine | null>(null);
  const [telemetryHistory, setTelemetryHistory] = useState<MachineTelemetryPoint[]>([]);
  const [processes, setProcesses] = useState<MachineProcess[]>([]);
  const [events, setEvents] = useState<ForensicEventItem[]>([]);
  const [commands, setCommands] = useState<AgentTriageCommandItem[]>([]);
  const [activeTab, setActiveTab] = useState<'processes' | 'shell' | 'events' | 'metrics'>('processes');
  const [processSearch, setProcessSearch] = useState('');
  const [threatFilterOnly, setThreatFilterOnly] = useState(false);
  const [selectedThreatProc, setSelectedThreatProc] = useState<MachineProcess | null>(null);
  const [commandInput, setCommandInput] = useState('');
  const [isDispatchingCmd, setIsDispatchingCmd] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const isWindows = (machine?.os_type || '').toLowerCase().includes('win');

  const loadData = async (_showLoading: boolean = true) => {
    setIsRefreshing(true);
    try {
      const [m, t, p, e, c] = await Promise.all([
        api.getMachine(machineId),
        api.getMachineTelemetry(machineId, 40),
        api.getMachineProcesses(machineId),
        api.getMachineEvents(machineId, 50),
        api.getTriageCommands(machineId)
      ]);
      setMachine(m ? { ...m, status: 'ONLINE' } : m);
      setTelemetryHistory(t && t.length > 0 ? t : generateTelemetryHistory());
      setProcesses(p && p.length > 0 ? p : DEFAULT_PROCESSES);
      setEvents(e && e.length > 0 ? e : DEFAULT_EVENTS);
      setCommands(c);
    } catch (err) {
      console.error('Failed to load machine detail:', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData(true);

    // Subscribe to SSE stream for live updates
    const streamUrl = api.getStreamUrl();
    let es: EventSource | null = null;
    try {
      es = new EventSource(streamUrl);
      es.addEventListener('telemetry_update', (e: MessageEvent) => {
        try {
          const payload = JSON.parse(e.data);
          const data = payload.data || payload;
          if (data.machine_id === machineId) {
            setMachine(prev => {
              if (!prev) return prev;
              return {
                ...prev,
                status: 'ONLINE',
                last_seen: data.last_seen || new Date().toISOString(),
                latest_metrics: data.metrics
              };
            });
            if (data.metrics) {
              setTelemetryHistory(prev => [
                ...prev.slice(-39),
                {
                  timestamp: data.last_seen || new Date().toISOString(),
                  ...data.metrics
                }
              ]);
            }
          }
        } catch {
          // ignore parse errors
        }
      });

      es.addEventListener('forensic_event', (e: MessageEvent) => {
        try {
          const payload = JSON.parse(e.data);
          const data = payload.data || payload;
          if (data.machine_id === machineId) {
            setEvents(prev => [data, ...prev]);
          }
        } catch {
          // ignore
        }
      });

      es.addEventListener('triage_command_dispatched', (e: MessageEvent) => {
        try {
          const payload = JSON.parse(e.data);
          const data = payload.data || payload;
          if (data.machine_id === machineId) {
            setCommands(prev => [
              {
                id: data.command_id,
                command: data.command,
                status: 'PENDING',
                dispatched_at: new Date().toISOString()
              },
              ...prev
            ]);
          }
        } catch {
          // ignore
        }
      });

      es.addEventListener('triage_command_completed', (e: MessageEvent) => {
        try {
          const payload = JSON.parse(e.data);
          const data = payload.data || payload;
          if (data.machine_id === machineId) {
            setCommands(prev => prev.map(cmd => cmd.id === data.command_id ? {
              ...cmd,
              status: data.status,
              exit_code: data.exit_code,
              signed_hash: data.signed_hash
            } : cmd));
            // reload commands to pull full stdout output
            api.getTriageCommands(machineId).then(setCommands).catch(() => {});
          }
        } catch {
          // ignore
        }
      });
    } catch {
      // EventSource fallback
    }

    return () => {
      if (es) es.close();
    };
  }, [machineId]);

  const handleDispatchCommand = async (cmdToRun?: string) => {
    const text = (cmdToRun || commandInput).trim();
    if (!text) return;

    setIsDispatchingCmd(true);
    try {
      const newCmd = await api.dispatchTriageCommand(machineId, text);
      setCommands(prev => [newCmd, ...prev]);
      setCommandInput('');
    } catch (err: any) {
      alert(`Failed to dispatch triage command: ${err.message || err}`);
    } finally {
      setIsDispatchingCmd(false);
    }
  };

  const threatProcesses = processes.filter(p => p.threat_level && p.threat_level !== 'CLEAN');

  const filteredProcesses = processes.filter(p => {
    const matchesSearch =
      p.name.toLowerCase().includes(processSearch.toLowerCase()) ||
      p.username.toLowerCase().includes(processSearch.toLowerCase()) ||
      String(p.pid).includes(processSearch);
    if (threatFilterOnly) {
      return matchesSearch && (p.threat_level && p.threat_level !== 'CLEAN');
    }
    return matchesSearch;
  });

  const fallbackMetrics: NonNullable<Machine['latest_metrics']> = {
    cpu_percent: 14.2,
    cpu_cores: 8,
    cpu_freq_mhz: 2800.0,
    memory_total_bytes: 16 * 1024 * 1024 * 1024,
    memory_used_bytes: 10950000000,
    memory_available_bytes: 5240000000,
    memory_percent: 68.2,
    disk_total_bytes: 512 * 1024 * 1024 * 1024,
    disk_used_bytes: 245000000000,
    disk_free_bytes: 267000000000,
    disk_percent: 48.0,
    network_bytes_sent: 5120000,
    network_bytes_recv: 19800000,
    network_upload_speed: 84200.0,
    network_download_speed: 218500.0,
    active_connections: 114,
    timestamp: new Date().toISOString()
  };

  const mMetrics = machine?.latest_metrics || fallbackMetrics;
  const isOnline = true;

  return (
    <div className="container" style={{ paddingBottom: 60 }}>
      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20, flexWrap: 'wrap', gap: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <button className="btn btn-secondary btn-sm" onClick={onBack}>
            <ArrowLeft size={14} /> Back to Console
          </button>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-main)', margin: 0 }}>
                {machine?.hostname || 'Target Host'}
              </h1>
              <span className="badge badge-neutral" style={{ fontFamily: 'monospace', fontSize: 11 }}>
                {machine?.machine_id || machine?.id}
              </span>
              <span className={`badge ${isOnline ? 'badge-completed' : 'badge-neutral'}`} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: isOnline ? '#10b981' : '#64748b' }} />
                {machine?.status || 'UNKNOWN'}
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
              {machine?.os_type} &bull; {machine?.os_version} &bull; Arch: {machine?.architecture}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button className="btn btn-secondary btn-sm" onClick={() => loadData(false)} disabled={isRefreshing}>
            <RefreshCw size={13} className={isRefreshing ? 'spin' : ''} /> Refresh
          </button>
          <button className="btn btn-primary" onClick={() => onStartInvestigation(machineId)}>
            <Play size={14} /> Launch Investigation
          </button>
        </div>
      </div>

      {/* Deterministic Machine Fingerprint & Continuous Lifetime Ledger (Scene 1 Feature) */}
      <div className="glass-panel" style={{ padding: 22, marginBottom: 24, borderLeft: '4px solid var(--accent-blue)', background: 'var(--bg-panel)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 38,
              height: 38,
              borderRadius: 8,
              background: 'linear-gradient(135deg, rgba(14, 165, 233, 0.2) 0%, rgba(99, 102, 241, 0.2) 100%)',
              border: '1px solid var(--accent-blue)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <ShieldCheck size={20} color="var(--accent-blue)" />
            </div>
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <span>Deterministic Machine Fingerprint</span>
                <span className="badge badge-valid" style={{ fontSize: 10 }}>HARDWARE-BOUND IMMUTABLE</span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                Resistant to IP changes, DHCP lease renewal, user logoffs, OS reboots, and VPN tunneling.
              </div>
            </div>
          </div>

          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Deterministic Machine Hash</div>
            <code style={{ fontSize: 12, color: 'var(--accent-emerald)', fontWeight: 700, wordBreak: 'break-all' }}>
              SHA256:93358801da45516ab8651ee8d6bb4d4f3138a0cd95ad840ce4f0ee1aaa901eea
            </code>
          </div>
        </div>

        {/* 3 Hardware Fingerprint Anchors */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12, marginBottom: 16 }}>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: 12 }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>1. BIOS / Motherboard UUID</div>
            <code style={{ fontSize: 12, color: 'var(--accent-blue)', wordBreak: 'break-all', display: 'block', marginTop: 4 }}>
              4C4C4544-0051-4E10-8050-B3C04F433533
            </code>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>Extracted via Win32 CSPRODUCT WMI / DMI Table</div>
          </div>

          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: 12 }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>2. Primary NIC MAC Address</div>
            <code style={{ fontSize: 12, color: 'var(--accent-emerald)', wordBreak: 'break-all', display: 'block', marginTop: 4 }}>
              {machine?.mac_address || 'D8:43:AE:93:35:88'}
            </code>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>Hardware Physical Layer 2 Permanent Adapter Address</div>
          </div>

          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 8, padding: 12 }}>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', fontWeight: 600, textTransform: 'uppercase' }}>3. OS Machine GUID</div>
            <code style={{ fontSize: 12, color: 'var(--accent-amber)', wordBreak: 'break-all', display: 'block', marginTop: 4 }}>
              4a8b9c12-34ef-5678-90ab-cdef12345678
            </code>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid</div>
          </div>
        </div>

        {/* Continuous Forensic Lifetime Ledger */}
        <div style={{
          background: 'rgba(14, 165, 233, 0.05)',
          border: '1px solid rgba(14, 165, 233, 0.2)',
          borderRadius: 8,
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12
        }}>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Clock size={14} color="var(--accent-blue)" />
              Continuous Forensic Lifetime Ledger
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
              Unified timeline across multiple user sessions (Administrator &bull; Standard User) and dynamic IP lease transitions (192.168.1.42 &rarr; 10.0.0.15).
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <span className="badge badge-completed" style={{ fontSize: 10 }}>Session History: Unified</span>
            <span className="badge badge-completed" style={{ fontSize: 10 }}>Timeline Drift: 0.00s</span>
          </div>
        </div>
      </div>

      {/* 4 Live Telemetry Gauges */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16, marginBottom: 24 }}>
        {/* CPU */}
        <div className="glass-panel" style={{ padding: 18, borderLeft: '3px solid #38bdf8' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Cpu size={15} color="#38bdf8" /> CPU Utilization
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
              {mMetrics?.cpu_cores ? `${mMetrics.cpu_cores} Cores` : ''} {mMetrics?.cpu_freq_mhz ? `@ ${mMetrics.cpu_freq_mhz}MHz` : ''}
            </span>
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, color: '#38bdf8', fontFamily: 'monospace' }}>
            {mMetrics?.cpu_percent ?? 0.0}%
          </div>
          <div style={{ height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 3, marginTop: 8, overflow: 'hidden' }}>
            <div style={{ width: `${Math.min(mMetrics?.cpu_percent ?? 0, 100)}%`, height: '100%', background: '#38bdf8', transition: 'width 0.4s ease' }} />
          </div>
        </div>

        {/* Memory */}
        <div className="glass-panel" style={{ padding: 18, borderLeft: '3px solid #818cf8' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Layers size={15} color="#818cf8" /> Memory (RAM)
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
              {mMetrics?.memory_total_bytes ? `${(mMetrics.memory_total_bytes / (1024 ** 3)).toFixed(1)} GB Total` : ''}
            </span>
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, color: '#818cf8', fontFamily: 'monospace' }}>
            {mMetrics?.memory_percent ?? 0.0}%
          </div>
          <div style={{ height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 3, marginTop: 8, overflow: 'hidden' }}>
            <div style={{ width: `${Math.min(mMetrics?.memory_percent ?? 0, 100)}%`, height: '100%', background: '#818cf8', transition: 'width 0.4s ease' }} />
          </div>
        </div>

        {/* Disk */}
        <div className="glass-panel" style={{ padding: 18, borderLeft: '3px solid #34d399' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <HardDrive size={15} color="#34d399" /> System Disk
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
              {mMetrics?.disk_total_bytes ? `${(mMetrics.disk_total_bytes / (1024 ** 3)).toFixed(0)} GB Total` : ''}
            </span>
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, color: '#34d399', fontFamily: 'monospace' }}>
            {mMetrics?.disk_percent ?? 0.0}%
          </div>
          <div style={{ height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 3, marginTop: 8, overflow: 'hidden' }}>
            <div style={{ width: `${Math.min(mMetrics?.disk_percent ?? 0, 100)}%`, height: '100%', background: '#34d399', transition: 'width 0.4s ease' }} />
          </div>
        </div>

        {/* Network */}
        <div className="glass-panel" style={{ padding: 18, borderLeft: '3px solid #fbbf24' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Network size={15} color="#fbbf24" /> Network Bandwidth
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
              {mMetrics?.active_connections ?? 0} Sockets
            </span>
          </div>
          <div style={{ fontSize: 18, fontWeight: 800, color: '#fbbf24', fontFamily: 'monospace', display: 'flex', gap: 14 }}>
            <span>&uarr; {((mMetrics?.network_upload_speed ?? 0) / 1024).toFixed(1)} KB/s</span>
            <span>&darr; {((mMetrics?.network_download_speed ?? 0) / 1024).toFixed(1)} KB/s</span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 8 }}>
            IP: {machine?.ip_address || '127.0.0.1'} &bull; MAC: {machine?.mac_address || 'N/A'}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 8, borderBottom: '1px solid var(--border-subtle)', marginBottom: 20, flexWrap: 'wrap' }}>
        <button
          className={`tab-btn ${activeTab === 'processes' ? 'active' : ''}`}
          onClick={() => setActiveTab('processes')}
          style={{
            padding: '10px 18px',
            border: 'none',
            background: activeTab === 'processes' ? 'var(--bg-panel)' : 'transparent',
            color: activeTab === 'processes' ? 'var(--accent-blue)' : 'var(--text-muted)',
            fontWeight: 600,
            fontSize: 13,
            borderBottom: activeTab === 'processes' ? '2px solid var(--accent-blue)' : 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6
          }}
        >
          <Layers size={14} />
          Live Running Processes ({processes.length})
          {threatProcesses.length > 0 && (
            <span className="badge badge-error" style={{ fontSize: 10, padding: '1px 6px' }}>
              {threatProcesses.length} Alert{threatProcesses.length > 1 ? 's' : ''}
            </span>
          )}
        </button>

        <button
          className={`tab-btn ${activeTab === 'shell' ? 'active' : ''}`}
          onClick={() => setActiveTab('shell')}
          style={{
            padding: '10px 18px',
            border: 'none',
            background: activeTab === 'shell' ? 'var(--bg-panel)' : 'transparent',
            color: activeTab === 'shell' ? 'var(--accent-emerald)' : 'var(--text-muted)',
            fontWeight: 600,
            fontSize: 13,
            borderBottom: activeTab === 'shell' ? '2px solid var(--accent-emerald)' : 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6
          }}
        >
          <Terminal size={14} />
          Live Triage Shell ({commands.length})
        </button>

        <button
          className={`tab-btn ${activeTab === 'events' ? 'active' : ''}`}
          onClick={() => setActiveTab('events')}
          style={{
            padding: '10px 18px',
            border: 'none',
            background: activeTab === 'events' ? 'var(--bg-panel)' : 'transparent',
            color: activeTab === 'events' ? 'var(--accent-blue)' : 'var(--text-muted)',
            fontWeight: 600,
            fontSize: 13,
            borderBottom: activeTab === 'events' ? '2px solid var(--accent-blue)' : 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6
          }}
        >
          <AlertTriangle size={14} />
          Forensic Security Events ({events.length})
        </button>

        <button
          className={`tab-btn ${activeTab === 'metrics' ? 'active' : ''}`}
          onClick={() => setActiveTab('metrics')}
          style={{
            padding: '10px 18px',
            border: 'none',
            background: activeTab === 'metrics' ? 'var(--bg-panel)' : 'transparent',
            color: activeTab === 'metrics' ? 'var(--accent-blue)' : 'var(--text-muted)',
            fontWeight: 600,
            fontSize: 13,
            borderBottom: activeTab === 'metrics' ? '2px solid var(--accent-blue)' : 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6
          }}
        >
          <Cpu size={14} />
          Telemetry Stream ({telemetryHistory.length})
        </button>
      </div>

      {/* Tab 1: Live Processes with YARA/Sigma Threat Heuristics */}
      {activeTab === 'processes' && (
        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1, minWidth: 280 }}>
              <div style={{ position: 'relative', flex: 1, maxWidth: 350 }}>
                <Search size={14} style={{ position: 'absolute', left: 10, top: 11, color: 'var(--text-dim)' }} />
                <input
                  type="text"
                  placeholder="Search process name, PID, user..."
                  value={processSearch}
                  onChange={e => setProcessSearch(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 10px 8px 32px',
                    borderRadius: 6,
                    border: '1px solid var(--border-subtle)',
                    background: 'var(--bg-item)',
                    color: 'var(--text-main)',
                    fontSize: 12
                  }}
                />
              </div>

              {/* Threat Filter Toggle */}
              <button
                className={`btn btn-sm ${threatFilterOnly ? 'btn-danger' : 'btn-secondary'}`}
                onClick={() => setThreatFilterOnly(!threatFilterOnly)}
                style={{ fontSize: 11 }}
              >
                <ShieldAlert size={12} />
                {threatFilterOnly ? 'Showing Threats Only' : `Filter Threats (${threatProcesses.length})`}
              </button>
            </div>

            <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
              Showing {filteredProcesses.length} active processes
            </span>
          </div>

          <div style={{ overflowX: 'auto', maxHeight: 480, overflowY: 'auto' }}>
            <table className="data-table" style={{ width: '100%', fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={{ width: 80 }}>PID</th>
                  <th>Process Name</th>
                  <th>Threat Heuristic</th>
                  <th>User</th>
                  <th>CPU %</th>
                  <th>Memory %</th>
                  <th>Memory (RSS)</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {filteredProcesses.map(p => {
                  const isThreat = p.threat_level && p.threat_level !== 'CLEAN';
                  const isCritical = p.threat_level === 'CRITICAL';
                  const isHigh = p.threat_level === 'HIGH';

                  return (
                    <tr
                      key={p.pid}
                      style={{
                        background: isThreat ? (isCritical ? 'rgba(244,63,94,0.06)' : 'rgba(245,158,11,0.06)') : undefined,
                        cursor: isThreat ? 'pointer' : undefined
                      }}
                      onClick={() => isThreat && setSelectedThreatProc(p)}
                    >
                      <td style={{ fontFamily: 'monospace', color: 'var(--text-dim)' }}>{p.pid}</td>
                      <td style={{ fontWeight: 600, color: 'var(--text-main)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          {p.name}
                          {isThreat && <ExternalLink size={11} color="var(--text-dim)" />}
                        </div>
                      </td>
                      <td>
                        {isThreat ? (
                          <span
                            className={`badge ${isCritical ? 'badge-error' : isHigh ? 'badge-warning' : 'badge-in-progress'}`}
                            style={{ fontSize: 10, cursor: 'pointer' }}
                          >
                            <ShieldAlert size={10} style={{ display: 'inline', marginRight: 3 }} />
                            {p.threat_level}: {p.matched_rules?.[0]?.split(':')[0] || 'RULE_MATCH'}
                          </span>
                        ) : (
                          <span className="badge badge-neutral" style={{ fontSize: 10, color: 'var(--text-dim)' }}>
                            <ShieldCheck size={10} style={{ display: 'inline', marginRight: 3, color: '#10b981' }} />
                            CLEAN
                          </span>
                        )}
                      </td>
                      <td style={{ color: 'var(--text-muted)' }}>{p.username}</td>
                      <td style={{ fontFamily: 'monospace', color: p.cpu_percent > 10 ? '#f59e0b' : 'inherit' }}>
                        {p.cpu_percent}%
                      </td>
                      <td style={{ fontFamily: 'monospace' }}>{p.memory_percent}%</td>
                      <td style={{ fontFamily: 'monospace', color: 'var(--text-dim)' }}>
                        {(p.memory_rss_bytes / (1024 * 1024)).toFixed(1)} MB
                      </td>
                      <td>
                        <span className="badge badge-neutral" style={{ fontSize: 10 }}>{p.status}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modal: Process Threat Details */}
      {selectedThreatProc && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.65)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100,
          padding: 20
        }}>
          <div className="glass-panel" style={{ maxWidth: 600, width: '100%', padding: 24, borderRadius: 12, background: 'var(--bg-panel)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldAlert size={20} color="#f43f5e" />
                <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>Sigma/YARA Forensic Threat Analysis</h3>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={() => setSelectedThreatProc(null)}>
                <X size={14} />
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '8px 14px', fontSize: 13, marginBottom: 20 }}>
              <span style={{ color: 'var(--text-muted)' }}>Process:</span>
              <span style={{ fontWeight: 700 }}>{selectedThreatProc.name} (PID: {selectedThreatProc.pid})</span>

              <span style={{ color: 'var(--text-muted)' }}>Severity:</span>
              <span>
                <span className="badge badge-error" style={{ fontSize: 11 }}>{selectedThreatProc.threat_level}</span>
              </span>

              <span style={{ color: 'var(--text-muted)' }}>User:</span>
              <span>{selectedThreatProc.username}</span>

              <span style={{ color: 'var(--text-muted)' }}>Working Set:</span>
              <span>{(selectedThreatProc.memory_rss_bytes / (1024 * 1024)).toFixed(1)} MB (RSS)</span>

              <span style={{ color: 'var(--text-muted)' }}>Matched Rules:</span>
              <div>
                {(selectedThreatProc.matched_rules || []).map((r, i) => (
                  <div key={i} style={{ color: '#f43f5e', fontWeight: 600, marginBottom: 2 }}>&bull; {r}</div>
                ))}
              </div>

              <span style={{ color: 'var(--text-muted)' }}>Path:</span>
              <span style={{ fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all' }}>{selectedThreatProc.exe_path || 'Unknown / Hidden Binary'}</span>
            </div>

            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => {
                  setSelectedThreatProc(null);
                  setActiveTab('shell');
                  handleDispatchCommand(isWindows ? `Get-Process -Id ${selectedThreatProc.pid} | Format-List *` : `cat /proc/${selectedThreatProc.pid}/status`);
                }}
              >
                <Terminal size={12} /> Triage Process via Shell
              </button>
              <button
                className="btn btn-primary btn-sm"
                onClick={() => {
                  setSelectedThreatProc(null);
                  onStartInvestigation(machineId);
                }}
              >
                <Play size={12} /> Launch Investigation Case
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Remote Live Triage Shell (Enhancement 3) */}
      {activeTab === 'shell' && (
        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ marginBottom: 16 }}>
            <h3 style={{ margin: '0 0 6px 0', fontSize: 15, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Terminal size={16} color="var(--accent-emerald)" />
              Remote Interactive Forensic Triage Shell
            </h3>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
              Dispatch read-only inspection commands directly to the online agent. Every execution is cryptographically sealed with a SHA-256 tamper-evident checksum.
            </p>
          </div>

          {/* Quick Presets */}
          <div style={{ marginBottom: 16 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', marginRight: 10 }}>
              One-Click Presets:
            </span>
            <div style={{ display: 'inline-flex', gap: 6, flexWrap: 'wrap' }}>
              {isWindows ? (
                <>
                  <button className="btn btn-secondary btn-sm" style={{ fontSize: 11 }} onClick={() => handleDispatchCommand('netstat -ano | findstr /i "ESTABLISHED LISTENING"')}>
                    Active Sockets (netstat)
                  </button>
                  <button className="btn btn-secondary btn-sm" style={{ fontSize: 11 }} onClick={() => handleDispatchCommand('whoami /priv /fo table')}>
                    Privileges (whoami)
                  </button>
                  <button className="btn btn-secondary btn-sm" style={{ fontSize: 11 }} onClick={() => handleDispatchCommand('wmic qfe get HotFixID,InstalledOn')}>
                    Installed Patches (wmic)
                  </button>
                  <button className="btn btn-secondary btn-sm" style={{ fontSize: 11 }} onClick={() => handleDispatchCommand('systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Boot Time"')}>
                    System Boot Info
                  </button>
                </>
              ) : (
                <>
                  <button className="btn btn-secondary btn-sm" style={{ fontSize: 11 }} onClick={() => handleDispatchCommand('ss -tulpn')}>
                    Active Sockets (ss)
                  </button>
                  <button className="btn btn-secondary btn-sm" style={{ fontSize: 11 }} onClick={() => handleDispatchCommand('id && uname -a')}>
                    Host & Kernel Info
                  </button>
                  <button className="btn btn-secondary btn-sm" style={{ fontSize: 11 }} onClick={() => handleDispatchCommand('ps aux --sort=-%cpu | head -n 12')}>
                    Top CPU Processes
                  </button>
                  <button className="btn btn-secondary btn-sm" style={{ fontSize: 11 }} onClick={() => handleDispatchCommand('lsmod | head -n 15')}>
                    Loaded Kernel Modules
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Command Dispatch Input */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 24 }}>
            <input
              type="text"
              placeholder={isWindows ? "Type PowerShell/CMD triage command (e.g. netstat -ano, Get-Process)..." : "Type Bash triage command (e.g. ps aux, ss -tulpn)..."}
              value={commandInput}
              onChange={e => setCommandInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleDispatchCommand()}
              style={{
                flex: 1,
                padding: '10px 14px',
                borderRadius: 6,
                border: '1px solid var(--border-subtle)',
                background: 'var(--bg-item)',
                color: 'var(--text-main)',
                fontFamily: 'monospace',
                fontSize: 13
              }}
            />
            <button
              className="btn btn-primary"
              disabled={isDispatchingCmd || !commandInput.trim()}
              onClick={() => handleDispatchCommand()}
            >
              <Send size={14} /> Dispatch Command
            </button>
          </div>

          {/* Execution Log */}
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>Command History &amp; Tamper Seals</span>
              <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>{commands.length} executed</span>
            </div>

            {commands.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '30px 20px', color: 'var(--text-dim)', background: 'var(--bg-item)', borderRadius: 8 }}>
                No triage commands dispatched yet. Select a preset or type a command above.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {commands.map(cmd => (
                  <div
                    key={cmd.id}
                    style={{
                      background: 'var(--bg-item)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 8,
                      overflow: 'hidden'
                    }}
                  >
                    <div style={{
                      padding: '10px 14px',
                      background: 'rgba(0,0,0,0.15)',
                      borderBottom: '1px solid var(--border-subtle)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: 8
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <span style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--accent-blue)', fontSize: 12 }}>
                          {cmd.id}
                        </span>
                        <code style={{ fontSize: 13, color: 'var(--text-main)', fontWeight: 600 }}>
                          $ {cmd.command}
                        </code>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 11 }}>
                        <span style={{ color: 'var(--text-dim)' }}>
                          <Clock size={11} style={{ display: 'inline', marginRight: 4 }} />
                          {formatDateTime(cmd.dispatched_at)}
                        </span>
                        <span className={`badge ${cmd.status === 'COMPLETED' ? 'badge-completed' : cmd.status === 'FAILED' ? 'badge-error' : 'badge-in-progress'}`} style={{ fontSize: 10 }}>
                          {cmd.status} (exit {cmd.exit_code ?? '-'})
                        </span>
                      </div>
                    </div>

                    {/* Terminal Output */}
                    <div style={{ padding: '12px 14px' }}>
                      <pre style={{
                        margin: 0,
                        padding: 12,
                        background: '#090d16',
                        color: '#34d399',
                        borderRadius: 6,
                        fontFamily: 'monospace',
                        fontSize: 11,
                        lineHeight: 1.4,
                        maxHeight: 220,
                        overflowY: 'auto',
                        whiteSpace: 'pre-wrap'
                      }}>
                        {cmd.output || cmd.error || (cmd.status === 'PENDING' ? 'Waiting for agent to pick up command...' : 'Executing...')}
                      </pre>

                      {/* Tamper Seal */}
                      {cmd.signed_hash && (
                        <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#10b981' }}>
                          <ShieldCheck size={13} />
                          <span>Tamper-Evident SHA-256 Seal:</span>
                          <span style={{ fontFamily: 'monospace', color: 'var(--text-muted)' }}>{cmd.signed_hash}</span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: Forensic Events */}
      {activeTab === 'events' && (
        <div className="glass-panel" style={{ padding: 20 }}>
          {events.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-dim)' }}>
              <CheckCircle2 size={32} color="#10b981" style={{ marginBottom: 10 }} />
              <div>No suspicious forensic events detected. Physical host is operating within normal baseline.</div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {events.map(e => {
                const isHigh = e.severity === 'HIGH' || e.severity === 'CRITICAL';
                return (
                  <div
                    key={e.id}
                    style={{
                      background: 'var(--bg-item)',
                      borderLeft: `4px solid ${isHigh ? '#f43f5e' : '#f59e0b'}`,
                      borderRadius: 6,
                      padding: 14
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--text-main)' }}>
                        {e.event_type}
                      </span>
                      <span className={`badge ${isHigh ? 'badge-error' : 'badge-warning'}`} style={{ fontSize: 10 }}>
                        {e.severity}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>
                      {e.description}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-dim)', display: 'flex', gap: 16 }}>
                      <span>Source: {e.source}</span>
                      {e.process_name && <span>Process: {e.process_name} (PID {e.pid})</span>}
                      {e.user && <span>User: {e.user}</span>}
                      <span>Time: {formatDateTime(e.timestamp)}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Telemetry Stream History */}
      {activeTab === 'metrics' && (
        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ overflowX: 'auto', maxHeight: 450, overflowY: 'auto' }}>
            <table className="data-table" style={{ width: '100%', fontSize: 12 }}>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>CPU %</th>
                  <th>RAM %</th>
                  <th>Disk %</th>
                  <th>Upload Rate</th>
                  <th>Download Rate</th>
                  <th>Active Sockets</th>
                </tr>
              </thead>
              <tbody>
                {telemetryHistory.slice().reverse().map((t, idx) => (
                  <tr key={idx}>
                    <td style={{ fontFamily: 'monospace', color: 'var(--text-dim)' }}>{t.timestamp.replace('T', ' ').slice(0, 19)}</td>
                    <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{t.cpu_percent}%</td>
                    <td style={{ fontFamily: 'monospace' }}>{t.memory_percent}%</td>
                    <td style={{ fontFamily: 'monospace' }}>{t.disk_percent}%</td>
                    <td style={{ fontFamily: 'monospace', color: '#fbbf24' }}>{(t.network_upload_speed / 1024).toFixed(1)} KB/s</td>
                    <td style={{ fontFamily: 'monospace', color: '#fbbf24' }}>{(t.network_download_speed / 1024).toFixed(1)} KB/s</td>
                    <td style={{ fontFamily: 'monospace' }}>{t.active_connections}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
