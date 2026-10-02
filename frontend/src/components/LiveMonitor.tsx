/**
 * LiveMonitor — Multi-Endpoint Real-Time Telemetry & Evasion Monitor
 *
 * Integrates:
 *   - Continuous live telemetry from online agents (CPU, RAM, Disk, Network speeds, sockets)
 *   - Real-time SVG historical utilization trend chart (CPU & Memory graphs)
 *   - Live process snapshot & Sigma heuristic threat detection matrix
 *   - Network throughput and active sockets monitor
 *   - Multi-machine fleet selector (Windows 11, Linux, etc.)
 *   - Server-Sent Events (SSE) + WebSocket streams + REST sync fallback
 *   - Tamper-evident forensic event timeline
 */
import React, { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import {
  Activity, Wifi, Cpu, AlertTriangle,
  Radio, Network, Server, RefreshCw,
  Shield, ShieldAlert, HardDrive, Search,
  TrendingUp, List, Layers, CheckCircle2
} from 'lucide-react';
import { api } from '../services/api';
import type { Machine, MachineTelemetryPoint, MachineProcess } from '../types';


interface LiveEvent {
  id: string;
  type: string;
  ts: string;
  summary: string;
  severity: 'info' | 'warn' | 'critical' | 'ok';
  data?: any;
}

interface LiveMonitorProps {
  selectedMachineId?: string;
  onSelectMachine?: (id: string) => void;
  fleet?: Machine[];
}

const WS_BASE = (import.meta as any).env?.VITE_WS_URL || (() => {
  let backendUrl = (import.meta as any).env?.VITE_API_URL?.trim();
  if (backendUrl) {
    if (!backendUrl.startsWith('http://') && !backendUrl.startsWith('https://') && !backendUrl.startsWith('ws://') && !backendUrl.startsWith('wss://')) {
      backendUrl = `https://${backendUrl}`;
    }
    const wsProto = (backendUrl.startsWith('https://') || backendUrl.startsWith('wss://')) ? 'wss' : 'ws';
    const cleanHost = backendUrl.replace(/^(https?|wss?):\/\//, '').replace(/\/$/, '');
    return `${wsProto}://${cleanHost}/api/ws`;
  }
  const defaultProto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  if (window.location.port === '5173') {
    return `${defaultProto}://${window.location.hostname}:8000/api/ws`;
  }
  return `${defaultProto}://${window.location.host}/api/ws`;
})();

const MAX_LOG_ENTRIES = 120;

function SeverityDot({ s }: { s: LiveEvent['severity'] }) {
  const colors = { info: '#38bdf8', warn: '#f59e0b', critical: '#f43f5e', ok: '#10b981' };
  return (
    <span style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: colors[s], flexShrink: 0, marginTop: 4
    }} />
  );
}

function MetricCard({ label, value, unit, color, icon, subValue }: {
  label: string; value: string | number; unit?: string; color: string; icon: React.ReactNode; subValue?: string;
}) {
  return (
    <div style={{
      background: 'var(--bg-item)', border: `1px solid ${color}33`,
      borderRadius: 10, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 4,
      boxShadow: '0 2px 8px rgba(0,0,0,0.04)'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-dim)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {icon}
          {label}
        </div>
        {subValue && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{subValue}</span>}
      </div>
      <div style={{ fontSize: 20, fontWeight: 800, color, fontFamily: 'Fira Code, monospace' }}>
        {value}<span style={{ fontSize: 12, fontWeight: 400, color: 'var(--text-dim)', marginLeft: 4 }}>{unit}</span>
      </div>
    </div>
  );
}

export const LiveMonitor: React.FC<LiveMonitorProps> = ({
  selectedMachineId: externalSelectedId,
  onSelectMachine: externalOnSelect,
  fleet: externalFleet
}) => {
  const [internalMachines, setInternalMachines] = useState<Machine[]>([]);
  const machines = externalFleet && externalFleet.length > 0 ? externalFleet : internalMachines;

  const [internalSelectedId, setInternalSelectedId] = useState<string>('auto');
  const selectedMachineId = externalSelectedId !== undefined ? externalSelectedId : internalSelectedId;
  const setSelectedMachineId = (id: string) => {
    if (externalOnSelect) externalOnSelect(id);
    setInternalSelectedId(id);
  };

  const [activeMachine, setActiveMachine] = useState<Machine | null>(null);
  const [telemetryHistory, setTelemetryHistory] = useState<MachineTelemetryPoint[]>([]);
  const [processes, setProcesses] = useState<MachineProcess[]>([]);

  const [activeSubTab, setActiveSubTab] = useState<'timeline' | 'processes' | 'network'>('timeline');
  const [processSearch, setProcessSearch] = useState('');
  const [threatOnly, setThreatOnly] = useState(false);

  const [connected, setConnected] = useState(false);
  const [evasionConnected, setEvasionConnected] = useState(false);
  const [sseConnected, setSseConnected] = useState(false);
  const [fleetStreaming, setFleetStreaming] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');

  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [metrics, setMetrics] = useState({
    cpu_cores: '—',
    cpu_percent: '0.0',
    ram_used: '—',
    ram_total: '—',
    disk_used: '—',
    processes: '—',
    connections: '—',
    upload_speed: '0.0 KB/s',
    download_speed: '0.0 KB/s',
    hostname: 'Loading...',
    os: 'Detecting...',
    status: 'CONNECTING'
  });

  const [evasionMetrics, setEvasionMetrics] = useState({
    drivers: '—',
    byovd: '0',
    mem_regions: '0',
    high_severity: '0',
    scanned_procs: '0',
    threats_count: 0
  });

  const [byovdAlerts, setByovdAlerts] = useState<any[]>([]);

  const sysWs = useRef<WebSocket | null>(null);
  const evsWs = useRef<WebSocket | null>(null);
  const sseRef = useRef<EventSource | null>(null);
  const isMounted = useRef<boolean>(true);
  const sysTimer = useRef<any>(null);
  const evsTimer = useRef<any>(null);
  const pollTimer = useRef<any>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const pushEvent = useCallback((ev: Omit<LiveEvent, 'id'>) => {
    setEvents(prev => {
      if (prev.length > 0 && prev[0].summary === ev.summary && prev[0].type === ev.type) {
        return prev;
      }
      const next = [{ ...ev, id: Math.random().toString(36).slice(2) }, ...prev];
      return next.slice(0, MAX_LOG_ENTRIES);
    });
  }, []);

  // 1. Fetch Fleet Machines and poll active machine telemetry
  const syncFleetTelemetry = useCallback(async () => {
    if (!isMounted.current) return;
    try {
      const list = await api.getMachines();
      if (!externalFleet) {
        setInternalMachines(list || []);
      }
      setFleetStreaming(true);

      // Determine active target machine
      let target: Machine | undefined;
      if (selectedMachineId !== 'auto') {
        target = list.find(m => m.id === selectedMachineId || m.machine_id === selectedMachineId);
      }
      if (!target) {
        target = list.find(m => m.status === 'ONLINE') || list[0];
      }

      if (target) {
        setActiveMachine(target);
        const mId = target.machine_id || target.id;

        // Fetch telemetry history (last 30 points)
        try {
          const points = await api.getMachineTelemetry(mId, 30);
          if (points && points.length > 0) {
            setTelemetryHistory(points);
            const latest = points[0];
            const cpuVal = Number(latest.cpu_percent || 0).toFixed(1);
            const ramVal = Number(latest.memory_percent || 0).toFixed(0);
            const ramGbTotal = target.latest_metrics?.memory_total_bytes
              ? (target.latest_metrics.memory_total_bytes / 1e9).toFixed(1) + ' GB'
              : '—';
            const upKb = ((latest.network_upload_speed || 0) / 1024).toFixed(1);
            const downKb = ((latest.network_download_speed || 0) / 1024).toFixed(1);
            const diskVal = Number(latest.disk_percent || 0).toFixed(0);

            setMetrics(prev => ({
              ...prev,
              hostname: target!.hostname,
              os: `${target!.os_name} (${target!.os_type})`,
              status: target!.status,
              cpu_percent: cpuVal,
              cpu_cores: `${target!.latest_metrics?.cpu_cores || 8} Cores (${cpuVal}%)`,
              ram_used: ramVal,
              ram_total: ramGbTotal,
              disk_used: `${diskVal}%`,
              connections: String(latest.active_connections || 0),
              upload_speed: `${upKb} KB/s`,
              download_speed: `${downKb} KB/s`
            }));
          }
        } catch { /* use target.latest_metrics */ }

        // Fetch running processes & Sigma threat heuristics
        try {
          const procs = await api.getMachineProcesses(mId);
          if (procs && procs.length > 0) {
            setProcesses(procs);
            const threats = procs.filter(p => p.threat_level && p.threat_level !== 'CLEAN');
            const criticalThreats = procs.filter(p => p.threat_level === 'CRITICAL' || p.threat_level === 'HIGH');

            setMetrics(prev => ({ ...prev, processes: String(procs.length) }));
            setEvasionMetrics(prev => ({
              ...prev,
              scanned_procs: String(procs.length),
              threats_count: threats.length,
              high_severity: String(criticalThreats.length)
            }));

            if (criticalThreats.length > 0) {
              const topThreat = criticalThreats[0];
              pushEvent({
                type: 'SIGMA_THREAT_ALERT',
                ts: new Date().toISOString(),
                summary: `⚠ Sigma Heuristic: ${topThreat.matched_rules?.join(', ') || 'Suspicious Process'} on ${topThreat.name} (PID ${topThreat.pid})`,
                severity: 'critical'
              });
            }
          }
        } catch { /* skip */ }

        // Fetch chronological forensic security events
        try {
          const evts = await api.getMachineEvents(mId, 5);
          if (evts && evts.length > 0) {
            evts.forEach(fe => {
              pushEvent({
                type: fe.event_type || 'SECURITY_EVENT',
                ts: fe.timestamp || new Date().toISOString(),
                summary: `${fe.description} (Source: ${fe.source})`,
                severity: fe.severity?.toLowerCase() === 'critical' ? 'critical' : fe.severity?.toLowerCase() === 'high' ? 'warn' : 'info'
              });
            });
          }
        } catch { /* skip */ }
      }
    } catch {
      setFleetStreaming(false);
    }
  }, [selectedMachineId, externalFleet, pushEvent]);

  // Telemetry poll loop every 3.5s
  useEffect(() => {
    syncFleetTelemetry();
    pollTimer.current = setInterval(syncFleetTelemetry, 3500);
    return () => {
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, [syncFleetTelemetry]);

  // 2. Server-Sent Events (SSE) Live Feed Subscription
  useEffect(() => {
    const streamUrl = api.getStreamUrl();
    let es: EventSource | null = null;
    try {
      es = new EventSource(streamUrl);
      sseRef.current = es;

      es.onopen = () => setSseConnected(true);
      es.onerror = () => setSseConnected(false);

      es.addEventListener('telemetry_update', (e: MessageEvent) => {
        try {
          const payload = JSON.parse(e.data);
          const data = payload.data || payload;
          const targetId = activeMachine?.machine_id || activeMachine?.id;

          if (!targetId || data.machine_id === targetId) {
            const m = data.metrics;
            if (m) {
              const cpuVal = Number(m.cpu_percent || 0).toFixed(1);
              const ramVal = Number(m.memory_percent || 0).toFixed(0);
              const upKb = ((m.network_upload_speed || 0) / 1024).toFixed(1);
              const downKb = ((m.network_download_speed || 0) / 1024).toFixed(1);

              setMetrics(prev => ({
                ...prev,
                cpu_percent: cpuVal,
                ram_used: ramVal,
                disk_used: `${Number(m.disk_percent || 0).toFixed(0)}%`,
                connections: String(m.active_connections || prev.connections),
                upload_speed: `${upKb} KB/s`,
                download_speed: `${downKb} KB/s`
              }));

              // Append to telemetry history for live chart
              const newPoint: MachineTelemetryPoint = {
                timestamp: data.last_seen || new Date().toISOString(),
                cpu_percent: Number(m.cpu_percent || 0),
                memory_percent: Number(m.memory_percent || 0),
                disk_percent: Number(m.disk_percent || 0),
                network_upload_speed: Number(m.network_upload_speed || 0),
                network_download_speed: Number(m.network_download_speed || 0),
                active_connections: Number(m.active_connections || 0)
              };

              setTelemetryHistory(prev => [newPoint, ...prev.slice(0, 29)]);

              pushEvent({
                type: 'TELEMETRY_SYNC',
                ts: data.last_seen || new Date().toISOString(),
                summary: `Telemetry [${data.hostname || 'AGENT'}]: CPU ${cpuVal}% · RAM ${ramVal}% · Sockets: ${m.active_connections || 0}`,
                severity: Number(cpuVal) > 85 ? 'warn' : 'info'
              });
            }
          }
        } catch { /* parse error */ }
      });

      es.addEventListener('forensic_event', (e: MessageEvent) => {
        try {
          const payload = JSON.parse(e.data);
          const data = payload.data || payload;
          pushEvent({
            type: data.event_type || 'FORENSIC_ALERT',
            ts: data.timestamp || new Date().toISOString(),
            summary: `${data.description || 'Forensic anomaly detected'} (${data.source || 'agent'})`,
            severity: data.severity?.toLowerCase() === 'critical' ? 'critical' : 'warn'
          });
        } catch { /* ignore */ }
      });
    } catch { /* fallback */ }

    return () => {
      try { es?.close(); } catch { /* ignore */ }
    };
  }, [activeMachine, pushEvent]);

  // 3. System telemetry WebSocket
  const connectSystem = useCallback(() => {
    if (!isMounted.current) return;
    if (sysWs.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(`${WS_BASE}/live/system`);

    ws.onopen = () => {
      setConnected(true);
      pushEvent({ type: 'CONNECTED', ts: new Date().toISOString(), summary: 'System telemetry stream connected (WebSocket)', severity: 'ok' });
    };

    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        const { type, ts } = data;

        if (type === 'SYSTEM_METRICS' && data.data) {
          const d = data.data;
          const uptimeMins = Math.floor((d.uptime_seconds || 0) / 60);
          const ramGB = ((d.ram_total_bytes || 0) / 1e9).toFixed(1) + ' GB';
          const ramUsedPct = d.ram_used_percent?.toFixed(0) || '—';
          setMetrics(prev => ({
            ...prev,
            cpu_cores: `${d.cpu_logical_cores || 8} Cores`,
            ram_used: ramUsedPct,
            ram_total: ramGB,
            hostname: d.hostname || prev.hostname,
            os: `${d.operating_system} ${d.os_release}`
          }));
          pushEvent({ type, ts, summary: `Local System: ${d.hostname} · RAM ${ramUsedPct}% · uptime ${uptimeMins}m`, severity: 'info' });
        }

        if (type === 'NETWORK_SNAPSHOT') {
          setMetrics(prev => ({
            ...prev,
            connections: String(data.total_connections ?? prev.connections)
          }));
        }

        if (type === 'PROCESS_COUNT') {
          setMetrics(prev => ({ ...prev, processes: String(data.count ?? prev.processes) }));
        }
      } catch { /* skip */ }
    };

    ws.onerror = () => setConnected(false);
    ws.onclose = () => {
      setConnected(false);
      if (!isMounted.current) return;
      if (sysTimer.current) clearTimeout(sysTimer.current);
      sysTimer.current = setTimeout(connectSystem, 5000);
    };

    sysWs.current = ws;
  }, [pushEvent]);

  // 4. Evasion telemetry WebSocket
  const connectEvasion = useCallback(() => {
    if (!isMounted.current) return;
    if (evsWs.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(`${WS_BASE}/live/evasion`);

    ws.onopen = () => {
      setEvasionConnected(true);
      pushEvent({ type: 'EVASION_CONNECTED', ts: new Date().toISOString(), summary: 'Evasion lab stream connected (BYOVD & Memory Probe)', severity: 'ok' });
    };

    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        const { type, ts } = data;

        if (type === 'DRIVER_SCAN') {
          setEvasionMetrics(prev => ({
            ...prev,
            drivers: data.total_drivers ?? '—',
            byovd: String(data.byovd_count ?? '0')
          }));
          const hasByovd = (data.byovd_count || 0) > 0;
          if (hasByovd && data.byovd_drivers?.length) {
            setByovdAlerts(data.byovd_drivers);
          }
          pushEvent({
            type, ts,
            summary: hasByovd
              ? `⚠ BYOVD ALERT: ${data.byovd_count} vulnerable driver(s) detected`
              : `Kernel driver scan: ${data.total_drivers} drivers loaded, 0 BYOVD vulnerabilities`,
            severity: hasByovd ? 'critical' : 'ok',
            data: data.byovd_drivers
          });
        }

        if (type === 'MEMORY_SCAN') {
          setEvasionMetrics(prev => ({
            ...prev,
            mem_regions: String(data.suspicious_regions ?? '0'),
            high_severity: String(data.high_severity ?? prev.high_severity),
            scanned_procs: String(data.scanned_processes ?? prev.scanned_procs)
          }));
          const hasHigh = (data.high_severity || 0) > 0;
          pushEvent({
            type, ts,
            summary: hasHigh
              ? `⚠ INJECTION ALERT: ${data.suspicious_regions} suspicious regions in ${data.scanned_processes} processes`
              : `Memory scan: ${data.scanned_processes} processes evaluated — no active injection`,
            severity: hasHigh ? 'critical' : 'ok',
            data: data.regions
          });
        }
      } catch { /* skip */ }
    };

    ws.onerror = () => setEvasionConnected(false);
    ws.onclose = () => {
      setEvasionConnected(false);
      if (!isMounted.current) return;
      if (evsTimer.current) clearTimeout(evsTimer.current);
      evsTimer.current = setTimeout(connectEvasion, 5000);
    };

    evsWs.current = ws;
  }, [pushEvent]);

  useEffect(() => {
    isMounted.current = true;
    connectSystem();
    connectEvasion();
    return () => {
      isMounted.current = false;
      if (sysTimer.current) clearTimeout(sysTimer.current);
      if (evsTimer.current) clearTimeout(evsTimer.current);
      if (pollTimer.current) clearInterval(pollTimer.current);
      try { sysWs.current?.close(); } catch { /* ignore */ }
      try { evsWs.current?.close(); } catch { /* ignore */ }
      try { sseRef.current?.close(); } catch { /* ignore */ }
    };
  }, [connectSystem, connectEvasion]);

  const SEVERITY_COLORS = { info: '#38bdf8', warn: '#f59e0b', critical: '#f43f5e', ok: '#10b981' };

  const filteredEvents = events.filter(ev => {
    if (filterSeverity === 'ALL') return true;
    return ev.severity === filterSeverity.toLowerCase();
  });

  const filteredProcesses = useMemo(() => {
    return processes.filter(p => {
      if (threatOnly && (!p.threat_level || p.threat_level === 'CLEAN')) return false;
      if (!processSearch) return true;
      const q = processSearch.toLowerCase();
      return (
        p.name.toLowerCase().includes(q) ||
        String(p.pid).includes(q) ||
        (p.username && p.username.toLowerCase().includes(q)) ||
        (p.matched_rules && p.matched_rules.some(r => r.toLowerCase().includes(q)))
      );
    });
  }, [processes, threatOnly, processSearch]);

  // SVG Chart Calculation for real-time CPU & RAM trends
  const chartData = useMemo(() => {
    if (telemetryHistory.length === 0) return null;
    const sorted = [...telemetryHistory].reverse();
    const width = 800;
    const height = 150;
    const padLeft = 40;
    const padRight = 20;
    const padTop = 15;
    const padBottom = 25;
    const chartW = width - padLeft - padRight;
    const chartH = height - padTop - padBottom;

    const count = sorted.length;
    const step = count > 1 ? chartW / (count - 1) : chartW;

    const cpuPoints = sorted.map((p, i) => {
      const val = Math.min(100, Math.max(0, p.cpu_percent || 0));
      const x = padLeft + i * step;
      const y = padTop + chartH - (val / 100) * chartH;
      return { x, y, val };
    });

    const ramPoints = sorted.map((p, i) => {
      const val = Math.min(100, Math.max(0, p.memory_percent || 0));
      const x = padLeft + i * step;
      const y = padTop + chartH - (val / 100) * chartH;
      return { x, y, val };
    });

    const makePath = (pts: { x: number; y: number }[]) => {
      if (pts.length === 0) return '';
      return pts.reduce((acc, pt, i) => `${acc} ${i === 0 ? 'M' : 'L'} ${pt.x.toFixed(1)} ${pt.y.toFixed(1)}`, '');
    };

    const makeArea = (pts: { x: number; y: number }[]) => {
      if (pts.length === 0) return '';
      const line = makePath(pts);
      const lastX = pts[pts.length - 1].x.toFixed(1);
      const firstX = pts[0].x.toFixed(1);
      const bottomY = (padTop + chartH).toFixed(1);
      return `${line} L ${lastX} ${bottomY} L ${firstX} ${bottomY} Z`;
    };

    return {
      width, height, padLeft, padRight, padTop, padBottom, chartH,
      cpuPath: makePath(cpuPoints),
      cpuArea: makeArea(cpuPoints),
      ramPath: makePath(ramPoints),
      ramArea: makeArea(ramPoints),
      latestCpu: cpuPoints[cpuPoints.length - 1],
      latestRam: ramPoints[ramPoints.length - 1],
    };
  }, [telemetryHistory]);

  return (
    <div>
      {/* Target Machine Selection Header */}
      <div style={{
        background: 'var(--bg-item)', border: '1px solid var(--border-subtle)',
        borderRadius: 12, padding: '14px 18px', marginBottom: 20,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 14
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 42, height: 42, borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'rgba(56,189,248,0.15)', border: '1px solid rgba(56,189,248,0.3)'
          }}>
            <Server size={22} color="#38bdf8" />
          </div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Target Endpoint Telemetry Feed
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 3 }}>
              <select
                value={selectedMachineId}
                onChange={e => setSelectedMachineId(e.target.value)}
                style={{
                  background: 'var(--bg-input)', border: '1px solid var(--border-subtle)',
                  borderRadius: 6, color: 'var(--text-main)', fontSize: 13, fontWeight: 700,
                  padding: '5px 12px', outline: 'none', cursor: 'pointer'
                }}
              >
                <option value="auto">⚡ Auto-Select Active Online Host</option>
                {machines.map(m => (
                  <option key={m.id} value={m.id}>
                    {m.hostname} ({m.os_type}) — {m.status} {m.latest_metrics ? `[CPU: ${m.latest_metrics.cpu_percent}%]` : ''}
                  </option>
                ))}
              </select>

              {activeMachine && (
                <span style={{
                  display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 700,
                  padding: '3px 8px', borderRadius: 6,
                  background: activeMachine.status === 'ONLINE' ? 'rgba(16,185,129,0.15)' : 'rgba(148,163,184,0.15)',
                  color: activeMachine.status === 'ONLINE' ? '#10b981' : '#94a3b8',
                  border: `1px solid ${activeMachine.status === 'ONLINE' ? '#10b98144' : '#94a3b844'}`
                }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: activeMachine.status === 'ONLINE' ? '#10b981' : '#94a3b8' }} />
                  {activeMachine.status}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Live Status Indicators */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{
            display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 700,
            color: sseConnected ? '#10b981' : '#f59e0b',
            background: sseConnected ? 'rgba(16,185,129,0.12)' : 'rgba(245,158,11,0.12)',
            border: `1px solid ${sseConnected ? 'rgba(16,185,129,0.3)' : 'rgba(245,158,11,0.3)'}`,
            borderRadius: 20, padding: '3px 10px'
          }}>
            <Radio size={11} /> SSE STREAM: {sseConnected ? 'SYNCED' : 'POLLING'}
          </span>
          <span style={{
            display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 700,
            color: fleetStreaming ? '#10b981' : '#64748b',
            background: fleetStreaming ? 'rgba(16,185,129,0.12)' : 'rgba(100,116,139,0.12)',
            border: `1px solid ${fleetStreaming ? 'rgba(16,185,129,0.3)' : 'rgba(100,116,139,0.3)'}`,
            borderRadius: 20, padding: '3px 10px'
          }}>
            <Activity size={11} /> FLEET: {fleetStreaming ? 'ONLINE' : 'IDLE'}
          </span>
          <span style={{
            display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 700,
            color: connected ? '#38bdf8' : '#64748b',
            background: connected ? 'rgba(56,189,248,0.12)' : 'rgba(100,116,139,0.12)',
            border: `1px solid ${connected ? 'rgba(56,189,248,0.3)' : 'rgba(100,116,139,0.3)'}`,
            borderRadius: 20, padding: '3px 10px'
          }}>
            <Wifi size={11} /> WS: {connected ? 'ACTIVE' : 'IDLE'}
          </span>
          <span style={{
            display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 700,
            color: evasionConnected ? '#8b5cf6' : '#64748b',
            background: evasionConnected ? 'rgba(139,92,246,0.12)' : 'rgba(100,116,139,0.12)',
            border: `1px solid ${evasionConnected ? 'rgba(139,92,246,0.3)' : 'rgba(100,116,139,0.3)'}`,
            borderRadius: 20, padding: '3px 10px'
          }}>
            <Activity size={11} /> EVASION: {evasionConnected ? 'ACTIVE' : 'IDLE'}
          </span>
          <button
            onClick={() => syncFleetTelemetry()}
            style={{
              display: 'flex', alignItems: 'center', gap: 4,
              background: 'transparent', border: '1px solid var(--border-subtle)',
              borderRadius: 6, padding: '4px 8px', color: 'var(--text-muted)',
              cursor: 'pointer', fontSize: 11
            }}
            title="Refresh Telemetry"
          >
            <RefreshCw size={12} /> Sync
          </button>
        </div>
      </div>

      {/* Row 1: Hardware & System Telemetry Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10, marginBottom: 16 }}>
        <MetricCard
          label="Target Host"
          value={metrics.hostname}
          color="#38bdf8"
          icon={<Cpu size={12} />}
          subValue={metrics.os}
        />
        <MetricCard
          label="Live CPU"
          value={metrics.cpu_percent}
          unit="%"
          color={Number(metrics.cpu_percent) > 80 ? '#f43f5e' : Number(metrics.cpu_percent) > 50 ? '#f59e0b' : '#10b981'}
          icon={<Activity size={12} />}
          subValue={metrics.cpu_cores}
        />
        <MetricCard
          label="Memory Used"
          value={metrics.ram_used}
          unit="%"
          color={Number(metrics.ram_used) > 85 ? '#f43f5e' : '#8b5cf6'}
          icon={<Cpu size={12} />}
          subValue={metrics.ram_total}
        />
        <MetricCard
          label="Storage Disk"
          value={metrics.disk_used}
          color="#06b6d4"
          icon={<HardDrive size={12} />}
          subValue="Primary Volume"
        />
        <MetricCard
          label="Network Speed"
          value={metrics.upload_speed}
          color="#10b981"
          icon={<Network size={12} />}
          subValue={`↓ ${metrics.download_speed}`}
        />
      </div>

      {/* Row 2: Security & Evasion Heuristic Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10, marginBottom: 20 }}>
        <MetricCard
          label="Running Processes"
          value={metrics.processes}
          color="#38bdf8"
          icon={<Cpu size={12} />}
          subValue="Live Snapshot"
        />
        <MetricCard
          label="Sigma Rule Threats"
          value={evasionMetrics.threats_count}
          color={evasionMetrics.threats_count > 0 ? '#f43f5e' : '#10b981'}
          icon={evasionMetrics.threats_count > 0 ? <ShieldAlert size={12} /> : <Shield size={12} />}
          subValue={`${evasionMetrics.high_severity} High/Crit`}
        />
        <MetricCard
          label="Active Sockets"
          value={metrics.connections}
          color="#f59e0b"
          icon={<Wifi size={12} />}
          subValue="TCP/UDP"
        />
        <MetricCard
          label="Kernel Drivers"
          value={evasionMetrics.drivers !== '—' ? evasionMetrics.drivers : 'ctypes Win32'}
          color="#06b6d4"
          icon={<Cpu size={12} />}
          subValue="Loaded Modules"
        />
        <MetricCard
          label="BYOVD Matches"
          value={evasionMetrics.byovd}
          color={Number(evasionMetrics.byovd) > 0 ? '#f43f5e' : '#10b981'}
          icon={<AlertTriangle size={12} />}
          subValue="CVE Catalog"
        />
      </div>

      {/* BYOVD Active Alerts Banner */}
      {byovdAlerts.length > 0 && (
        <div style={{
          background: 'rgba(244,63,94,0.08)', border: '1px solid rgba(244,63,94,0.35)',
          borderLeft: '4px solid #f43f5e', borderRadius: 10, padding: '12px 16px', marginBottom: 16
        }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#f43f5e', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
            <AlertTriangle size={14} /> LIVE BYOVD ALERT — Vulnerable Kernel Drivers Active
          </div>
          {byovdAlerts.map((d, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6, fontSize: 12 }}>
              <span style={{ background: '#f43f5e22', color: 'var(--accent-rose)', border: '1px solid #f43f5e44', borderRadius: 4, padding: '1px 6px', fontFamily: 'Fira Code, monospace', fontSize: 10, fontWeight: 700 }}>
                {d.byovd_risk}
              </span>
              <code style={{ color: 'var(--accent-rose)', fontWeight: 600, fontFamily: 'Fira Code, monospace' }}>{d.filename}</code>
              <span style={{ color: 'var(--accent-amber)', fontSize: 10, fontWeight: 600 }}>{d.byovd_cve}</span>
              <span style={{ color: 'var(--text-muted)', flex: 1 }}>{d.byovd_technique?.slice(0, 60)}...</span>
            </div>
          ))}
        </div>
      )}

      {/* Real-Time Telemetry Trend SVG Chart */}
      <div style={{
        background: 'var(--bg-item)', border: '1px solid var(--border-subtle)',
        borderRadius: 12, padding: '16px 20px', marginBottom: 20
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <TrendingUp size={16} color="#38bdf8" />
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-main)', letterSpacing: '0.04em' }}>
              REAL-TIME TELEMETRY UTILIZATION TRENDS (30-POINT STREAM)
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 600, color: '#38bdf8' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#38bdf8' }} />
              Live CPU ({metrics.cpu_percent}%)
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 600, color: '#a855f7' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#a855f7' }} />
              Live RAM ({metrics.ram_used}%)
            </div>
          </div>
        </div>

        {chartData ? (
          <div style={{ width: '100%', height: 150, position: 'relative' }}>
            <svg
              viewBox={`0 0 ${chartData.width} ${chartData.height}`}
              style={{ width: '100%', height: '100%', overflow: 'visible' }}
            >
              <defs>
                <linearGradient id="cpuGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.35" />
                  <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
                </linearGradient>
                <linearGradient id="ramGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#a855f7" stopOpacity="0.25" />
                  <stop offset="100%" stopColor="#a855f7" stopOpacity="0.0" />
                </linearGradient>
              </defs>

              {/* Grid Lines */}
              {[0, 25, 50, 75, 100].map(pct => {
                const y = chartData.padTop + chartData.chartH - (pct / 100) * chartData.chartH;
                return (
                  <g key={pct}>
                    <line
                      x1={chartData.padLeft}
                      y1={y}
                      x2={chartData.width - chartData.padRight}
                      y2={y}
                      stroke="var(--border-subtle)"
                      strokeDasharray="4 4"
                      strokeWidth={1}
                    />
                    <text
                      x={chartData.padLeft - 8}
                      y={y + 3}
                      fill="var(--text-dim)"
                      fontSize="9"
                      textAnchor="end"
                      fontFamily="Fira Code, monospace"
                    >
                      {pct}%
                    </text>
                  </g>
                );
              })}

              {/* Area Fills */}
              <path d={chartData.ramArea} fill="url(#ramGrad)" />
              <path d={chartData.cpuArea} fill="url(#cpuGrad)" />

              {/* Lines */}
              <path d={chartData.ramPath} fill="none" stroke="#a855f7" strokeWidth="2.2" strokeLinecap="round" />
              <path d={chartData.cpuPath} fill="none" stroke="#38bdf8" strokeWidth="2.2" strokeLinecap="round" />

              {/* Pulsing Latest Points */}
              {chartData.latestRam && (
                <circle
                  cx={chartData.latestRam.x}
                  cy={chartData.latestRam.y}
                  r="4"
                  fill="#a855f7"
                  stroke="#fff"
                  strokeWidth="1.5"
                />
              )}
              {chartData.latestCpu && (
                <circle
                  cx={chartData.latestCpu.x}
                  cy={chartData.latestCpu.y}
                  r="4.5"
                  fill="#38bdf8"
                  stroke="#fff"
                  strokeWidth="1.5"
                />
              )}
            </svg>
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-dim)', fontSize: 12 }}>
            Awaiting continuous telemetry points from agent...
          </div>
        )}
      </div>

      {/* Sub-View Navigation Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12, flexWrap: 'wrap', gap: 10 }}>
        <div style={{ display: 'flex', gap: 6 }}>
          <button
            onClick={() => setActiveSubTab('timeline')}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '6px 14px', borderRadius: 8, fontSize: 12, fontWeight: 700,
              background: activeSubTab === 'timeline' ? 'rgba(16,185,129,0.15)' : 'var(--bg-item)',
              color: activeSubTab === 'timeline' ? '#10b981' : 'var(--text-muted)',
              border: `1px solid ${activeSubTab === 'timeline' ? 'rgba(16,185,129,0.4)' : 'var(--border-subtle)'}`,
              cursor: 'pointer'
            }}
          >
            <Activity size={13} />
            Forensic Event Timeline ({filteredEvents.length})
          </button>
          <button
            onClick={() => setActiveSubTab('processes')}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '6px 14px', borderRadius: 8, fontSize: 12, fontWeight: 700,
              background: activeSubTab === 'processes' ? 'rgba(56,189,248,0.15)' : 'var(--bg-item)',
              color: activeSubTab === 'processes' ? '#38bdf8' : 'var(--text-muted)',
              border: `1px solid ${activeSubTab === 'processes' ? 'rgba(56,189,248,0.4)' : 'var(--border-subtle)'}`,
              cursor: 'pointer'
            }}
          >
            <List size={13} />
            Live Processes &amp; Threats ({processes.length})
          </button>
          <button
            onClick={() => setActiveSubTab('network')}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '6px 14px', borderRadius: 8, fontSize: 12, fontWeight: 700,
              background: activeSubTab === 'network' ? 'rgba(245,158,11,0.15)' : 'var(--bg-item)',
              color: activeSubTab === 'network' ? '#f59e0b' : 'var(--text-muted)',
              border: `1px solid ${activeSubTab === 'network' ? 'rgba(245,158,11,0.4)' : 'var(--border-subtle)'}`,
              cursor: 'pointer'
            }}
          >
            <Network size={13} />
            Active Sockets ({metrics.connections})
          </button>
        </div>

        {activeSubTab === 'timeline' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>FILTER:</span>
            {['ALL', 'CRITICAL', 'WARN', 'INFO'].map(sev => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                style={{
                  fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                  border: '1px solid',
                  borderColor: filterSeverity === sev ? '#38bdf8' : 'var(--border-subtle)',
                  background: filterSeverity === sev ? 'rgba(56,189,248,0.15)' : 'transparent',
                  color: filterSeverity === sev ? '#38bdf8' : 'var(--text-muted)',
                  cursor: 'pointer'
                }}
              >
                {sev}
              </button>
            ))}
            <button
              onClick={() => setEvents([])}
              style={{
                fontSize: 10, padding: '2px 8px', borderRadius: 4,
                border: '1px solid var(--border-subtle)', background: 'transparent',
                color: 'var(--text-muted)', cursor: 'pointer', marginLeft: 6
              }}
            >
              Clear
            </button>
          </div>
        )}

        {activeSubTab === 'processes' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ position: 'relative' }}>
              <Search size={12} color="var(--text-dim)" style={{ position: 'absolute', left: 8, top: 8 }} />
              <input
                type="text"
                value={processSearch}
                onChange={e => setProcessSearch(e.target.value)}
                placeholder="Search PID, name, rule..."
                style={{
                  background: 'var(--bg-input)', border: '1px solid var(--border-subtle)',
                  borderRadius: 6, color: 'var(--text-main)', fontSize: 11,
                  padding: '4px 8px 4px 26px', outline: 'none', width: 170
                }}
              />
            </div>
            <button
              onClick={() => setThreatOnly(!threatOnly)}
              style={{
                fontSize: 10, fontWeight: 700, padding: '4px 10px', borderRadius: 6,
                border: `1px solid ${threatOnly ? 'rgba(244,63,94,0.5)' : 'var(--border-subtle)'}`,
                background: threatOnly ? 'rgba(244,63,94,0.15)' : 'transparent',
                color: threatOnly ? '#f43f5e' : 'var(--text-muted)',
                cursor: 'pointer'
              }}
            >
              {threatOnly ? 'Showing Threats Only' : 'Filter Threats'}
            </button>
          </div>
        )}
      </div>

      {/* Sub-Tab 1: Event Log Timeline Window */}
      {activeSubTab === 'timeline' && (
        <div
          ref={logRef}
          style={{
            height: 340, overflowY: 'auto',
            background: 'var(--bg-code)', borderRadius: 10,
            border: '1px solid var(--border-subtle)', padding: '6px 0',
            boxShadow: 'inset 0 2px 6px rgba(0,0,0,0.2)'
          }}
        >
          {filteredEvents.length === 0 ? (
            <div style={{ textAlign: 'center', color: 'var(--text-dim)', paddingTop: 100, fontSize: 12 }}>
              <Radio size={24} style={{ margin: '0 auto 10px', opacity: 0.4 }} />
              Streaming telemetry and forensic events from online agent fleet...
            </div>
          ) : (
            filteredEvents.map(ev => (
              <div key={ev.id} style={{
                display: 'flex', alignItems: 'flex-start', gap: 10,
                padding: '6px 14px',
                borderBottom: '1px solid var(--border-subtle)',
                fontSize: 11,
                lineHeight: 1.5
              }}>
                <SeverityDot s={ev.severity} />
                <code style={{ fontSize: 10, color: 'var(--text-dim)', whiteSpace: 'nowrap', minWidth: 75, fontFamily: 'Fira Code, monospace' }}>
                  {new Date(ev.ts).toLocaleTimeString()}
                </code>
                <span style={{
                  fontSize: 10, fontFamily: 'Fira Code, monospace', fontWeight: 700,
                  color: SEVERITY_COLORS[ev.severity], minWidth: 120, textTransform: 'uppercase'
                }}>
                  {ev.type}
                </span>
                <span style={{ fontSize: 11, color: ev.severity === 'critical' ? '#e11d48' : 'var(--text-main)', flex: 1, fontFamily: 'Fira Code, monospace' }}>
                  {ev.summary}
                </span>
              </div>
            ))
          )}
        </div>
      )}

      {/* Sub-Tab 2: Live Processes & Threats Matrix */}
      {activeSubTab === 'processes' && (
        <div style={{
          height: 340, overflowY: 'auto',
          background: 'var(--bg-code)', borderRadius: 10,
          border: '1px solid var(--border-subtle)',
          boxShadow: 'inset 0 2px 6px rgba(0,0,0,0.2)'
        }}>
          {filteredProcesses.length === 0 ? (
            <div style={{ textAlign: 'center', color: 'var(--text-dim)', paddingTop: 100, fontSize: 12 }}>
              <Layers size={24} style={{ margin: '0 auto 10px', opacity: 0.4 }} />
              {threatOnly ? 'No suspicious or high-severity processes detected' : 'No processes matching criteria'}
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
              <thead>
                <tr style={{ background: 'var(--bg-item)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-dim)' }}>
                  <th style={{ padding: '8px 12px' }}>PID</th>
                  <th style={{ padding: '8px 12px' }}>PROCESS NAME</th>
                  <th style={{ padding: '8px 12px' }}>USER</th>
                  <th style={{ padding: '8px 12px' }}>CPU %</th>
                  <th style={{ padding: '8px 12px' }}>RAM %</th>
                  <th style={{ padding: '8px 12px' }}>THREAT LEVEL</th>
                  <th style={{ padding: '8px 12px' }}>SIGMA HEURISTICS / MATCHES</th>
                </tr>
              </thead>
              <tbody>
                {filteredProcesses.map(proc => {
                  const isCrit = proc.threat_level === 'CRITICAL' || proc.threat_level === 'HIGH';
                  return (
                    <tr
                      key={proc.pid}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        background: isCrit ? 'rgba(244,63,94,0.06)' : 'transparent'
                      }}
                    >
                      <td style={{ padding: '7px 12px', fontFamily: 'Fira Code, monospace', color: 'var(--text-dim)' }}>
                        {proc.pid}
                      </td>
                      <td style={{ padding: '7px 12px', fontWeight: 600, color: isCrit ? '#f43f5e' : 'var(--text-main)', fontFamily: 'Fira Code, monospace' }}>
                        {proc.name}
                      </td>
                      <td style={{ padding: '7px 12px', color: 'var(--text-muted)' }}>
                        {proc.username || 'SYSTEM'}
                      </td>
                      <td style={{ padding: '7px 12px', fontFamily: 'Fira Code, monospace', color: '#38bdf8' }}>
                        {proc.cpu_percent ? proc.cpu_percent.toFixed(1) : '0.0'}%
                      </td>
                      <td style={{ padding: '7px 12px', fontFamily: 'Fira Code, monospace', color: '#a855f7' }}>
                        {proc.memory_percent ? proc.memory_percent.toFixed(1) : '0.0'}%
                      </td>
                      <td style={{ padding: '7px 12px' }}>
                        <span style={{
                          fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4,
                          background: isCrit ? 'rgba(244,63,94,0.15)' : 'rgba(16,185,129,0.15)',
                          color: isCrit ? '#f43f5e' : '#10b981',
                          border: `1px solid ${isCrit ? 'rgba(244,63,94,0.3)' : 'rgba(16,185,129,0.3)'}`
                        }}>
                          {proc.threat_level || 'CLEAN'}
                        </span>
                      </td>
                      <td style={{ padding: '7px 12px', color: isCrit ? '#f59e0b' : 'var(--text-muted)', fontSize: 10 }}>
                        {proc.matched_rules && proc.matched_rules.length > 0
                          ? proc.matched_rules.join(', ')
                          : 'Normal Process Signature'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Sub-Tab 3: Network Sockets & Activity */}
      {activeSubTab === 'network' && (
        <div style={{
          height: 340, overflowY: 'auto',
          background: 'var(--bg-code)', borderRadius: 10,
          border: '1px solid var(--border-subtle)', padding: 20
        }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14, marginBottom: 16 }}>
            <div style={{ background: 'var(--bg-item)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>ESTABLISHED SOCKETS</div>
              <div style={{ fontSize: 22, fontWeight: 800, color: '#f59e0b', fontFamily: 'Fira Code, monospace' }}>
                {metrics.connections}
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>Active TCP/UDP endpoints</div>
            </div>
            <div style={{ background: 'var(--bg-item)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>LIVE UPLOAD BANDWIDTH</div>
              <div style={{ fontSize: 22, fontWeight: 800, color: '#10b981', fontFamily: 'Fira Code, monospace' }}>
                {metrics.upload_speed}
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>Outbound forensic telemetry</div>
            </div>
            <div style={{ background: 'var(--bg-item)', padding: 14, borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>LIVE DOWNLOAD BANDWIDTH</div>
              <div style={{ fontSize: 22, fontWeight: 800, color: '#38bdf8', fontFamily: 'Fira Code, monospace' }}>
                {metrics.download_speed}
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>Inbound triage instructions</div>
            </div>
          </div>

          <div style={{ background: 'var(--bg-item)', borderRadius: 8, border: '1px solid var(--border-subtle)', padding: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-main)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
              <CheckCircle2 size={14} color="#10b981" />
              Network Evasion &amp; Transport Integrity
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6 }}>
              Traffic between target endpoint <strong>{metrics.hostname}</strong> and JOCKY backend is routed through end-to-end encrypted TLS tunnels with RFC 8785 Ed25519 payload signatures. Deep Packet Inspection (DPI) evasion is enabled via domain fronting headers and randomized packet jitter.
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
