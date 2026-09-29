/**
 * LiveMonitor — Real-time WebSocket system telemetry panel.
 *
 * Connects to ws://localhost:8000/api/ws/live/system and pushes:
 *   - CPU / RAM metrics every 3s
 *   - External network connections every 6s
 *   - Process counts every 3s
 *
 * And connects to ws://localhost:8000/api/ws/live/evasion for:
 *   - Live BYOVD driver scans every 10s
 *   - Live memory injection scans every 20s
 */
import React, { useEffect, useRef, useState, useCallback } from 'react';
import {
  Activity, Wifi, Cpu, Database, AlertTriangle,
  Radio, MemoryStick, Network
} from 'lucide-react';

interface LiveEvent {
  id: string;
  type: string;
  ts: string;
  summary: string;
  severity: 'info' | 'warn' | 'critical' | 'ok';
  data?: any;
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
const MAX_LOG_ENTRIES = 80;

function SeverityDot({ s }: { s: LiveEvent['severity'] }) {
  const colors = { info: '#38bdf8', warn: '#f59e0b', critical: '#f43f5e', ok: '#10b981' };
  return (
    <span style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      background: colors[s], flexShrink: 0, marginTop: 2
    }} />
  );
}

function MetricCard({ label, value, unit, color, icon }: {
  label: string; value: string | number; unit?: string; color: string; icon: React.ReactNode;
}) {
  return (
    <div style={{
      background: 'var(--bg-item)', border: `1px solid ${color}22`,
      borderRadius: 10, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 4
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-dim)' }}>
        {icon}
        {label}
      </div>
      <div style={{ fontSize: 22, fontWeight: 800, color, fontFamily: 'Fira Code, monospace' }}>
        {value}<span style={{ fontSize: 12, fontWeight: 400, color: 'var(--text-dim)', marginLeft: 4 }}>{unit}</span>
      </div>
    </div>
  );
}

export const LiveMonitor: React.FC = () => {
  const [connected, setConnected] = useState(false);
  const [evasionConnected, setEvasionConnected] = useState(false);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [metrics, setMetrics] = useState({
    cpu_cores: '—', ram_used: '—', ram_total: '—',
    processes: '—', connections: '—', external: '—',
    hostname: '—', os: '—', uptime: '—'
  });
  const [evasionMetrics, setEvasionMetrics] = useState({
    drivers: '—', byovd: '—', mem_regions: '—', high_severity: '—', scanned_procs: '—'
  });
  const [byovdAlerts, setByovdAlerts] = useState<any[]>([]);

  const sysWs = useRef<WebSocket | null>(null);
  const evsWs = useRef<WebSocket | null>(null);
  const isMounted = useRef<boolean>(true);
  const sysTimer = useRef<any>(null);
  const evsTimer = useRef<any>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const pushEvent = useCallback((ev: Omit<LiveEvent, 'id'>) => {
    setEvents(prev => {
      const next = [{ ...ev, id: Math.random().toString(36).slice(2) }, ...prev];
      return next.slice(0, MAX_LOG_ENTRIES);
    });
  }, []);

  // System telemetry WebSocket
  const connectSystem = useCallback(() => {
    if (!isMounted.current) return;
    if (sysWs.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(`${WS_BASE}/live/system`);

    ws.onopen = () => {
      setConnected(true);
      pushEvent({ type: 'CONNECTED', ts: new Date().toISOString(), summary: 'System telemetry stream connected', severity: 'ok' });
    };

    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        const { type, ts } = data;

        if (type === 'SYSTEM_METRICS' && data.data) {
          const d = data.data;
          const uptimeMins = Math.floor((d.uptime_seconds || 0) / 60);
          const ramGB = ((d.ram_total_bytes || 0) / 1e9).toFixed(1);
          const ramUsedPct = d.ram_used_percent?.toFixed(0) || '—';
          setMetrics(prev => ({
            ...prev,
            cpu_cores: d.cpu_logical_cores ?? '—',
            ram_used: ramUsedPct,
            ram_total: ramGB,
            hostname: d.hostname || '—',
            os: `${d.operating_system} ${d.os_release}`,
            uptime: `${uptimeMins}m`
          }));
          pushEvent({ type, ts, summary: `System: ${d.hostname} · RAM ${ramUsedPct}% · uptime ${uptimeMins}m`, severity: 'info' });
        }

        if (type === 'NETWORK_SNAPSHOT') {
          setMetrics(prev => ({
            ...prev,
            connections: data.total_connections ?? '—',
            external: data.external_count ?? '—'
          }));
          const severity: LiveEvent['severity'] = (data.external_count || 0) > 5 ? 'warn' : 'info';
          pushEvent({ type, ts, summary: `Network: ${data.total_connections} connections, ${data.external_count} external`, severity, data: data.external_connections });
        }

        if (type === 'PROCESS_COUNT') {
          setMetrics(prev => ({ ...prev, processes: data.count ?? '—' }));
        }
      } catch { /* skip malformed */ }
    };

    ws.onerror = () => {
      setConnected(false);
      pushEvent({ type: 'ERROR', ts: new Date().toISOString(), summary: 'System stream error — will retry', severity: 'warn' });
    };

    ws.onclose = () => {
      setConnected(false);
      if (!isMounted.current) return;
      pushEvent({ type: 'DISCONNECTED', ts: new Date().toISOString(), summary: 'System stream disconnected', severity: 'warn' });
      if (sysTimer.current) clearTimeout(sysTimer.current);
      sysTimer.current = setTimeout(connectSystem, 5000);
    };

    sysWs.current = ws;
  }, [pushEvent]);

  // Evasion telemetry WebSocket
  const connectEvasion = useCallback(() => {
    if (!isMounted.current) return;
    if (evsWs.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(`${WS_BASE}/live/evasion`);

    ws.onopen = () => {
      setEvasionConnected(true);
      pushEvent({ type: 'EVASION_CONNECTED', ts: new Date().toISOString(), summary: 'Evasion lab stream connected (driver + memory scans)', severity: 'ok' });
    };

    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        const { type, ts } = data;

        if (type === 'DRIVER_SCAN') {
          setEvasionMetrics(prev => ({
            ...prev,
            drivers: data.total_drivers ?? '—',
            byovd: data.byovd_count ?? '—'
          }));
          const hasByovd = (data.byovd_count || 0) > 0;
          if (hasByovd && data.byovd_drivers?.length) {
            setByovdAlerts(data.byovd_drivers);
          }
          pushEvent({
            type, ts,
            summary: hasByovd
              ? `⚠ BYOVD ALERT: ${data.byovd_count} vulnerable driver(s) detected`
              : `Driver scan: ${data.total_drivers} drivers loaded, 0 BYOVD`,
            severity: hasByovd ? 'critical' : 'ok',
            data: data.byovd_drivers
          });
        }

        if (type === 'MEMORY_SCAN') {
          setEvasionMetrics(prev => ({
            ...prev,
            mem_regions: data.suspicious_regions ?? '—',
            high_severity: data.high_severity ?? '—',
            scanned_procs: data.scanned_processes ?? '—'
          }));
          const hasHigh = (data.high_severity || 0) > 0;
          pushEvent({
            type, ts,
            summary: hasHigh
              ? `⚠ INJECTION: ${data.suspicious_regions} suspicious regions (${data.high_severity} HIGH) in ${data.scanned_processes} procs`
              : `Memory scan: ${data.scanned_processes} procs — no injection detected`,
            severity: hasHigh ? 'critical' : 'ok',
            data: data.regions
          });
        }

        if (type === 'DRIVER_SCAN_ERROR' || type === 'MEMORY_SCAN_ERROR') {
          pushEvent({ type, ts, summary: `Evasion scan error: ${data.error}`, severity: 'warn' });
        }
      } catch { /* skip malformed */ }
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
      try { sysWs.current?.close(); } catch { /* ignore */ }
      try { evsWs.current?.close(); } catch { /* ignore */ }
    };
  }, [connectSystem, connectEvasion]);

  const SEVERITY_COLORS = { info: '#38bdf8', warn: '#f59e0b', critical: '#f43f5e', ok: '#10b981' };

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 20 }}>
        <div style={{
          width: 44, height: 44, borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'rgba(16,185,129,0.15)', border: '1px solid rgba(16,185,129,0.3)'
        }}>
          <Radio size={22} color="#10b981" />
        </div>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)' }}>Live System Monitor</div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 2 }}>Real-time telemetry via WebSocket — live OS data, no simulation</div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <span style={{
            display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 700,
            color: connected ? '#10b981' : '#f43f5e',
            background: connected ? 'rgba(16,185,129,0.12)' : 'rgba(244,63,94,0.12)',
            border: `1px solid ${connected ? 'rgba(16,185,129,0.3)' : 'rgba(244,63,94,0.3)'}`,
            borderRadius: 20, padding: '3px 10px'
          }}>
            <Wifi size={11} /> SYS {connected ? 'LIVE' : 'DISCONNECTED'}
          </span>
          <span style={{
            display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontWeight: 700,
            color: evasionConnected ? '#10b981' : '#f43f5e',
            background: evasionConnected ? 'rgba(16,185,129,0.12)' : 'rgba(244,63,94,0.12)',
            border: `1px solid ${evasionConnected ? 'rgba(16,185,129,0.3)' : 'rgba(244,63,94,0.3)'}`,
            borderRadius: 20, padding: '3px 10px'
          }}>
            <Activity size={11} /> EVASION {evasionConnected ? 'LIVE' : 'DISCONNECTED'}
          </span>
        </div>
      </div>

      {/* System metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 10, marginBottom: 16 }}>
        <MetricCard label="Hostname" value={metrics.hostname} color="#38bdf8" icon={<Cpu size={11} />} />
        <MetricCard label="Platform" value={metrics.os} color="#8b5cf6" icon={<Database size={11} />} />
        <MetricCard label="RAM Used" value={metrics.ram_used} unit="%" color="#f59e0b" icon={<MemoryStick size={11} />} />
        <MetricCard label="Connections" value={metrics.connections} color="#06b6d4" icon={<Network size={11} />} />
        <MetricCard label="External IPs" value={metrics.external} color={Number(metrics.external) > 5 ? '#f43f5e' : '#10b981'} icon={<Wifi size={11} />} />
      </div>

      {/* Evasion metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 10, marginBottom: 16 }}>
        <MetricCard label="Drivers Loaded" value={evasionMetrics.drivers} color="#38bdf8" icon={<Cpu size={11} />} />
        <MetricCard label="BYOVD Matches" value={evasionMetrics.byovd} color={Number(evasionMetrics.byovd) > 0 ? '#f43f5e' : '#10b981'} icon={<AlertTriangle size={11} />} />
        <MetricCard label="Suspicious Regions" value={evasionMetrics.mem_regions} color="#f59e0b" icon={<Activity size={11} />} />
        <MetricCard label="HIGH Severity" value={evasionMetrics.high_severity} color={Number(evasionMetrics.high_severity) > 0 ? '#f43f5e' : '#10b981'} icon={<AlertTriangle size={11} />} />
        <MetricCard label="Procs Scanned" value={evasionMetrics.scanned_procs} color="#8b5cf6" icon={<Cpu size={11} />} />
      </div>

      {/* BYOVD active alerts */}
      {byovdAlerts.length > 0 && (
        <div style={{
          background: 'rgba(244,63,94,0.08)', border: '1px solid rgba(244,63,94,0.35)',
          borderLeft: '3px solid #f43f5e', borderRadius: 10, padding: '12px 16px', marginBottom: 16
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

      {/* Event log */}
      <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 8 }}>
        LIVE EVENT LOG — {events.length} events
      </div>
      <div
        ref={logRef}
        style={{
          height: 320, overflowY: 'auto',
          background: 'var(--bg-code)', borderRadius: 10,
          border: '1px solid var(--border-subtle)', padding: '8px 0'
        }}
      >
        {events.length === 0 ? (
          <div style={{ textAlign: 'center', color: 'var(--text-dim)', paddingTop: 60, fontSize: 12 }}>
            Connecting to live streams...
          </div>
        ) : (
          events.map(ev => (
            <div key={ev.id} style={{
              display: 'flex', alignItems: 'flex-start', gap: 8,
              padding: '5px 14px',
              borderBottom: '1px solid var(--border-subtle)',
              transition: 'background 0.15s'
            }}>
              <SeverityDot s={ev.severity} />
              <code style={{ fontSize: 10, color: 'var(--text-dim)', whiteSpace: 'nowrap', minWidth: 75, fontFamily: 'Fira Code, monospace' }}>
                {new Date(ev.ts).toLocaleTimeString()}
              </code>
              <span style={{
                fontSize: 10, fontFamily: 'Fira Code, monospace', fontWeight: 700,
                color: SEVERITY_COLORS[ev.severity], minWidth: 100, textTransform: 'uppercase'
              }}>
                {ev.type}
              </span>
              <span style={{ fontSize: 11, color: ev.severity === 'critical' ? '#e11d48' : 'var(--text-muted)', flex: 1 }}>
                {ev.summary}
              </span>
            </div>
          ))
        )}
      </div>

      <style>{`
        @keyframes ping { 0%,100%{transform:scale(1);opacity:0.4} 50%{transform:scale(1.8);opacity:0} }
      `}</style>
    </div>
  );
};
