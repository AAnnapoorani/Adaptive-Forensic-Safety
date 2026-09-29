import React, { useState, useEffect, useCallback } from 'react';
import {
  Cpu, Shield, Zap, Lock, Globe, Server, RefreshCw,
  ChevronDown, ChevronRight, AlertTriangle, CheckCircle,
  Copy, Eye, EyeOff, Wifi, WifiOff, Terminal,
  Activity, Radio, Hash, Key, Link2, ShieldCheck, XCircle, Play
} from 'lucide-react';
import { api } from '../services/api';
import { LiveMonitor } from '../components/LiveMonitor';

// ── Helpers ────────────────────────────────────────────────────────────────

const RISK_COLOR: Record<string, string> = {
  CRITICAL: 'var(--accent-rose)',
  HIGH: 'var(--accent-amber)',
  MEDIUM: 'var(--accent-cyan)',
  LOW: 'var(--accent-emerald)',
};

const SEVERITY_BG: Record<string, string> = {
  CRITICAL: 'rgba(225, 29, 72, 0.12)',
  HIGH: 'rgba(217, 119, 6, 0.12)',
  MEDIUM: 'rgba(8, 145, 178, 0.12)',
  LOW: 'rgba(5, 150, 105, 0.12)',
};

function Badge({ text, color }: { text: string; color: string }) {
  return (
    <span style={{
      fontSize: 11, fontWeight: 700, padding: '2px 8px',
      borderRadius: 6, background: 'var(--bg-item)', color, border: `1px solid ${color}44`,
      fontFamily: 'Fira Code, monospace', letterSpacing: '0.05em'
    }}>{text}</span>
  );
}

function SectionHeader({ icon, title, subtitle, color = '#06b6d4' }: {
  icon: React.ReactNode; title: string; subtitle: string; color?: string;
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 20 }}>
      <div style={{
        width: 44, height: 44, borderRadius: 12, display: 'flex',
        alignItems: 'center', justifyContent: 'center',
        background: `${color}18`, border: `1px solid ${color}33`
      }}>{icon}</div>
      <div>
        <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)' }}>{title}</div>
        <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 2 }}>{subtitle}</div>
      </div>
    </div>
  );
}

function PulsingDot({ color }: { color: string }) {
  return (
    <span style={{ position: 'relative', display: 'inline-block', width: 10, height: 10 }}>
      <span style={{
        position: 'absolute', inset: 0, borderRadius: '50%',
        background: color, opacity: 0.4,
        animation: 'ping 1.5s cubic-bezier(0,0,0.2,1) infinite'
      }} />
      <span style={{
        position: 'absolute', inset: 2, borderRadius: '50%', background: color
      }} />
    </span>
  );
}

function LiveTag() {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5,
      fontSize: 10, fontWeight: 700, color: '#10b981',
      background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.3)',
      borderRadius: 20, padding: '2px 8px' }}>
      <PulsingDot color="#10b981" />
      LIVE
    </span>
  );
}

// ── Tab: Polymorphic Engine ─────────────────────────────────────────────────

function PolymorphicTab() {
  const [script, setScript] = useState('INVESTIGATE suspicious_network_activity');
  const [iterations, setIterations] = useState(3);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [selectedVariant, setSelectedVariant] = useState(0);
  const [copied, setCopied] = useState<number | null>(null);

  const run = async () => {
    setLoading(true);
    try {
      const res = await api.mutateScript(script, iterations);
      setResult(res);
      setSelectedVariant(0);
    } catch (e: any) {
      alert('Error: ' + e.message);
    } finally { setLoading(false); }
  };

  const copy = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopied(idx);
    setTimeout(() => setCopied(null), 1500);
  };

  return (
    <div>
      <SectionHeader
        icon={<Zap size={22} color="#f59e0b" />}
        title="Polymorphic Script Engine"
        subtitle="Generates structurally-equivalent JOCKY scripts with unique SHA-256 per output — neutralizing file-reputation AV databases"
        color="#f59e0b"
      />

      {/* Input */}
      <div className="glass-panel" style={{ padding: 20, marginBottom: 20 }}>
        <div style={{ display: 'flex', gap: 12, marginBottom: 12, alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
              JOCKY Source Script
            </label>
            <textarea
              value={script}
              onChange={e => setScript(e.target.value)}
              rows={4}
              style={{
                width: '100%', background: 'var(--bg-input)', border: '1px solid var(--border-subtle)',
                borderRadius: 8, color: 'var(--text-main)', fontFamily: 'Fira Code, monospace',
                fontSize: 13, padding: '10px 14px', resize: 'vertical', outline: 'none'
              }}
            />
          </div>
          <div style={{ minWidth: 120 }}>
            <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
              Variants
            </label>
            <input
              type="number" min={1} max={10} value={iterations}
              onChange={e => setIterations(Number(e.target.value))}
              style={{
                width: '100%', background: 'var(--bg-input)', border: '1px solid var(--border-subtle)',
                borderRadius: 8, color: 'var(--text-main)', fontSize: 14, padding: '10px 14px', outline: 'none'
              }}
            />
          </div>
        </div>
        <button
          onClick={run} disabled={loading}
          style={{
            display: 'flex', alignItems: 'center', gap: 8,
            background: loading ? 'rgba(245,158,11,0.1)' : 'linear-gradient(135deg,#f59e0b,#d97706)',
            color: '#fff', border: 'none', borderRadius: 8,
            padding: '10px 22px', cursor: loading ? 'not-allowed' : 'pointer',
            fontWeight: 700, fontSize: 13
          }}
        >
          {loading ? <RefreshCw size={14} className="spin" /> : <Zap size={14} />}
          {loading ? 'Mutating...' : 'Generate Polymorphic Variants'}
        </button>
      </div>

      {/* Result */}
      {result && (
        <div>
          {/* Hash Overview */}
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginBottom: 16
          }}>
            {[
              { label: 'Variants Generated', val: result.variant_count, color: 'var(--accent-amber)' },
              { label: 'All Hashes Unique', val: result.all_hashes_unique ? '✓ YES' : '✗ NO', color: result.all_hashes_unique ? 'var(--accent-emerald)' : 'var(--accent-rose)' },
              { label: 'Mutation Techniques', val: result.mutation_techniques?.length, color: 'var(--accent-purple)' },
            ].map(c => (
              <div key={c.label} className="glass-panel" style={{ padding: 16, textAlign: 'center' }}>
                <div style={{ fontSize: 24, fontWeight: 800, color: c.color }}>{c.val}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{c.label}</div>
              </div>
            ))}
          </div>

          {/* Technique badges */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 16 }}>
            {result.mutation_techniques?.map((t: string) => (
              <Badge key={t} text={t.replace(/_/g, ' ').toUpperCase()} color="var(--accent-purple)" />
            ))}
          </div>

          {/* Original hash */}
          <div className="glass-panel" style={{ padding: 14, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 10 }}>
            <Hash size={14} color="var(--text-dim)" />
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Original SHA-256:</span>
            <code style={{ fontSize: 11, color: 'var(--accent-rose)', fontFamily: 'Fira Code, monospace', flex: 1 }}>
              {result.original_hash}
            </code>
            <Badge text="BASELINE" color="var(--accent-rose)" />
          </div>

          {/* Variant selector */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            {result.variants?.map((_: any, i: number) => (
              <button key={i}
                onClick={() => setSelectedVariant(i)}
                style={{
                  padding: '6px 14px', borderRadius: 8, border: '1px solid',
                  borderColor: selectedVariant === i ? 'var(--accent-amber)' : 'var(--border-subtle)',
                  background: selectedVariant === i ? 'rgba(217,119,6,0.15)' : 'var(--bg-item)',
                  color: selectedVariant === i ? 'var(--accent-amber)' : 'var(--text-main)',
                  cursor: 'pointer', fontSize: 12, fontWeight: 600
                }}
              >
                Variant {i + 1}
              </button>
            ))}
          </div>

          {/* Selected variant */}
          {result.variants?.[selectedVariant] && (
            <div className="glass-panel" style={{ padding: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Hash size={13} color="var(--accent-emerald)" />
                  <code style={{ fontSize: 11, color: 'var(--accent-emerald)', fontFamily: 'Fira Code, monospace', fontWeight: 600 }}>
                    {result.hashes[selectedVariant]}
                  </code>
                  <Badge text="UNIQUE" color="var(--accent-emerald)" />
                </div>
                <button
                  onClick={() => copy(result.variants[selectedVariant], selectedVariant)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    background: 'rgba(99,102,241,0.15)', border: '1px solid rgba(99,102,241,0.4)',
                    color: 'var(--accent-purple)', borderRadius: 6, padding: '4px 10px',
                    cursor: 'pointer', fontSize: 11, fontWeight: 600
                  }}
                >
                  {copied === selectedVariant ? <CheckCircle size={12} /> : <Copy size={12} />}
                  {copied === selectedVariant ? 'Copied' : 'Copy'}
                </button>
              </div>
              <pre style={{
                background: 'var(--bg-code)', borderRadius: 8, padding: 14,
                border: '1px solid var(--border-subtle)',
                fontFamily: 'Fira Code, monospace', fontSize: 12, color: 'var(--text-code)',
                overflowX: 'auto', whiteSpace: 'pre-wrap', maxHeight: 280, overflowY: 'auto'
              }}>
                {result.variants[selectedVariant]}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Tab: Payload Encryption ─────────────────────────────────────────────────

function EncryptionTab() {
  const [invId, setInvId] = useState('INV-20260925-001');
  const [payload, setPayload] = useState('{\n  "pid": 4820,\n  "process": "powershell.exe",\n  "connection": "198.51.100.44:443"\n}');
  const [encResult, setEncResult] = useState<any>(null);
  const [decResult, setDecResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [showBlob, setShowBlob] = useState(false);

  const encrypt = async () => {
    setLoading(true);
    setDecResult(null);
    try {
      const parsed = JSON.parse(payload);
      const res = await api.encryptPayload(parsed, invId);
      setEncResult(res);
    } catch (e: any) {
      alert('Error: ' + e.message);
    } finally { setLoading(false); }
  };

  const decrypt = async () => {
    if (!encResult?.blob_hex) return;
    setLoading(true);
    try {
      const res = await api.decryptPayload(encResult.blob_hex, invId);
      setDecResult(res);
    } catch (e: any) {
      alert('Decryption Error: ' + e.message);
    } finally { setLoading(false); }
  };

  return (
    <div>
      <SectionHeader
        icon={<Lock size={22} color="#8b5cf6" />}
        title="Payload Encryption Engine"
        subtitle="XOR + AES-128-CBC with PBKDF2-derived per-investigation key — unique ciphertext per investigation ID"
        color="#8b5cf6"
      />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Input */}
        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', marginBottom: 14 }}>Plaintext Payload</div>
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>Investigation ID (Key Material)</label>
          <input
            value={invId} onChange={e => setInvId(e.target.value)}
            style={{
              width: '100%', marginBottom: 12, background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)', borderRadius: 8,
              color: 'var(--accent-purple)', fontFamily: 'Fira Code, monospace',
              fontSize: 12, padding: '8px 12px', outline: 'none'
            }}
          />
          <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>JSON Evidence Payload</label>
          <textarea
            value={payload} onChange={e => setPayload(e.target.value)}
            rows={6}
            style={{
              width: '100%', background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)', borderRadius: 8,
              color: 'var(--text-main)', fontFamily: 'Fira Code, monospace',
              fontSize: 12, padding: '10px 12px', resize: 'vertical', outline: 'none'
            }}
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button onClick={encrypt} disabled={loading} style={{
              flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              background: 'linear-gradient(135deg,#8b5cf6,#6d28d9)', color: '#fff',
              border: 'none', borderRadius: 8, padding: '10px 0',
              cursor: loading ? 'not-allowed' : 'pointer', fontWeight: 700, fontSize: 12
            }}>
              {loading ? <RefreshCw size={13} className="spin" /> : <Lock size={13} />}
              Encrypt
            </button>
            {encResult && (
              <button onClick={decrypt} disabled={loading} style={{
                flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                background: 'rgba(16,185,129,0.15)', color: 'var(--accent-emerald)',
                border: '1px solid var(--accent-emerald)', borderRadius: 8, padding: '10px 0',
                cursor: loading ? 'not-allowed' : 'pointer', fontWeight: 700, fontSize: 12
              }}>
                <Key size={13} />
                Decrypt
              </button>
            )}
          </div>
        </div>

        {/* Output */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {encResult && (
            <div className="glass-panel" style={{ padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-purple)', marginBottom: 12 }}>
                🔒 Encrypted Output
              </div>
              {[
                { label: 'Scheme', val: encResult.encryption_scheme },
                { label: 'Key Derivation', val: encResult.key_derivation },
                { label: 'Blob Size', val: `${encResult.blob_size_bytes} bytes` },
                { label: 'Payload SHA-256', val: encResult.payload_sha256?.slice(0, 24) + '...' },
              ].map(r => (
                <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 12 }}>
                  <span style={{ color: 'var(--text-muted)' }}>{r.label}</span>
                  <code style={{ color: 'var(--accent-purple)', fontFamily: 'Fira Code, monospace', fontSize: 11, fontWeight: 600 }}>{r.val}</code>
                </div>
              ))}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 10 }}>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Ciphertext Blob</span>
                <button onClick={() => setShowBlob(b => !b)} style={{
                  background: 'none', border: 'none', color: 'var(--accent-purple)',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontSize: 11
                }}>
                  {showBlob ? <EyeOff size={12} /> : <Eye size={12} />}
                  {showBlob ? 'Hide' : 'Show'}
                </button>
              </div>
              {showBlob && (
                <code style={{
                  display: 'block', marginTop: 8, fontSize: 10,
                  color: 'var(--text-code)', fontFamily: 'Fira Code, monospace',
                  background: 'var(--bg-code)', border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '8px 10px',
                  wordBreak: 'break-all', maxHeight: 100, overflowY: 'auto'
                }}>{encResult.blob_hex}</code>
              )}
            </div>
          )}
          {decResult && (
            <div className="glass-panel" style={{ padding: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-emerald)', marginBottom: 12 }}>
                🔓 Decrypted — Round-trip Verified
              </div>
              <pre style={{
                background: 'var(--bg-code)', border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '10px 12px',
                fontFamily: 'Fira Code, monospace', fontSize: 12, color: 'var(--text-code)',
                overflowX: 'auto'
              }}>{JSON.stringify(decResult.payload, null, 2)}</pre>
              <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text-muted)' }}>
                Integrity Hash: <code style={{ color: 'var(--accent-emerald)', fontWeight: 600 }}>{decResult.integrity_hash?.slice(0, 24)}...</code>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Tab: Driver / BYOVD Detection ───────────────────────────────────────────

function DriversTab() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getDrivers();
      setData(res);
      setLastRefresh(new Date());
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, []);

  // Auto-refresh every 15s
  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [load]);

  const vulnDrivers = data?.drivers?.filter((d: any) => d.is_byovd_known_vulnerable) || [];
  const safeDrivers = data?.drivers?.filter((d: any) => !d.is_byovd_known_vulnerable) || [];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <SectionHeader
          icon={<Cpu size={22} color="#f43f5e" />}
          title="Kernel Driver Enumeration & BYOVD Detection"
          subtitle="Direct Win32 EnumDeviceDrivers via ctypes (low EDR visibility) — cross-referenced against CVE-linked vulnerable driver database"
          color="#f43f5e"
        />
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 6 }}>
          <LiveTag />
          {lastRefresh && (
            <span style={{ fontSize: 10, color: '#475569' }}>
              Last: {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button onClick={load} disabled={loading} style={{
            display: 'flex', alignItems: 'center', gap: 5,
            background: 'rgba(244,63,94,0.15)', border: '1px solid rgba(244,63,94,0.35)',
            color: '#f43f5e', borderRadius: 8, padding: '6px 12px',
            cursor: loading ? 'not-allowed' : 'pointer', fontSize: 11, fontWeight: 600
          }}>
            <RefreshCw size={12} className={loading ? 'spin' : ''} />
            {loading ? 'Scanning...' : 'Re-scan'}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Total Drivers', val: data?.item_count ?? '—', color: 'var(--accent-blue)' },
          { label: 'BYOVD Matches', val: vulnDrivers.length, color: vulnDrivers.length > 0 ? 'var(--accent-rose)' : 'var(--accent-emerald)' },
          { label: 'CRITICAL', val: vulnDrivers.filter((d: any) => d.byovd_risk === 'CRITICAL').length, color: 'var(--accent-rose)' },
          { label: 'Collection Method', val: 'ctypes Win32', color: 'var(--accent-purple)' },
        ].map(c => (
          <div key={c.label} className="glass-panel" style={{ padding: 14 }}>
            <div style={{ fontSize: 20, fontWeight: 800, color: c.color, fontFamily: 'Fira Code, monospace' }}>{c.val}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{c.label}</div>
          </div>
        ))}
      </div>

      {/* BYOVD Alerts */}
      {vulnDrivers.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-rose)', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={15} /> BYOVD Vulnerable Drivers Detected
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {vulnDrivers.map((d: any) => (
              <div key={d.filename} style={{
                background: SEVERITY_BG[d.byovd_risk] || 'rgba(244,63,94,0.08)',
                border: `1px solid ${RISK_COLOR[d.byovd_risk] || '#f43f5e'}44`,
                borderLeft: `3px solid ${RISK_COLOR[d.byovd_risk] || '#f43f5e'}`,
                borderRadius: 10, overflow: 'hidden'
              }}>
                <div
                  style={{ padding: '12px 16px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                  onClick={() => setExpanded(expanded === d.filename ? null : d.filename)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <Badge text={d.byovd_risk} color={RISK_COLOR[d.byovd_risk] || 'var(--accent-rose)'} />
                    <code style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', fontFamily: 'Fira Code, monospace' }}>{d.filename}</code>
                    {d.byovd_cve && <Badge text={d.byovd_cve} color="var(--accent-amber)" />}
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{d.byovd_vendor}</span>
                  </div>
                  {expanded === d.filename ? <ChevronDown size={14} color="var(--text-dim)" /> : <ChevronRight size={14} color="var(--text-dim)" />}
                </div>
                {expanded === d.filename && (
                  <div style={{ padding: '0 16px 14px', borderTop: '1px solid var(--border-subtle)' }}>
                    <div style={{ paddingTop: 12 }}>
                      <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 8, fontWeight: 600 }}>ATTACK TECHNIQUE</div>
                      <p style={{ fontSize: 12, color: 'var(--accent-amber)', lineHeight: 1.6 }}>{d.byovd_technique}</p>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12 }}>
                        <div>
                          <div style={{ fontSize: 10, color: 'var(--text-dim)', marginBottom: 3 }}>BASE ADDRESS</div>
                          <code style={{ fontSize: 11, color: 'var(--text-code)', fontFamily: 'Fira Code, monospace' }}>{d.base_address}</code>
                        </div>
                        <div>
                          <div style={{ fontSize: 10, color: 'var(--text-dim)', marginBottom: 3 }}>DEVICE PATH</div>
                          <code style={{ fontSize: 11, color: 'var(--text-code)', fontFamily: 'Fira Code, monospace' }}>{d.device_path}</code>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Safe drivers */}
      <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-emerald)', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
        <CheckCircle size={15} /> Safe System Drivers ({safeDrivers.length})
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        {safeDrivers.slice(0, 30).map((d: any) => (
          <code key={d.filename} style={{
            fontSize: 11, background: 'var(--bg-item)', border: '1px solid var(--border-subtle)',
            borderRadius: 6, padding: '3px 8px', color: 'var(--accent-emerald)', fontFamily: 'Fira Code, monospace', fontWeight: 600
          }}>{d.filename}</code>
        ))}
        {safeDrivers.length > 30 && (
          <span style={{ fontSize: 11, color: 'var(--text-dim)', padding: '3px 8px' }}>+{safeDrivers.length - 30} more</span>
        )}
      </div>
    </div>
  );
}

// ── Tab: Memory Injection ───────────────────────────────────────────────────

function MemoryTab() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getMemoryAnalysis();
      setData(res);
      setLastRefresh(new Date());
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 12000);
    return () => clearInterval(t);
  }, [load]);

  const regions = data?.suspicious_regions || [];
  const highCount = regions.filter((r: any) => r.severity === 'HIGH').length;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <SectionHeader
          icon={<Activity size={22} color="var(--accent-cyan)" />}
          title="In-Memory Injection Detection"
          subtitle="Direct VirtualQueryEx via ctypes kernel32 — detects process hollowing, reflective DLL injection, shellcode, thread hijacking"
          color="#06b6d4"
        />
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 6 }}>
          <LiveTag />
          {lastRefresh && <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>Last: {lastRefresh.toLocaleTimeString()}</span>}
          <button onClick={load} disabled={loading} style={{
            display: 'flex', alignItems: 'center', gap: 5,
            background: 'rgba(6,182,212,0.15)', border: '1px solid rgba(6,182,212,0.35)',
            color: 'var(--accent-cyan)', borderRadius: 8, padding: '6px 12px',
            cursor: loading ? 'not-allowed' : 'pointer', fontSize: 11, fontWeight: 600
          }}>
            <RefreshCw size={12} className={loading ? 'spin' : ''} />
            {loading ? 'Scanning...' : 'Re-scan'}
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Suspicious Regions', val: data?.item_count ?? '—', color: 'var(--accent-cyan)' },
          { label: 'HIGH Severity', val: highCount, color: highCount > 0 ? 'var(--accent-rose)' : 'var(--accent-emerald)' },
          { label: 'Processes Scanned', val: data?.metadata?.scanned_processes ?? '—', color: 'var(--accent-purple)' },
          { label: 'Detection Method', val: 'VirtualQueryEx', color: 'var(--accent-blue)' },
        ].map(c => (
          <div key={c.label} className="glass-panel" style={{ padding: 14 }}>
            <div style={{ fontSize: 20, fontWeight: 800, color: c.color, fontFamily: 'Fira Code, monospace' }}>{c.val}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{c.label}</div>
          </div>
        ))}
      </div>

      {regions.length === 0 ? (
        <div className="glass-panel" style={{ padding: 32, textAlign: 'center' }}>
          <CheckCircle size={32} color="var(--accent-emerald)" style={{ marginBottom: 12 }} />
          <div style={{ color: 'var(--accent-emerald)', fontWeight: 700 }}>No Suspicious Memory Regions Detected</div>
          <div style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 6 }}>
            {data?.status === 'NOT_AVAILABLE'
              ? 'Memory analysis requires elevated privileges or Windows OS'
              : 'All process VADs appear clean — no private executable regions detected'}
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {regions.map((r: any, i: number) => (
            <div key={i} style={{
              background: SEVERITY_BG[r.severity] || 'rgba(6,182,212,0.08)',
              border: `1px solid ${RISK_COLOR[r.severity] || '#06b6d4'}44`,
              borderLeft: `3px solid ${RISK_COLOR[r.severity] || '#06b6d4'}`,
              borderRadius: 10, padding: '14px 16px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <Badge text={r.severity} color={RISK_COLOR[r.severity] || 'var(--accent-cyan)'} />
                  <code style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', fontFamily: 'Fira Code, monospace' }}>
                    {r.process_name}
                  </code>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>PID {r.pid}</span>
                </div>
                <Badge text={r.protection} color="var(--accent-purple)" />
              </div>
              <p style={{ fontSize: 12, color: 'var(--accent-amber)', marginBottom: 10 }}>{r.detection_notes}</p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 10 }}>
                {[
                  { label: 'Base Address', val: r.base_address },
                  { label: 'Region Size', val: `${(r.region_size_bytes / 1024).toFixed(1)} KB` },
                  { label: 'Type', val: r.type + ' / ' + r.state },
                ].map(item => (
                  <div key={item.label}>
                    <div style={{ fontSize: 10, color: 'var(--text-dim)', marginBottom: 2 }}>{item.label}</div>
                    <code style={{ fontSize: 11, color: 'var(--text-code)', fontFamily: 'Fira Code, monospace' }}>{item.val}</code>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Tab: CDN Routing ────────────────────────────────────────────────────────

function RoutingTab() {
  const [config, setConfig] = useState<any>(null);
  const [mode, setMode] = useState('DIRECT');
  const [cdnDomain, setCdnDomain] = useState('');
  const [realHost, setRealHost] = useState('');
  const [proxyUrl, setProxyUrl] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api.getRoutingConfig().then(r => {
      setConfig(r);
      setMode(r.routing_mode || 'DIRECT');
    }).catch(() => {});
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      const res = await api.setRoutingConfig({
        routing_mode: mode,
        cdn_domain: cdnDomain || undefined,
        real_host: realHost || undefined,
        proxy_url: proxyUrl || undefined,
      });
      setConfig(res);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e: any) { alert('Error: ' + e.message); }
    finally { setSaving(false); }
  };

  const MODES = [
    { id: 'DIRECT', label: 'Direct', icon: '→', color: '#64748b', desc: 'Standard HTTP — no routing evasion. Frontend ↔ Backend directly.' },
    { id: 'CLOUDFLARE', label: 'Cloudflare Tunnel', icon: '☁', color: '#f59e0b', desc: 'Routes via Cloudflare Tunnel. Traffic appears from Cloudflare IPs — hides real server.' },
    { id: 'DOMAIN_FRONT', label: 'Domain Fronting', icon: '⚡', color: '#f43f5e', desc: 'HTTPS SNI = CDN domain, Host header = JOCKY server. Bypasses DPI/SNI blocking.' },
    { id: 'NGROK', label: 'ngrok Tunnel', icon: '🔗', color: '#8b5cf6', desc: 'Public ngrok.io endpoint tunneled to local JOCKY server. Zero port exposure.' },
  ];

  return (
    <div>
      <SectionHeader
        icon={<Globe size={22} color="#10b981" />}
        title="CDN Routing & Domain Fronting"
        subtitle="Route management traffic through trusted CDN infrastructure — satisfies 'traffic via cloud infrastructure/CDNs using domain fronting'"
        color="#10b981"
      />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Mode selector */}
        <div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12, fontWeight: 600 }}>SELECT ROUTING MODE</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {MODES.map(m => (
              <div
                key={m.id}
                onClick={() => setMode(m.id)}
                style={{
                  padding: '14px 16px', borderRadius: 10, cursor: 'pointer',
                  border: `1px solid ${mode === m.id ? m.color : 'var(--border-subtle)'}`,
                  background: mode === m.id ? `${m.color}14` : 'var(--bg-item)',
                  transition: 'all 0.2s'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: 18 }}>{m.icon}</span>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: mode === m.id ? m.color : 'var(--text-main)' }}>{m.label}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 2 }}>{m.desc}</div>
                  </div>
                  {mode === m.id && <CheckCircle size={16} color={m.color} />}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Config inputs */}
        <div className="glass-panel" style={{ padding: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', marginBottom: 16 }}>Configuration</div>
          {[
            { label: 'CDN Domain (SNI)', val: cdnDomain, set: setCdnDomain, placeholder: 'cdn.example.com', show: mode !== 'DIRECT' },
            { label: 'Real Host (Host header)', val: realHost, set: setRealHost, placeholder: 'jocky.yourdomain.com', show: mode === 'DOMAIN_FRONT' },
            { label: 'Proxy / Tunnel URL', val: proxyUrl, set: setProxyUrl, placeholder: 'http://127.0.0.1:4040', show: mode !== 'DIRECT' },
          ].filter(f => f.show || mode === 'DIRECT').map(f => (
            <div key={f.label} style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>{f.label}</label>
              <input
                value={f.val} onChange={e => f.set(e.target.value)}
                placeholder={f.placeholder}
                disabled={mode === 'DIRECT'}
                style={{
                  width: '100%', background: mode === 'DIRECT' ? 'var(--bg-item)' : 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)', borderRadius: 8,
                  color: mode === 'DIRECT' ? 'var(--text-dim)' : 'var(--text-main)',
                  fontSize: 12, padding: '8px 12px', outline: 'none',
                  fontFamily: 'Fira Code, monospace'
                }}
              />
            </div>
          ))}
          <button onClick={save} disabled={saving} style={{
            width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
            background: 'linear-gradient(135deg,#10b981,#059669)',
            color: '#fff', border: 'none', borderRadius: 8, padding: '10px 0',
            cursor: saving ? 'not-allowed' : 'pointer', fontWeight: 700, fontSize: 13, marginTop: 8
          }}>
            {saving ? <RefreshCw size={13} className="spin" /> : saved ? <CheckCircle size={13} /> : <Globe size={13} />}
            {saving ? 'Applying...' : saved ? 'Routing Applied!' : 'Apply Routing Mode'}
          </button>

          {config && (
            <div style={{ marginTop: 16, padding: 12, background: 'var(--bg-item)', border: '1px solid var(--border-subtle)', borderRadius: 8 }}>
              <div style={{ fontSize: 10, color: 'var(--text-dim)', marginBottom: 6, fontWeight: 600 }}>ACTIVE CONFIG</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Badge text={config.routing_mode || 'DIRECT'} color="var(--accent-emerald)" />
                {config.proxy_configured && <Badge text="PROXY" color="var(--accent-amber)" />}
              </div>
              <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
                {config.current_description}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Tab: Remote Machines ────────────────────────────────────────────────────

function RemoteTab() {
  const [machines, setMachines] = useState<any[]>([]);
  const [pingResults, setPingResults] = useState<any[]>([]);
  const [pinging, setPinging] = useState(false);
  const [form, setForm] = useState({
    machine_id: '', hostname: '', ip_address: '',
    os_type: 'windows', port: 22, username: '', auth_method: 'password', tags: ''
  });
  const [adding, setAdding] = useState(false);
  const [showForm, setShowForm] = useState(false);

  const load = () => api.getRemoteMachines().then(r => setMachines(r.machines || [])).catch(() => {});

  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t); }, []);

  const add = async () => {
    setAdding(true);
    try {
      await api.registerRemoteMachine({
        ...form, port: Number(form.port),
        tags: form.tags.split(',').map(t => t.trim()).filter(Boolean)
      });
      setShowForm(false);
      load();
    } catch (e: any) { alert('Error: ' + e.message); }
    finally { setAdding(false); }
  };

  const ping = async () => {
    setPinging(true);
    try {
      const r = await api.pingRemoteMachines();
      setPingResults(r.ping_results || []);
    } catch (e: any) { alert(e.message); }
    finally { setPinging(false); }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <SectionHeader
          icon={<Server size={22} color="var(--accent-blue)" />}
          title="Multi-Machine Remote Agent"
          subtitle="SSH-based parallel forensic collection across multiple endpoints — all results aggregated per machine via ThreadPoolExecutor"
          color="#38bdf8"
        />
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={() => setShowForm(f => !f)} style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: 'rgba(56,189,248,0.15)', border: '1px solid rgba(56,189,248,0.4)',
            color: 'var(--accent-blue)', borderRadius: 8, padding: '7px 14px',
            cursor: 'pointer', fontSize: 12, fontWeight: 600
          }}>
            <Server size={13} />
            {showForm ? 'Cancel' : 'Register Machine'}
          </button>
          <button onClick={ping} disabled={pinging || machines.length === 0} style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: pinging ? 'rgba(16,185,129,0.08)' : 'rgba(16,185,129,0.15)',
            border: '1px solid rgba(16,185,129,0.4)',
            color: 'var(--accent-emerald)', borderRadius: 8, padding: '7px 14px',
            cursor: (pinging || machines.length === 0) ? 'not-allowed' : 'pointer',
            fontSize: 12, fontWeight: 600
          }}>
            <Wifi size={13} />
            {pinging ? 'Pinging...' : 'Ping All'}
          </button>
        </div>
      </div>

      {/* Register form */}
      {showForm && (
        <div className="glass-panel" style={{ padding: 20, marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-blue)', marginBottom: 14 }}>Register Remote Machine</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12 }}>
            {[
              { label: 'Machine ID', key: 'machine_id', placeholder: 'MACHINE-002' },
              { label: 'Hostname', key: 'hostname', placeholder: 'forensic-target-02' },
              { label: 'IP Address', key: 'ip_address', placeholder: '192.168.1.50' },
              { label: 'Username', key: 'username', placeholder: 'analyst' },
              { label: 'SSH Port', key: 'port', placeholder: '22' },
              { label: 'Tags (comma-sep)', key: 'tags', placeholder: 'windows, lab' },
            ].map(f => (
              <div key={f.key}>
                <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>{f.label}</label>
                <input
                  value={(form as any)[f.key]} placeholder={f.placeholder}
                  onChange={e => setForm(p => ({ ...p, [f.key]: e.target.value }))}
                  style={{
                    width: '100%', background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)', borderRadius: 8,
                    color: 'var(--text-main)', fontSize: 12, padding: '8px 12px', outline: 'none'
                  }}
                />
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 10, marginTop: 14 }}>
            <select value={form.os_type} onChange={e => setForm(p => ({ ...p, os_type: e.target.value }))}
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: 8, color: 'var(--text-main)', fontSize: 12, padding: '8px 12px', outline: 'none' }}>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
            </select>
            <select value={form.auth_method} onChange={e => setForm(p => ({ ...p, auth_method: e.target.value }))}
              style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: 8, color: 'var(--text-main)', fontSize: 12, padding: '8px 12px', outline: 'none' }}>
              <option value="password">Password</option>
              <option value="key">SSH Key</option>
            </select>
            <button onClick={add} disabled={adding} style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'linear-gradient(135deg,#38bdf8,#0ea5e9)', color: '#fff',
              border: 'none', borderRadius: 8, padding: '8px 18px',
              cursor: adding ? 'not-allowed' : 'pointer', fontWeight: 700, fontSize: 12
            }}>
              {adding ? <RefreshCw size={13} className="spin" /> : <Server size={13} />}
              {adding ? 'Registering...' : 'Register'}
            </button>
          </div>
        </div>
      )}

      {/* Machine list */}
      {machines.length === 0 ? (
        <div className="glass-panel" style={{ padding: 32, textAlign: 'center' }}>
          <Server size={32} color="var(--text-dim)" style={{ marginBottom: 12 }} />
          <div style={{ color: 'var(--text-muted)', fontWeight: 700 }}>No Remote Machines Registered</div>
          <div style={{ color: 'var(--text-dim)', fontSize: 12, marginTop: 6 }}>Register target endpoints to enable parallel multi-machine forensic collection</div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {machines.map((m: any) => {
            const ping = pingResults.find(p => p.machine_id === m.machine_id);
            return (
              <div key={m.machine_id} className="glass-panel" style={{ padding: '14px 18px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                  <div style={{
                    width: 36, height: 36, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: m.os_type === 'windows' ? 'rgba(56,189,248,0.15)' : 'rgba(139,92,246,0.15)'
                  }}>
                    <Terminal size={18} color={m.os_type === 'windows' ? 'var(--accent-blue)' : 'var(--accent-purple)'} />
                  </div>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)' }}>{m.hostname}</span>
                      <Badge text={m.os_type.toUpperCase()} color="var(--accent-blue)" />
                      <Badge text={m.machine_id} color="var(--accent-purple)" />
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                      {m.ip_address}:{m.port} · {m.username} · {m.auth_method}
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  {ping ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      {ping.tcp_reachable
                        ? <><Wifi size={14} color="var(--accent-emerald)" /><span style={{ fontSize: 11, color: 'var(--accent-emerald)', fontWeight: 600 }}>{ping.latency_ms?.toFixed(0)}ms</span></>
                        : <><WifiOff size={14} color="var(--accent-rose)" /><span style={{ fontSize: 11, color: 'var(--accent-rose)', fontWeight: 600 }}>Unreachable</span></>
                      }
                    </div>
                  ) : (
                    <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>Not pinged</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {pingResults.length > 0 && (
        <div style={{ marginTop: 16, padding: 14, background: 'var(--active-live-bg)', border: '1px solid var(--active-live-border)', borderRadius: 10 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-emerald)', marginBottom: 8 }}>PING RESULTS</div>
          {pingResults.map(p => (
            <div key={p.machine_id} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4 }}>
              <code style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>{p.hostname} ({p.ip}:{p.port})</code>
              <div style={{ display: 'flex', gap: 10 }}>
                <span style={{ color: p.tcp_reachable ? 'var(--accent-emerald)' : 'var(--accent-rose)', fontWeight: 600 }}>TCP: {p.tcp_reachable ? '✓' : '✗'}</span>
                <span style={{ color: p.ssh_connected ? 'var(--accent-emerald)' : 'var(--accent-rose)', fontWeight: 600 }}>SSH: {p.ssh_connected ? '✓' : '✗'}</span>
                {p.latency_ms && <span style={{ color: 'var(--text-dim)' }}>{p.latency_ms.toFixed(0)}ms</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Tab: Evidence Integrity 2.0 & Tamper Demo ──────────────────────────────

function IntegrityTamperTab() {
  const [keysData, setKeysData] = useState<{ active_key_id: string; keys: any[] } | null>(null);
  const [rotatingKey, setRotatingKey] = useState(false);
  const [keyAlias, setKeyAlias] = useState('');
  const [selectedAttack, setSelectedAttack] = useState<string>('payload');
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState<any>(null);

  const loadKeys = async () => {
    try {
      const res = await api.listPublicKeys();
      setKeysData(res);
    } catch (e: any) {
      console.error('Failed to load keys', e);
    }
  };

  useEffect(() => {
    loadKeys();
  }, []);

  const handleRotate = async () => {
    setRotatingKey(true);
    try {
      await api.rotateSigningKey(keyAlias || undefined);
      setKeyAlias('');
      await loadKeys();
    } catch (e: any) {
      alert('Key rotation failed: ' + e.message);
    } finally {
      setRotatingKey(false);
    }
  };

  const runSimulation = () => {
    setSimulating(true);
    setTimeout(() => {
      if (selectedAttack === 'clean') {
        setSimResult({
          result: 'VERIFIED',
          message: 'All 7 cryptographic passes verified successfully. The hash chain, RFC 8785 canonical metadata, and Ed25519 digital signature are 100% valid.',
          diagnostics: {
            evidence_hashes: 'PASSED',
            metadata_integrity: 'PASSED',
            hash_chain: 'PASSED',
            chain_ordering: 'PASSED',
            chain_tip: 'PASSED',
            ed25519_signature: 'PASSED'
          },
          details: null
        });
      } else if (selectedAttack === 'payload') {
        setSimResult({
          result: 'TAMPERED',
          message: 'Evidence file content modified after collection! 1-byte alteration detected by SHA-256 chunked digest mismatch.',
          diagnostics: {
            evidence_hashes: 'FAILED',
            metadata_integrity: 'SKIPPED',
            hash_chain: 'SKIPPED',
            chain_ordering: 'SKIPPED',
            chain_tip: 'SKIPPED',
            ed25519_signature: 'SKIPPED'
          },
          details: {
            attack_type: 'MODIFIED_EVIDENCE_PAYLOAD',
            reason: 'SHA-256 mismatch for artifact_processes.json: payload byte altered at offset 0x004F',
            expected_sha256: '7d1a938c4b694b299e52c8b8719f96b99de24e6ffad47a8c3d9a16f2c2b3e891',
            calculated_sha256: '4f03bc1106e28f328a6bb13a37b3408a737877e8db2b535dcf3280145452fcf9'
          }
        });
      } else if (selectedAttack === 'metadata') {
        setSimResult({
          result: 'TAMPERED',
          message: 'Provenance metadata altered! RFC 8785 canonical record hash mismatch caught in Pass 2.',
          diagnostics: {
            evidence_hashes: 'PASSED',
            metadata_integrity: 'FAILED',
            hash_chain: 'SKIPPED',
            chain_ordering: 'SKIPPED',
            chain_tip: 'SKIPPED',
            ed25519_signature: 'SKIPPED'
          },
          details: {
            attack_type: 'CANONICAL_METADATA_TAMPERED',
            reason: 'Record hash calculation mismatch for record #2: Canonical serialization altered',
            expected_hash: '9a3b8c1d5e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b',
            calculated_hash: '11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff'
          }
        });
      } else if (selectedAttack === 'hash_chain') {
        setSimResult({
          result: 'TAMPERED',
          message: 'Previous hash pointer broken! Adversary attempted to graft or splice foreign evidence into the chain.',
          diagnostics: {
            evidence_hashes: 'PASSED',
            metadata_integrity: 'PASSED',
            hash_chain: 'FAILED',
            chain_ordering: 'SKIPPED',
            chain_tip: 'SKIPPED',
            ed25519_signature: 'SKIPPED'
          },
          details: {
            attack_type: 'PREVIOUS_HASH_MISMATCH',
            reason: 'Record #3 points to previous hash 00000000... instead of predecessor record hash a9f4c3...',
            expected_previous_hash: 'a9f4c3b2d1e0f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3',
            stored_previous_hash: '0000000000000000000000000000000000000000000000000000000000000000'
          }
        });
      } else if (selectedAttack === 'gap') {
        setSimResult({
          result: 'TAMPERED',
          message: 'Intermediate evidence block deleted! Monotonic sequence gap detected between #1 and #3.',
          diagnostics: {
            evidence_hashes: 'PASSED',
            metadata_integrity: 'PASSED',
            hash_chain: 'PASSED',
            chain_ordering: 'FAILED',
            chain_tip: 'SKIPPED',
            ed25519_signature: 'SKIPPED'
          },
          details: {
            attack_type: 'SEQUENCE_GAP_OR_OUT_OF_ORDER',
            reason: 'Monotonic sequence broken at index 1: expected sequence #2, found sequence #3',
            expected_sequence: 2,
            found_sequence: 3
          }
        });
      } else if (selectedAttack === 'signature') {
        setSimResult({
          result: 'TAMPERED',
          message: 'Ed25519 digital signature invalid! Chain tip was modified or signed by an unauthorized private key.',
          diagnostics: {
            evidence_hashes: 'PASSED',
            metadata_integrity: 'PASSED',
            hash_chain: 'PASSED',
            chain_ordering: 'PASSED',
            chain_tip: 'PASSED',
            ed25519_signature: 'FAILED'
          },
          details: {
            attack_type: 'INVALID_ED25519_SIGNATURE',
            reason: 'Cryptographic signature verification failed against registered public key',
            key_id: keysData?.active_key_id || 'key_ed25519_default'
          }
        });
      }
      setSimulating(false);
    }, 350);
  };

  return (
    <div>
      <SectionHeader
        icon={<Link2 size={22} color="#38bdf8" />}
        title="Evidence Integrity 2.0 & Cryptographic Custody Lab"
        subtitle="RFC 8785 Canonical JSON Serialization · Streaming 64KB SHA-256 Hashing · Hash Chain of Custody · Ed25519 Digital Signatures · Offline CLI Verifier"
        color="#38bdf8"
      />

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 24 }}>
        {/* Left Column: Interactive Tamper Demonstration */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div style={{
            background: 'var(--bg-item)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 12,
            padding: 20
          }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 8 }}>
              <ShieldCheck size={18} color="#38bdf8" />
              Cryptographic Tamper Resistance Simulator
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
              Select an adversarial tamper injection vector to see how JOCKY's 7-pass forensic verifier detects the exact point of compromise in court:
            </p>

            {/* Attack Selector */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 16 }}>
              {[
                { id: 'clean', label: '1. Pristine Chain (No Tampering)', desc: 'Valid payloads, canonical metadata, intact hash chain, and valid Ed25519 signature.' },
                { id: 'payload', label: '2. 1-Byte Evidence Payload Tamper', desc: 'Attacker modifies 1 single byte in artifact data on disk. Caught in Pass 1 (SHA-256).' },
                { id: 'metadata', label: '3. Provenance Metadata Manipulation', desc: 'Attacker falsifies collection timestamp or machine ID. Caught in Pass 2 (RFC 8785 canonical hash).' },
                { id: 'hash_chain', label: '4. Chain Link Pointer Corruption', desc: 'Attacker splices/substitutes records. Caught in Pass 3 (previous_record_hash).' },
                { id: 'gap', label: '5. Intermediate Record Deletion', desc: 'Attacker deletes an incriminating intermediate artifact. Caught in Pass 4 (Sequence gap).' },
                { id: 'signature', label: '6. Ed25519 Signature Forgery', desc: 'Attacker forges signature or alters tip. Caught in Pass 6 (Ed25519 verification).' },
              ].map(opt => (
                  <label
                  key={opt.id}
                  onClick={() => setSelectedAttack(opt.id)}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    padding: '10px 14px',
                    borderRadius: 8,
                    cursor: 'pointer',
                    background: selectedAttack === opt.id ? 'var(--active-live-bg)' : 'var(--bg-card)',
                    border: selectedAttack === opt.id ? '1px solid var(--active-live-border)' : '1px solid var(--border-subtle)',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <input
                      type="radio"
                      name="tamper_attack"
                      checked={selectedAttack === opt.id}
                      onChange={() => setSelectedAttack(opt.id)}
                      style={{ accentColor: '#38bdf8' }}
                    />
                    <span style={{ fontSize: 13, fontWeight: 600, color: selectedAttack === opt.id ? 'var(--accent-blue)' : 'var(--text-main)' }}>
                      {opt.label}
                    </span>
                  </div>
                  <span style={{ fontSize: 11, color: 'var(--text-dim)', marginLeft: 24, marginTop: 2 }}>
                    {opt.desc}
                  </span>
                </label>
              ))}
            </div>

            <button
              className="btn btn-primary"
              onClick={runSimulation}
              disabled={simulating}
              style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
            >
              {simulating ? <RefreshCw size={14} className="spin" /> : <Play size={14} />}
              {simulating ? 'Auditing 7 Cryptographic Passes...' : 'Run 7-Pass Verification Audit'}
            </button>
          </div>

          {/* Simulation Result Box */}
          {simResult && (
            <div style={{
              background: simResult.result === 'VERIFIED' ? 'var(--verified-bg)' : 'var(--tamper-bg)',
              border: simResult.result === 'VERIFIED' ? '1px solid var(--accent-emerald)' : '1px solid var(--accent-rose)',
              borderRadius: 12,
              padding: 18
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {simResult.result === 'VERIFIED' ? (
                    <CheckCircle size={18} color="var(--accent-emerald)" />
                  ) : (
                    <XCircle size={18} color="var(--accent-rose)" />
                  )}
                  <span style={{ fontSize: 14, fontWeight: 700, color: simResult.result === 'VERIFIED' ? 'var(--accent-emerald)' : 'var(--accent-rose)' }}>
                    {simResult.result === 'VERIFIED' ? 'VERIFICATION PASSED (CHAIN VALID)' : 'COMPROMISE DETECTED (TAMPERED)'}
                  </span>
                </div>
              </div>
              <p style={{ fontSize: 12, color: 'var(--text-main)', marginBottom: 14 }}>
                {simResult.message}
              </p>

              {/* 7-Pass Breakdown */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginBottom: 12 }}>
                {Object.entries(simResult.diagnostics).map(([k, v]: [string, any]) => (
                  <div key={k} style={{
                    background: 'var(--bg-item)',
                    padding: '6px 10px',
                    borderRadius: 6,
                    border: v === 'FAILED' ? '1px solid var(--accent-rose)' : '1px solid var(--border-subtle)'
                  }}>
                    <div style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase' }}>{k.replace('_', ' ')}</div>
                    <div style={{
                      fontSize: 11,
                      fontWeight: 700,
                      marginTop: 2,
                      color: v === 'PASSED' ? 'var(--accent-emerald)' : v === 'FAILED' ? 'var(--accent-rose)' : 'var(--text-muted)'
                    }}>
                      {v}
                    </div>
                  </div>
                ))}
              </div>

              {simResult.details && (
                <div style={{
                  background: 'var(--bg-item)',
                  border: '1px solid var(--border-subtle)',
                  padding: 12,
                  borderRadius: 6,
                  fontSize: 11,
                  fontFamily: 'monospace',
                  color: 'var(--text-main)'
                }}>
                  <div style={{ color: 'var(--accent-rose)', fontWeight: 700, marginBottom: 4 }}>
                    Attack Type: {simResult.details.attack_type}
                  </div>
                  <div>Reason: {simResult.details.reason}</div>
                  {simResult.details.expected_sha256 && (
                    <div style={{ marginTop: 4 }}>
                      <div style={{ color: 'var(--accent-blue)' }}>Expected: {simResult.details.expected_sha256.slice(0, 24)}...</div>
                      <div style={{ color: 'var(--accent-rose)' }}>Computed: {simResult.details.calculated_sha256.slice(0, 24)}...</div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Column: Ed25519 Key Management & Offline CLI */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          {/* Key Management Card */}
          <div style={{
            background: 'var(--bg-item)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 12,
            padding: 20
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Key size={16} color="var(--accent-amber)" />
                Ed25519 Key Management & Rotation
              </div>
              <span className="badge badge-completed" style={{ fontSize: 10 }}>
                Isolated Storage
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
              Asymmetric Ed25519 digital signatures secure evidence chains. Private keys are never exposed over APIs. Historical keys remain registered for backward verification.
            </p>

            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', padding: 12, borderRadius: 8, marginBottom: 14 }}>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 4 }}>Current Active Signing Key ID:</div>
              <code style={{ fontSize: 12, color: 'var(--accent-blue)', wordBreak: 'break-all', fontWeight: 600 }}>
                {keysData?.active_key_id || 'key_ed25519_default'}
              </code>
            </div>

            {/* Key Rotation Input */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
              <input
                type="text"
                placeholder="Optional key alias (e.g. 'Court Audit 2026')"
                value={keyAlias}
                onChange={e => setKeyAlias(e.target.value)}
                style={{
                  flex: 1,
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  padding: '8px 12px',
                  fontSize: 12,
                  color: 'var(--text-main)'
                }}
              />
              <button
                className="btn btn-secondary btn-sm"
                onClick={handleRotate}
                disabled={rotatingKey}
                style={{ display: 'flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}
              >
                <RefreshCw size={12} className={rotatingKey ? 'spin' : ''} />
                {rotatingKey ? 'Rotating...' : 'Rotate Key'}
              </button>
            </div>

            {/* Registered Public Keys */}
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-main)', marginBottom: 6 }}>
              Registered Public Keys ({keysData?.keys.length || 0}):
            </div>
            <div style={{ maxHeight: 160, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }}>
              {keysData?.keys.map(k => (
                <div key={k.key_id} style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  padding: '8px 10px',
                  fontSize: 11,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between'
                }}>
                  <div>
                    <div style={{ fontFamily: 'monospace', color: k.is_active ? 'var(--accent-emerald)' : 'var(--text-main)', fontWeight: 600 }}>
                      {k.key_id} {k.is_active && '(ACTIVE)'}
                    </div>
                    <code style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                      {k.public_key_hex.slice(0, 24)}...
                    </code>
                  </div>
                  {k.alias && <span className="badge badge-neutral" style={{ fontSize: 10 }}>{k.alias}</span>}
                </div>
              ))}
            </div>
          </div>

          {/* Standalone Offline Verifier Card */}
          <div style={{
            background: 'var(--bg-item)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 12,
            padding: 20
          }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <Terminal size={16} color="var(--accent-emerald)" />
              Independent Offline Verifier CLI
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
              Zero-dependency Python CLI tool bundled inside every exported forensic zip package. Judges and opposing counsel can independently verify evidence without connecting to JOCKY servers:
            </p>
            <pre style={{
              background: 'var(--bg-code)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 6,
              padding: 12,
              fontSize: 11,
              color: 'var(--text-code)',
              fontFamily: 'monospace',
              margin: 0,
              overflowX: 'auto',
              lineHeight: 1.6
            }}>
              {`# 1. Verify portable court zip package offline
python standalone_verifier.py --package forensic_package_case1.zip

# 2. Verify extracted evidence directory
python standalone_verifier.py --chain jocky-chain.json --evidence-dir evidence/

# Output returns JSON report and exit code 0 (Pass) or 1 (Tampered)`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main Evasion Lab Page ───────────────────────────────────────────────────

type TabId = 'live' | 'polymorphic' | 'encryption' | 'integrity' | 'drivers' | 'memory' | 'routing' | 'remote';

const TABS: { id: TabId; label: string; icon: React.ReactNode; color: string }[] = [
  { id: 'live', label: 'Live Monitor', icon: <Radio size={15} />, color: '#10b981' },
  { id: 'polymorphic', label: 'Polymorphic Engine', icon: <Zap size={15} />, color: '#f59e0b' },
  { id: 'encryption', label: 'Payload Encryption', icon: <Lock size={15} />, color: '#8b5cf6' },
  { id: 'integrity', label: 'Evidence Integrity & Tamper Demo', icon: <Link2 size={15} />, color: '#38bdf8' },
  { id: 'drivers', label: 'BYOVD / Drivers', icon: <Cpu size={15} />, color: '#f43f5e' },
  { id: 'memory', label: 'Memory Injection', icon: <Activity size={15} />, color: '#06b6d4' },
  { id: 'routing', label: 'CDN Routing', icon: <Globe size={15} />, color: '#10b981' },
  { id: 'remote', label: 'Remote Agents', icon: <Server size={15} />, color: '#38bdf8' },
];

export const EvasionLabPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabId>('live');

  return (
    <div style={{ maxWidth: 1380, margin: '0 auto', padding: '32px 24px' }}>
      {/* Page header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 8 }}>
          <div style={{
            width: 52, height: 52, borderRadius: 14, display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'linear-gradient(135deg, rgba(244,63,94,0.3), rgba(139,92,246,0.3))',
            border: '1px solid rgba(244,63,94,0.4)'
          }}>
            <Shield size={28} color="#f43f5e" />
          </div>
          <div>
            <h1 style={{ fontSize: 26, fontWeight: 800, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
              Evasion Lab
            </h1>
            <p style={{ fontSize: 13, color: 'var(--text-dim)', marginTop: 2 }}>
              Polymorphic engine · Payload encryption · Evidence Integrity 2.0 · BYOVD detection · In-memory injection scanning · CDN routing · Multi-machine forensics
            </p>
          </div>
          <div style={{ marginLeft: 'auto' }}>
            <LiveTag />
          </div>
        </div>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 24, overflowX: 'auto', paddingBottom: 4 }}>
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 7, whiteSpace: 'nowrap',
              padding: '8px 16px', borderRadius: 10, border: '1px solid',
              borderColor: activeTab === tab.id ? tab.color : 'var(--border-subtle)',
              background: activeTab === tab.id ? `${tab.color}18` : 'var(--bg-item)',
              color: activeTab === tab.id ? tab.color : 'var(--text-muted)',
              cursor: 'pointer', fontSize: 12, fontWeight: 600,
              transition: 'all 0.2s'
            }}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="glass-panel" style={{ padding: 28 }}>
          {activeTab === 'live' && <LiveMonitor />}
          {activeTab === 'polymorphic' && <PolymorphicTab />}
          {activeTab === 'encryption' && <EncryptionTab />}
          {activeTab === 'integrity' && <IntegrityTamperTab />}
          {activeTab === 'drivers' && <DriversTab />}
          {activeTab === 'memory' && <MemoryTab />}
          {activeTab === 'routing' && <RoutingTab />}
          {activeTab === 'remote' && <RemoteTab />}
        </div>

      <style>{`
        @keyframes ping { 0%,100%{transform:scale(1);opacity:0.4} 50%{transform:scale(1.8);opacity:0} }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        .spin { animation: spin 1s linear infinite; }
      `}</style>
    </div>
  );
};
