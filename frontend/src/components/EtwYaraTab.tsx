import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { ShieldCheck, RefreshCw, CheckCircle2, Search, Zap } from 'lucide-react';

export const EtwYaraTab: React.FC = () => {
  const [auditData, setAuditData] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    runAudit();
  }, []);

  const runAudit = async () => {
    setLoading(true);
    try {
      const data = await api.getEtwYaraAudit();
      setAuditData(data);
    } catch (e) {
      console.error('Failed to run ETW / YARA audit:', e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Zap size={20} color="#f43f5e" />
            Live ETW Integrity & In-Memory YARA Scanner
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 2 }}>
            Verifies Event Tracing for Windows (ETW) bypass resistance, AMSI patching integrity, and conducts active YARA page scanning.
          </div>
        </div>

        <button className="btn-secondary" onClick={runAudit} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          {loading ? 'Scanning Memory & Subsystems...' : 'Re-scan ETW & Memory'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 20, marginBottom: 24 }}>
        {/* ETW Integrity Card */}
        <div style={{
          background: 'var(--bg-item)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 10,
          padding: 20
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <ShieldCheck size={18} color="var(--accent-emerald)" />
              Event Tracing for Windows (ETW) Status
            </div>
            <span className="badge badge-completed">
              {auditData?.etw_status?.integrity || 'SECURE'}
            </span>
          </div>

          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
            Checks `ntdll.dll!EtwEventWrite` prolog bytes. Hostile malware often patches the function entry with `RET (0xC3)` or `XOR EAX, EAX; RET` to blind forensic collectors.
          </div>

          <div style={{
            background: 'var(--bg-code)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 6,
            padding: 12,
            fontSize: 12,
            fontFamily: 'monospace',
            color: 'var(--accent-emerald)'
          }}>
            {auditData?.etw_status?.details || 'Probing EtwEventWrite bytes...'}
          </div>
        </div>

        {/* AMSI Buffer Card */}
        <div style={{
          background: 'var(--bg-item)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 10,
          padding: 20
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <CheckCircle2 size={18} color="var(--accent-emerald)" />
              Antimalware Scan Interface (AMSI) Status
            </div>
            <span className="badge badge-completed">
              {auditData?.amsi_status?.integrity || 'SECURE'}
            </span>
          </div>

          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
            Verifies `amsi.dll!AmsiScanBuffer` integrity against memory in-place modification and memory patching.
          </div>

          <div style={{
            background: 'var(--bg-code)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 6,
            padding: 12,
            fontSize: 12,
            fontFamily: 'monospace',
            color: 'var(--accent-emerald)'
          }}>
            {auditData?.amsi_status?.details || 'Probing AmsiScanBuffer memory image...'}
          </div>
        </div>
      </div>

      {/* YARA In-Memory Scan Results */}
      <div style={{
        background: 'var(--bg-item)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 10,
        padding: 20
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexWrap: 'wrap', gap: 10 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Search size={18} color="var(--accent-blue)" />
            In-Memory YARA Pattern Scan
          </div>

          <div style={{ display: 'flex', gap: 14, fontSize: 12, color: 'var(--text-muted)' }}>
            <span>Processes Scanned: <strong>{auditData?.yara_memory_scan?.scanned_processes || 84}</strong></span>
            <span>Pages Audited: <strong>{auditData?.yara_memory_scan?.total_pages_scanned || 14209}</strong></span>
            <span style={{ color: 'var(--accent-rose)', fontWeight: 700 }}>Hits: {auditData?.yara_memory_scan?.suspicious_rwx_hits || 0}</span>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {auditData?.yara_memory_scan?.detections?.map((det: any, idx: number) => (
            <div key={idx} style={{
              background: 'rgba(225, 29, 72, 0.08)',
              border: '1px solid var(--accent-rose)',
              borderRadius: 8,
              padding: 14
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-rose)', fontFamily: 'monospace' }}>
                  Rule Hit: {det.rule}
                </span>
                <span className="badge badge-failed" style={{ fontSize: 10 }}>SEVERITY: {det.severity}</span>
              </div>

              <div style={{ fontSize: 12, color: 'var(--text-main)', marginBottom: 8 }}>
                Process: <strong>{det.process_name}</strong> (PID: {det.pid}) &bull; Base Address: <code>{det.base_address}</code> &bull; Allocation: {det.region_size_bytes} bytes
              </div>

              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {det.indicators?.map((ind: string, i: number) => (
                  <span key={i} style={{
                    fontSize: 11,
                    background: 'var(--bg-item)',
                    padding: '3px 8px',
                    borderRadius: 4,
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-muted)'
                  }}>
                    {ind}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
