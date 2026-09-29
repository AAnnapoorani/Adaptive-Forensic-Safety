import React, { useState } from 'react';
import type { ProvenanceRecord } from '../types';
import { 
  ShieldCheck, 
  Copy, 
  Check, 
  Link2, 
  Key, 
  FileCode, 
  ArrowRight, 
  Info, 
  X,
  Lock
} from 'lucide-react';

interface ProvenanceTableProps {
  records: ProvenanceRecord[];
}

export const ProvenanceTable: React.FC<ProvenanceTableProps> = ({ records }) => {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<ProvenanceRecord | null>(null);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const hasChain = records.some(r => r.record_hash);

  return (
    <div className="glass-panel" style={{ padding: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div>
          <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldCheck size={18} color="#10b981" />
            Immutable Forensic Provenance Ledger — Integrity 2.0
          </h3>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
            Cryptographically sealed audit trail proving the origin, round, investigator rationale, RFC 8785 canonical manifest, SHA-256 hash chain, and Ed25519 digital signature.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {hasChain ? (
            <span className="badge badge-completed" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <Lock size={12} />
              Hash Chain Active (Ed25519)
            </span>
          ) : (
            <span className="badge badge-warning" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <Info size={12} />
              Legacy Format
            </span>
          )}
          <div className="badge badge-in-progress">
            {records.length} Records
          </div>
        </div>
      </div>

      {/* Visual Hash-Chain Flow Bar if chain is present */}
      {hasChain && records.length > 0 && (
        <div style={{
          background: 'var(--bg-item)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 8,
          padding: '12px 16px',
          marginBottom: 16,
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          overflowX: 'auto'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
            <span style={{
              background: 'linear-gradient(135deg, #0284c7, #2563eb)',
              color: '#fff',
              fontSize: 10,
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: 4,
              letterSpacing: '0.05em'
            }}>
              GENESIS
            </span>
            <code style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }} title="254e580515def211ef9e9aab16afbb94485cde23739d204b2d975d534c5a1ba6">
              254e58...
            </code>
          </div>

          {records.map((r, i) => (
            <React.Fragment key={r.id || i}>
              <ArrowRight size={14} color="var(--text-dim)" style={{ flexShrink: 0 }} />
              <div 
                onClick={() => setSelectedRecord(r)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  padding: '4px 10px',
                  cursor: 'pointer',
                  flexShrink: 0,
                  transition: 'all 0.15s ease'
                }}
                title={`Click to inspect canonical record for #${r.sequence_number || i + 1}`}
              >
                <Link2 size={12} color="var(--accent-blue)" />
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-blue)' }}>
                  #{r.sequence_number || i + 1}
                </span>
                <code style={{ fontSize: 11, color: 'var(--text-main)', fontFamily: 'monospace', fontWeight: 500 }}>
                  {r.record_hash ? `${r.record_hash.slice(0, 8)}...` : 'legacy'}
                </code>
              </div>
            </React.Fragment>
          ))}

          {records[records.length - 1]?.record_hash && (
            <>
              <ArrowRight size={14} color="#10b981" style={{ flexShrink: 0 }} />
              <div style={{
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                borderRadius: 6,
                padding: '4px 10px',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                flexShrink: 0
              }}>
                <Key size={12} color="#10b981" />
                <span style={{ fontSize: 11, fontWeight: 700, color: '#10b981' }}>TIP SEALED</span>
              </div>
            </>
          )}
        </div>
      )}

      {/* Table */}
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 60 }}>Seq</th>
              <th>Artifact ID</th>
              <th>Operation / Collector</th>
              <th>Round</th>
              <th>Collection Rationale</th>
              <th>SHA-256 Payload</th>
              <th>Hash Chain Link (Prev ➔ Record)</th>
              <th>Ed25519 Sign</th>
              <th>Inspect</th>
            </tr>
          </thead>
          <tbody>
            {records.map((rec, idx) => (
              <tr key={rec.id || idx}>
                <td>
                  <span style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: 28,
                    height: 28,
                    borderRadius: 14,
                    background: rec.record_hash ? 'rgba(2, 132, 199, 0.12)' : 'var(--bg-item)',
                    color: rec.record_hash ? 'var(--accent-blue)' : 'var(--text-muted)',
                    border: '1px solid var(--border-subtle)',
                    fontWeight: 700,
                    fontSize: 12,
                    fontFamily: 'monospace'
                  }}>
                    #{rec.sequence_number || idx + 1}
                  </span>
                </td>
                <td>
                  <span style={{ fontWeight: 600, color: 'var(--accent-blue)', fontFamily: 'monospace' }}>
                    {rec.artifact_id}
                  </span>
                </td>
                <td>
                  <div>
                    <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>{rec.operation}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>{rec.collector}</div>
                  </div>
                </td>
                <td>
                  <span className={`badge ${rec.round_number > 1 ? 'badge-warning' : 'badge-in-progress'}`}>
                    Round {rec.round_number} {rec.round_number > 1 ? '(Adaptive)' : '(Initial)'}
                  </span>
                </td>
                <td style={{ maxWidth: 220 }}>
                  <div style={{ fontSize: 12, color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={rec.reason}>
                    {rec.reason}
                  </div>
                </td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <code style={{ fontSize: 11, color: 'var(--accent-blue)', fontWeight: 500 }}>
                      {rec.sha256 ? `${rec.sha256.slice(0, 10)}...` : '—'}
                    </code>
                    {rec.sha256 && (
                      <button
                        onClick={() => copyToClipboard(rec.sha256)}
                        style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedHash === rec.sha256 ? 'var(--accent-emerald)' : 'var(--text-dim)' }}
                        title="Copy full payload SHA-256"
                      >
                        {copiedHash === rec.sha256 ? <Check size={13} /> : <Copy size={13} />}
                      </button>
                    )}
                  </div>
                </td>
                <td>
                  {rec.record_hash ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}>
                        <span style={{ color: 'var(--text-dim)' }}>Prev:</span>
                        <code style={{ color: 'var(--text-dim)', fontWeight: 500 }}>{rec.previous_record_hash ? `${rec.previous_record_hash.slice(0, 8)}...` : 'GENESIS'}</code>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}>
                        <span style={{ color: 'var(--accent-emerald)', fontWeight: 600 }}>Rec:</span>
                        <code style={{ color: 'var(--accent-emerald)', fontWeight: 600 }}>{rec.record_hash.slice(0, 10)}...</code>
                        <button
                          onClick={() => copyToClipboard(rec.record_hash!)}
                          style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedHash === rec.record_hash ? 'var(--accent-emerald)' : 'var(--text-dim)' }}
                          title="Copy full record hash"
                        >
                          {copiedHash === rec.record_hash ? <Check size={12} /> : <Copy size={12} />}
                        </button>
                      </div>
                    </div>
                  ) : (
                    <span style={{ fontSize: 11, color: 'var(--text-dim)', fontStyle: 'italic' }}>
                      Legacy Unchained
                    </span>
                  )}
                </td>
                <td>
                  {rec.signature ? (
                    <span 
                      className="badge badge-completed" 
                      style={{ fontSize: 10, display: 'inline-flex', alignItems: 'center', gap: 4 }}
                      title={`Ed25519 Signed with Key: ${rec.key_id || 'unknown'}`}
                    >
                      <Key size={10} />
                      Ed25519
                    </span>
                  ) : rec.record_hash ? (
                    <span className="badge badge-in-progress" style={{ fontSize: 10 }}>
                      Chained
                    </span>
                  ) : (
                    <span className="badge badge-warning" style={{ fontSize: 10 }}>
                      Legacy
                    </span>
                  )}
                </td>
                <td>
                  <button
                    onClick={() => setSelectedRecord(rec)}
                    className="btn btn-secondary btn-sm"
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                      padding: '4px 8px',
                      fontSize: 11
                    }}
                    title="Inspect RFC 8785 Canonical Record"
                  >
                    <FileCode size={12} />
                    Inspect
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Canonical Record Inspector Modal */}
      {selectedRecord && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: 20
        }}>
          <div className="glass-panel" style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 12,
            width: '100%',
            maxWidth: 680,
            maxHeight: '85vh',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            boxShadow: 'var(--shadow-card-hover)'
          }}>
            {/* Modal Header */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '16px 20px',
              borderBottom: '1px solid var(--border-subtle)',
              background: 'var(--bg-item)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <FileCode size={20} color="var(--accent-blue)" />
                <div>
                  <h4 style={{ margin: 0, fontSize: 15, color: 'var(--text-main)', fontWeight: 700 }}>
                    RFC 8785 Canonical Record #{selectedRecord.sequence_number || 1}
                  </h4>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    Artifact: {selectedRecord.artifact_id}
                  </span>
                </div>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: 4
                }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: 20, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div style={{ background: 'var(--bg-item)', padding: 10, borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>Record Hash</div>
                  <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--accent-emerald)', wordBreak: 'break-all', marginTop: 4, fontWeight: 600 }}>
                    {selectedRecord.record_hash || 'Legacy / Unhashed'}
                  </div>
                </div>
                <div style={{ background: 'var(--bg-item)', padding: 10, borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>Previous Record Hash</div>
                  <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--accent-blue)', wordBreak: 'break-all', marginTop: 4, fontWeight: 600 }}>
                    {selectedRecord.previous_record_hash || 'None (Genesis or Legacy)'}
                  </div>
                </div>
              </div>

              {selectedRecord.signature && (
                <div style={{ background: 'var(--bg-item)', padding: 10, borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                    Ed25519 Signature (Key ID: {selectedRecord.key_id || 'unknown'})
                  </div>
                  <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--accent-amber)', wordBreak: 'break-all', marginTop: 4, fontWeight: 600 }}>
                    {selectedRecord.signature}
                  </div>
                </div>
              )}

              <div>
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-main)', marginBottom: 6 }}>
                  Canonical JSON Payload (RFC 8785 Normalized):
                </div>
                <pre style={{
                  background: 'var(--bg-code)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  padding: 12,
                  fontSize: 12,
                  color: 'var(--text-main)',
                  fontFamily: 'monospace',
                  overflowX: 'auto',
                  margin: 0,
                  maxHeight: 260
                }}>
                  {JSON.stringify(
                    selectedRecord.canonical_record || {
                      sequence_number: selectedRecord.sequence_number,
                      artifact_id: selectedRecord.artifact_id,
                      sha256: selectedRecord.sha256,
                      operation: selectedRecord.operation,
                      collector: selectedRecord.collector,
                      round_number: selectedRecord.round_number,
                      reason: selectedRecord.reason,
                      machine_id: selectedRecord.machine_id,
                      recorded_at: selectedRecord.recorded_at,
                      previous_record_hash: selectedRecord.previous_record_hash
                    },
                    null,
                    2
                  )}
                </pre>
              </div>
            </div>

            {/* Modal Footer */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'flex-end',
              padding: '12px 20px',
              borderTop: '1px solid var(--border-subtle)',
              background: 'var(--bg-item)'
            }}>
              <button
                onClick={() => setSelectedRecord(null)}
                className="btn btn-secondary"
                style={{ fontSize: 12, padding: '6px 14px' }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
