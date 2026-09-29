import React, { useState } from 'react';
import type { EvidenceArtifact } from '../types';
import { api } from '../services/api';
import { FileJson, CheckCircle, AlertTriangle, ShieldCheck, Eye, Copy, Check } from 'lucide-react';

interface ArtifactsTableProps {
  artifacts: EvidenceArtifact[];
  investigationId: string;
  onRefresh: () => void;
}

export const ArtifactsTable: React.FC<ArtifactsTableProps> = ({ artifacts, investigationId, onRefresh }) => {
  const [selectedRawArtifact, setSelectedRawArtifact] = useState<{ id: string; name: string; data: any } | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const handleVerifyAll = async () => {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await api.verifyEvidence(investigationId);
      if (res.all_valid) {
        setVerifyResult(`All ${res.total_artifacts} artifacts verified: Cryptographic SHA-256 signatures match.`);
      } else {
        setVerifyResult(`Warning: Integrity mismatch detected (${res.valid_count}/${res.total_artifacts} valid).`);
      }
      onRefresh();
    } catch (err: any) {
      setVerifyResult(`Verification failed: ${err.message}`);
    } finally {
      setVerifying(false);
    }
  };

  const handleInspectRaw = async (artifact: EvidenceArtifact) => {
    try {
      const data = await api.getRawArtifact(artifact.id);
      setSelectedRawArtifact({ id: artifact.id, name: artifact.name, data });
    } catch (err: any) {
      alert(`Could not load raw artifact: ${err.message}`);
    }
  };

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Action Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <FileJson size={18} color="var(--accent-blue)" />
            Stored Forensic Evidence Artifacts
          </h3>
          <span className="badge badge-neutral">{artifacts.length} files</span>
        </div>

        <button
          className="btn btn-emerald btn-sm"
          onClick={handleVerifyAll}
          disabled={verifying}
        >
          <ShieldCheck size={14} />
          {verifying ? 'Re-Computing Cryptographic Hashes...' : 'Verify Cryptographic Signatures (SHA-256)'}
        </button>
      </div>

      {verifyResult && (
        <div style={{
          padding: '10px 16px',
          borderRadius: 6,
          fontSize: 13,
          fontWeight: 600,
          background: verifyResult.includes('All') ? 'rgba(16, 185, 129, 0.12)' : 'rgba(244, 63, 94, 0.12)',
          border: verifyResult.includes('All') ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid rgba(244, 63, 94, 0.4)',
          color: verifyResult.includes('All') ? 'var(--accent-emerald)' : 'var(--accent-rose)',
          display: 'flex',
          alignItems: 'center',
          gap: 8
        }}>
          {verifyResult.includes('All') ? <CheckCircle size={16} /> : <AlertTriangle size={16} />}
          <span>{verifyResult}</span>
        </div>
      )}

      {/* Artifacts Table */}
      <div className="glass-panel" style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Artifact ID</th>
              <th>File Name</th>
              <th>Operation</th>
              <th>Round</th>
              <th>Size</th>
              <th>Cryptographic Hash (SHA-256)</th>
              <th>Integrity</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {artifacts.map(a => (
              <tr key={a.id}>
                <td>
                  <span style={{ fontWeight: 600, color: 'var(--accent-blue)', fontFamily: 'monospace' }}>
                    {a.id}
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <FileJson size={15} color="var(--accent-blue)" />
                    {a.is_synthetic ? (
                      <span className="badge badge-warning" style={{ fontSize: 9 }}>SYNTHETIC</span>
                    ) : (
                      <span className="badge badge-valid" style={{ fontSize: 9 }}>LIVE HOST</span>
                    )}
                  </div>
                </td>
                <td>
                  <span className="badge badge-neutral">{a.operation}</span>
                </td>
                <td>
                  <span className={`badge ${a.round_number > 1 ? 'badge-warning' : 'badge-in-progress'}`}>
                    Round {a.round_number}
                  </span>
                </td>
                <td>
                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    {(a.file_size_bytes / 1024).toFixed(1)} KB
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <code style={{ fontSize: 11, color: 'var(--accent-blue)', fontWeight: 500 }}>{a.sha256.slice(0, 16)}...</code>
                    <button
                      onClick={() => copyHash(a.sha256)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedHash === a.sha256 ? 'var(--accent-emerald)' : 'var(--text-dim)' }}
                      title="Copy full SHA-256"
                    >
                      {copiedHash === a.sha256 ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                  </div>
                </td>
                <td>
                  <span className={`badge ${a.integrity_status === 'VALID' ? 'badge-completed' : 'badge-failed'}`}>
                    {a.integrity_status}
                  </span>
                </td>
                <td>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => handleInspectRaw(a)}
                  >
                    <Eye size={12} /> Inspect
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Raw JSON Modal */}
      {selectedRawArtifact && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100,
          padding: 24
        }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: 800, maxHeight: '85vh', display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'var(--bg-item)' }}>
              <div>
                <h4 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)' }}>{selectedRawArtifact.name}</h4>
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Artifact ID: {selectedRawArtifact.id}</div>
              </div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setSelectedRawArtifact(null)}
              >
                Close
              </button>
            </div>

            <div style={{ padding: 20, overflowY: 'auto', flex: 1 }}>
              <pre style={{
                background: 'var(--bg-code)',
                padding: 16,
                borderRadius: 8,
                fontSize: 12,
                color: 'var(--text-main)',
                overflowX: 'auto',
                border: '1px solid var(--border-subtle)'
              }}>
                {JSON.stringify(selectedRawArtifact.data, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
