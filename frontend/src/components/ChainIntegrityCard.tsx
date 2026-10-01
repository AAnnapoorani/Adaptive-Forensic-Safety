import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type { ChainVerificationReport } from '../types';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Shield, 
  Key, 
  Download, 
  RefreshCw, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle,
  FileArchive,
  Info,
  ChevronDown,
  ChevronUp,
  FileText,
  ExternalLink
} from 'lucide-react';

interface ChainIntegrityCardProps {
  investigationId: string;
  isCompleted: boolean;
  onRefresh?: () => void;
}

export const ChainIntegrityCard: React.FC<ChainIntegrityCardProps> = ({
  investigationId,
  isCompleted,
  onRefresh
}) => {
  const [report, setReport] = useState<ChainVerificationReport | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [signing, setSigning] = useState<boolean>(false);
  const [showDiagnostics, setShowDiagnostics] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const runVerification = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await api.verifyChain(investigationId);
      setReport(res);
    } catch (err: any) {
      setErrorMsg(err.message || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSignTip = async () => {
    setSigning(true);
    setErrorMsg(null);
    try {
      await api.signChainTip(investigationId);
      await runVerification();
      if (onRefresh) onRefresh();
    } catch (err: any) {
      setErrorMsg(`Signing failed: ${err.message}`);
    } finally {
      setSigning(false);
    }
  };

  const handleExportZip = () => {
    const url = api.getForensicPackageUrl(investigationId);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `forensic_package_${investigationId}.zip`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  useEffect(() => {
    runVerification();
  }, [investigationId]);

  const isVerified = report?.result === 'VERIFIED';
  const isTampered = report?.result === 'TAMPERED';
  const isLegacy = report?.result === 'LEGACY_FORMAT';
  const isEmpty = report?.result === 'EMPTY';

  return (
    <div className="glass-panel" style={{
      padding: 24,
      border: isTampered 
        ? '1px solid rgba(239, 68, 68, 0.5)' 
        : isVerified 
          ? '1px solid rgba(16, 185, 129, 0.4)' 
          : '1px solid var(--border-subtle)',
      background: isTampered 
        ? 'var(--tamper-bg)' 
        : isVerified 
          ? 'var(--verified-bg)'
          : 'var(--bg-panel)'
    }}>
      {/* Top Header Row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 44,
            height: 44,
            borderRadius: 10,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: isTampered 
              ? 'rgba(239, 68, 68, 0.2)' 
              : isVerified 
                ? 'rgba(16, 185, 129, 0.2)' 
                : 'rgba(56, 189, 248, 0.15)',
            color: isTampered ? '#ef4444' : isVerified ? '#10b981' : '#38bdf8'
          }}>
            {isTampered ? (
              <ShieldAlert size={26} />
            ) : isVerified ? (
              <ShieldCheck size={26} />
            ) : (
              <Shield size={26} />
            )}
          </div>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)', margin: 0 }}>
                Forensic Chain of Custody & Integrity 2.0
              </h3>
              {isVerified && (
                <span className="badge badge-completed" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <CheckCircle2 size={12} /> CRYPTOGRAPHICALLY VERIFIED
                </span>
              )}
              {isTampered && (
                <span className="badge" style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.4)', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <AlertTriangle size={12} /> TAMPER DETECTED
                </span>
              )}
              {isLegacy && (
                <span className="badge badge-warning" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Info size={12} /> LEGACY EVIDENCE FORMAT
                </span>
              )}
              {isEmpty && (
                <span className="badge badge-neutral">NO ARTIFACTS YET</span>
              )}
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4, margin: 0 }}>
              RFC 8785 Canonical Serialization &bull; Streaming SHA-256 &bull; Cryptographic Hash Chain &bull; Ed25519 Signatures
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <button
            className="btn btn-secondary btn-sm"
            onClick={runVerification}
            disabled={loading}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
            title="Perform live 7-pass cryptographic verification"
          >
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
            {loading ? 'Verifying...' : 'Verify Chain'}
          </button>

          {isCompleted && !isTampered && (
            <button
              className="btn btn-secondary btn-sm"
              onClick={handleSignTip}
              disabled={signing || loading}
              style={{ display: 'flex', alignItems: 'center', gap: 6 }}
              title="Sign latest chain tip with active Ed25519 key"
            >
              <Key size={13} color="#f59e0b" />
              {signing ? 'Signing...' : 'Re-sign Tip'}
            </button>
          )}

          <button
            className="btn btn-secondary btn-sm"
            onClick={() => window.open(api.getCourtDossierHtmlUrl(investigationId), '_blank')}
            style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--accent-blue)', borderColor: 'var(--accent-blue)' }}
            title="Open printable Section 65B Legal Certificate"
          >
            <FileText size={13} />
            Section 65B Court Dossier
            <ExternalLink size={11} />
          </button>

          <button
            className="btn btn-primary btn-sm"
            onClick={handleExportZip}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
            title="Download self-contained offline forensic package (.zip)"
          >
            <Download size={13} />
            Export Forensic Package (.zip)
          </button>
        </div>
      </div>

      {errorMsg && (
        <div style={{ marginTop: 16, padding: '10px 14px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: 6, color: '#f87171', fontSize: 12 }}>
          {errorMsg}
        </div>
      )}

      {/* Tamper Alert Detailed Diagnostic Box */}
      {isTampered && report?.failure_details && (
        <div style={{
          marginTop: 16,
          padding: 16,
          background: 'rgba(239, 68, 68, 0.12)',
          border: '1px solid rgba(239, 68, 68, 0.4)',
          borderRadius: 8
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#ef4444', fontWeight: 700, fontSize: 13, marginBottom: 8 }}>
            <XCircle size={16} />
            Tamper Detected: {report.failure_details.attack_type || 'CHAIN_INTEGRITY_VIOLATION'}
          </div>
          <p style={{ fontSize: 12, color: 'var(--accent-rose)', margin: '0 0 10px 0', fontWeight: 500 }}>
            {report.failure_details.reason}
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 8, fontSize: 11, fontFamily: 'monospace' }}>
            {report.failure_details.artifact_id && (
              <div style={{ background: 'var(--bg-item)', border: '1px solid var(--border-subtle)', padding: 8, borderRadius: 4 }}>
                <span style={{ color: 'var(--text-muted)' }}>Affected Artifact: </span>
                <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>{report.failure_details.artifact_id}</span>
              </div>
            )}
            {report.failure_details.record_sequence !== undefined && (
              <div style={{ background: 'var(--bg-item)', border: '1px solid var(--border-subtle)', padding: 8, borderRadius: 4 }}>
                <span style={{ color: 'var(--text-muted)' }}>Sequence Number: </span>
                <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>#{report.failure_details.record_sequence}</span>
              </div>
            )}
            {report.failure_details.expected_sha256 && (
              <div style={{ background: 'var(--bg-item)', border: '1px solid var(--border-subtle)', padding: 8, borderRadius: 4, gridColumn: 'span 2' }}>
                <div style={{ color: 'var(--text-muted)' }}>Expected SHA-256 (from Manifest):</div>
                <div style={{ color: 'var(--accent-blue)', wordBreak: 'break-all', fontWeight: 600 }}>{report.failure_details.expected_sha256}</div>
                <div style={{ color: 'var(--text-muted)', marginTop: 4 }}>Calculated SHA-256 (from Disk Payload):</div>
                <div style={{ color: 'var(--accent-rose)', wordBreak: 'break-all', fontWeight: 600 }}>{report.failure_details.calculated_sha256}</div>
              </div>
            )}
            {report.failure_details.expected_previous_hash && (
              <div style={{ background: 'var(--bg-item)', border: '1px solid var(--border-subtle)', padding: 8, borderRadius: 4, gridColumn: 'span 2' }}>
                <div style={{ color: 'var(--text-muted)' }}>Expected Previous Hash:</div>
                <div style={{ color: 'var(--accent-emerald)', wordBreak: 'break-all', fontWeight: 600 }}>{report.failure_details.expected_previous_hash}</div>
                <div style={{ color: 'var(--text-muted)', marginTop: 4 }}>Stored Previous Hash:</div>
                <div style={{ color: 'var(--accent-rose)', wordBreak: 'break-all', fontWeight: 600 }}>{report.failure_details.stored_previous_hash}</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Chain Metadata Quick Strip */}
      {report && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: 12,
          marginTop: 16,
          paddingTop: 16,
          borderTop: '1px solid var(--border-subtle)'
        }}>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Records Verified</div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)', marginTop: 2 }}>
              {report.records_count} Records
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Chain Tip Hash</div>
            <div style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--accent-blue)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 600 }} title={report.chain_tip || 'N/A'}>
              {report.chain_tip ? `${report.chain_tip.slice(0, 16)}...` : 'N/A'}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Ed25519 Signing Key</div>
            <div style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--accent-emerald)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 600 }} title={report.key_id || 'N/A'}>
              {report.key_id || 'N/A'}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Offline Standalone CLI</div>
            <div style={{ fontSize: 12, color: 'var(--accent-blue)', marginTop: 2, display: 'flex', alignItems: 'center', gap: 4, fontWeight: 600 }}>
              <FileArchive size={12} />
              standalone_verifier.py
            </div>
          </div>
        </div>
      )}

      {/* Expandable 7-Pass Diagnostics */}
      {report && report.diagnostics && (
        <div style={{ marginTop: 16 }}>
          <button
            onClick={() => setShowDiagnostics(!showDiagnostics)}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--accent-blue)',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              padding: 0
            }}
          >
            {showDiagnostics ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            {showDiagnostics ? 'Hide 7-Pass Verification Audit' : 'Show 7-Pass Verification Audit'}
          </button>

          {showDiagnostics && (
            <div style={{
              marginTop: 12,
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: 10,
              background: 'var(--bg-item)',
              padding: 14,
              borderRadius: 8,
              border: '1px solid var(--border-subtle)'
            }}>
              <DiagnosticPassItem
                title="Pass 1: Payload SHA-256"
                status={report.diagnostics.evidence_hashes}
                desc="64KB chunked file hash matches provenance"
              />
              <DiagnosticPassItem
                title="Pass 2: Canonical Metadata"
                status={report.diagnostics.metadata_integrity}
                desc="RFC 8785 deterministic serialization"
              />
              <DiagnosticPassItem
                title="Pass 3: Hash Chain Linkage"
                status={report.diagnostics.hash_chain}
                desc="Previous hash equals predecessor record hash"
              />
              <DiagnosticPassItem
                title="Pass 4: Monotonic Ordering"
                status={report.diagnostics.chain_ordering}
                desc="Strict 1..N continuous sequence without gaps"
              />
              <DiagnosticPassItem
                title="Pass 5: Chain Tip Integrity"
                status={report.diagnostics.chain_tip}
                desc="Tip points to final record in chain"
              />
              <DiagnosticPassItem
                title="Pass 6: Ed25519 Signature"
                status={report.diagnostics.ed25519_signature}
                desc="Cryptographic verification against active key"
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const DiagnosticPassItem: React.FC<{ title: string; status: string; desc: string }> = ({
  title,
  status,
  desc
}) => {
  const isPass = status === 'PASSED';
  const isFail = status === 'FAILED';

  return (
    <div style={{
      background: 'var(--bg-card)',
      padding: '8px 12px',
      borderRadius: 6,
      border: isFail ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid var(--border-subtle)'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-main)' }}>{title}</span>
        <span style={{
          fontSize: 10,
          fontWeight: 700,
          color: isPass ? 'var(--accent-emerald)' : isFail ? 'var(--accent-rose)' : 'var(--accent-amber)'
        }}>
          {status}
        </span>
      </div>
      <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
        {desc}
      </div>
    </div>
  );
};
