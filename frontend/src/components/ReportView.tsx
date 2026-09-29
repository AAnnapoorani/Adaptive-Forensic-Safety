import React, { useState, useEffect } from 'react';
import { api, BASE_URL } from '../services/api';
import { Copy, Check, Printer, ShieldCheck } from 'lucide-react';

interface ReportViewProps {
  investigationId: string;
  isOngoing?: boolean;
}

export const ReportView: React.FC<ReportViewProps> = ({ investigationId, isOngoing }) => {
  const [reportData, setReportData] = useState<{ markdown: string; html: string; json?: any } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<'html' | 'markdown' | 'json'>('html');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    loadReport();
  }, [investigationId]);

  // If initial load returned null or isOngoing, poll until report is available
  useEffect(() => {
    let timer: any = null;
    if (!reportData || isOngoing) {
      timer = setInterval(() => {
        loadReport(false);
      }, 2500);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [investigationId, reportData, isOngoing]);

  const loadReport = async (showSpinner: boolean = true) => {
    if (showSpinner) setLoading(true);
    setError(null);
    try {
      const data = await api.getInvestigationReport(investigationId);
      setReportData(data);
    } catch (err: any) {
      console.error('Failed to load report:', err);
      setError(err.message || 'Unable to load report');
    } finally {
      if (showSpinner) setLoading(false);
    }
  };

  const handleCopy = () => {
    if (!reportData) return;
    let contentToCopy = '';
    if (mode === 'json' && reportData.json) {
      contentToCopy = JSON.stringify(reportData.json, null, 2);
    } else {
      contentToCopy = reportData.markdown;
    }
    navigator.clipboard.writeText(contentToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    const win = window.open(`${BASE_URL}/investigations/${investigationId}/report/html`, '_blank');
    if (win) {
      win.focus();
    }
  };

  if (loading && !reportData) {
    return (
      <div className="glass-panel" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
        <div style={{ marginBottom: 12, fontSize: 16, fontWeight: 600, color: 'var(--text-main)' }}>
          Synthesizing Digital Forensic Report...
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          Extracting evidence artifacts, building timeline ledger, and compiling forensic Markdown &amp; HTML report.
        </div>
      </div>
    );
  }

  if (!reportData) {
    return (
      <div className="glass-panel" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
        <div style={{ color: 'var(--accent-rose)', fontSize: 15, fontWeight: 600, marginBottom: 8 }}>
          {error || 'Unable to load report for this investigation.'}
        </div>
        <div style={{ fontSize: 13, marginBottom: 16 }}>
          The investigation may still be executing or initializing.
        </div>
        <button className="btn btn-secondary btn-sm" onClick={() => loadReport(true)}>
          Retry Generating Report
        </button>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Report Header Actions */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <button
            className={`btn ${mode === 'html' ? 'btn-primary' : 'btn-secondary'} btn-sm`}
            onClick={() => setMode('html')}
          >
            Formatted HTML Report
          </button>
          <button
            className={`btn ${mode === 'markdown' ? 'btn-primary' : 'btn-secondary'} btn-sm`}
            onClick={() => setMode('markdown')}
          >
            Markdown Report
          </button>
          <button
            className={`btn ${mode === 'json' ? 'btn-primary' : 'btn-secondary'} btn-sm`}
            onClick={() => setMode('json')}
          >
            Structured JSON
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <a
            href={api.getCourtDossierHtmlUrl(investigationId)}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-sm"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
              color: '#fff',
              textDecoration: 'none',
              fontWeight: 600,
              padding: '6px 12px',
              borderRadius: 6
            }}
            title="Download Court-Admissible Forensic Certificate (Section 65B Indian Evidence Act / ISO/IEC 27037)"
          >
            <ShieldCheck size={14} />
            Section 65B Court Dossier (PDF)
          </a>
          <button className="btn btn-secondary btn-sm" onClick={handleCopy}>
            {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
            {copied ? 'Copied!' : mode === 'json' ? 'Copy JSON' : 'Copy Markdown'}
          </button>
          <button className="btn btn-primary btn-sm" onClick={handlePrint}>
            <Printer size={14} />
            Print / Export HTML Report
          </button>
        </div>
      </div>

      {/* Report Document Container */}
      <div className="glass-panel" style={{ padding: 20 }}>
        {mode === 'html' ? (
          <div style={{
            background: '#ffffff',
            borderRadius: 8,
            overflow: 'hidden',
            minHeight: 650,
            border: '1px solid var(--border-subtle)'
          }}>
            <iframe
              srcDoc={reportData.html}
              title="Forensic Report HTML"
              style={{
                width: '100%',
                minHeight: 700,
                border: 'none',
                background: '#ffffff'
              }}
            />
          </div>
        ) : mode === 'markdown' ? (
          <textarea
            readOnly
            value={reportData.markdown}
            style={{
              width: '100%',
              minHeight: 600,
              background: 'var(--bg-code)',
              color: 'var(--text-code)',
              fontFamily: 'Fira Code, monospace',
              fontSize: 12,
              padding: 16,
              borderRadius: 8,
              border: '1px solid var(--border-subtle)',
              resize: 'vertical',
              lineHeight: 1.5
            }}
          />
        ) : (
          <textarea
            readOnly
            value={JSON.stringify(reportData.json || {}, null, 2)}
            style={{
              width: '100%',
              minHeight: 600,
              background: 'var(--bg-code)',
              color: 'var(--text-main)',
              fontFamily: 'Fira Code, monospace',
              fontSize: 12,
              padding: 16,
              borderRadius: 8,
              border: '1px solid var(--border-subtle)',
              resize: 'vertical',
              lineHeight: 1.5
            }}
          />
        )}
      </div>
    </div>
  );
};
