import React, { useState } from 'react';
import type { CorrelationMatch } from '../types';
import { AlertTriangle, Eye, ShieldAlert, CheckCircle } from 'lucide-react';

interface CorrelationsViewProps {
  correlations: CorrelationMatch[];
}

export const CorrelationsView: React.FC<CorrelationsViewProps> = ({ correlations }) => {
  const [selectedMatch, setSelectedMatch] = useState<CorrelationMatch | null>(null);

  if (correlations.length === 0) {
    return (
      <div className="glass-panel" style={{ padding: 40, textAlign: 'center' }}>
        <CheckCircle size={36} color="var(--accent-emerald)" style={{ margin: '0 auto 12px' }} />
        <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)' }}>No Investigation Indicators Triggered</h3>
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 6, maxWidth: 500, margin: '6px auto 0' }}>
          All executed forensic checks completed within expected operational parameters. No rule-based correlation patterns were matched.
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Notice Banner */}
      <div style={{ padding: '12px 18px', background: 'rgba(217, 119, 6, 0.08)', borderRadius: 8, border: '1px solid rgba(217, 119, 6, 0.4)', display: 'flex', alignItems: 'center', gap: 12 }}>
        <AlertTriangle size={20} color="var(--accent-amber)" style={{ flexShrink: 0 }} />
        <div style={{ fontSize: 13, color: 'var(--text-main)', lineHeight: 1.5 }}>
          <strong style={{ color: 'var(--accent-amber)' }}>Rule-Based Forensic Indicators:</strong> These correlation events represent observed system telemetry matches that triggered investigative escalation. They are neutral investigative leads requiring verification.
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: selectedMatch ? '1fr 380px' : '1fr', gap: 20 }}>
        {/* Match Cards List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {correlations.map(corr => (
            <div
              key={corr.id}
              className="glass-panel"
              onClick={() => setSelectedMatch(corr)}
              style={{
                padding: '18px 20px',
                cursor: 'pointer',
                border: selectedMatch?.id === corr.id ? '2px solid var(--accent-amber)' : '1px solid var(--border-subtle)',
                background: selectedMatch?.id === corr.id ? 'rgba(217, 119, 6, 0.12)' : 'var(--bg-item)',
                transition: 'all 0.15s ease'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <ShieldAlert size={18} color="var(--accent-amber)" />
                  <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-main)' }}>{corr.rule_name}</span>
                  <span className="badge badge-warning" style={{ fontSize: 11 }}>{corr.status_label}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className="badge badge-in-progress" style={{ fontSize: 10 }}>Round {corr.round_number}</span>
                  <span style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'monospace' }}>
                    {new Date(corr.created_at).toLocaleTimeString()}
                  </span>
                </div>
              </div>

              <div style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.5, marginBottom: 12 }}>
                {corr.description}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-muted)', paddingTop: 10, borderTop: '1px solid var(--border-subtle)' }}>
                <span>Confidence Assessment: <strong style={{ color: 'var(--accent-blue)' }}>{corr.confidence}</strong></span>
                <span style={{ color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', gap: 4, fontWeight: 600 }}>
                  <Eye size={13} /> View Telemetry Details
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Selected Correlation Telemetry Inspector */}
        {selectedMatch && (
          <div className="glass-panel" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 10 }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-muted)' }}>Indicator Evidence Details</span>
              <button
                onClick={() => setSelectedMatch(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: 14 }}
              >
                ✕
              </button>
            </div>

            <div>
              <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)' }}>{selectedMatch.rule_name}</div>
              <div style={{ fontSize: 12, color: 'var(--accent-amber)', marginTop: 2, fontWeight: 700 }}>{selectedMatch.status_label.toUpperCase()}</div>
            </div>

            <div>
              <span style={{ color: 'var(--text-dim)', fontSize: 11, display: 'block', marginBottom: 4, fontWeight: 600 }}>MATCHED TELEMETRY PAYLOAD:</span>
              <pre style={{
                background: 'var(--bg-code)',
                padding: 12,
                borderRadius: 6,
                fontSize: 12,
                color: 'var(--text-main)',
                overflowX: 'auto',
                maxHeight: 320,
                border: '1px solid var(--border-subtle)'
              }}>
                {selectedMatch.matched_data ? JSON.stringify(JSON.parse(selectedMatch.matched_data), null, 2) : 'No raw data recorded.'}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
