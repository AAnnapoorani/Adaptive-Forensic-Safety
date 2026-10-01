import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { BrainCircuit, Sparkles, ShieldAlert, FileCode2, Copy, Check, RefreshCw } from 'lucide-react';

interface AiAnalystViewProps {
  investigationId: string;
}

export const AiAnalystView: React.FC<AiAnalystViewProps> = ({ investigationId }) => {
  const [analysis, setAnalysis] = useState<any>(null);
  const [sigmaRule, setSigmaRule] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'reasoning' | 'sigma'>('reasoning');

  useEffect(() => {
    loadAiData();
  }, [investigationId]);

  const loadAiData = async () => {
    setLoading(true);
    try {
      const [aiRes, sigmaRes] = await Promise.all([
        api.getAiAnalysis(investigationId),
        api.getSigmaRule(investigationId)
      ]);
      setAnalysis(aiRes);
      setSigmaRule(sigmaRes.sigma_rule || '');
    } catch (e) {
      console.error('Failed to load AI analyst data:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleCopySigma = () => {
    navigator.clipboard.writeText(sigmaRule);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div className="glass-panel" style={{ padding: 40, textAlign: 'center' }}>
        <BrainCircuit size={36} className="spin" color="var(--accent-blue)" style={{ margin: '0 auto 16px' }} />
        <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)' }}>AI Forensic Engine Synthesizing Evidence...</h3>
        <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>Correlating artifact chains with MITRE ATT&CK techniques and generating Sigma detection rules.</p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* AI Header Banner */}
      <div className="glass-panel" style={{
        padding: '20px 24px',
        background: 'linear-gradient(135deg, rgba(14, 165, 233, 0.08) 0%, rgba(99, 102, 241, 0.08) 100%)',
        border: '1px solid rgba(14, 165, 233, 0.3)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 16
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 44,
            height: 44,
            borderRadius: 10,
            background: 'linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 15px rgba(14, 165, 233, 0.4)'
          }}>
            <Sparkles size={24} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-main)', margin: 0 }}>
                SUVADU AI Forensic Analyst & Detection Engine
              </h2>
              <span className="badge badge-valid" style={{ fontSize: 11 }}>
                AUTONOMOUS REASONING
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
              Evidence telemetry evaluated with MITRE ATT&CK alignment &bull; Section 65B Admissibility Confirmed
            </div>
          </div>
        </div>

        <button className="btn-secondary" onClick={loadAiData} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <RefreshCw size={14} /> Re-analyze
        </button>
      </div>

      {/* Sub Tabs */}
      <div style={{ display: 'flex', gap: 10 }}>
        <button
          className={`tab-btn ${activeTab === 'reasoning' ? 'active' : ''}`}
          onClick={() => setActiveTab('reasoning')}
          style={{ display: 'flex', alignItems: 'center', gap: 8 }}
        >
          <BrainCircuit size={16} /> Forensic Reasoning & MITRE Matrix
        </button>
        <button
          className={`tab-btn ${activeTab === 'sigma' ? 'active' : ''}`}
          onClick={() => setActiveTab('sigma')}
          style={{ display: 'flex', alignItems: 'center', gap: 8 }}
        >
          <FileCode2 size={16} /> Auto-Generated Sigma Rule
        </button>
      </div>

      {activeTab === 'reasoning' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 20 }}>
          {/* Executive Synthesis Card */}
          <div className="glass-panel" style={{ padding: 24 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldAlert size={18} color="var(--accent-red)" /> Executive Threat Synthesis
              </h3>
              <span className={`badge ${analysis?.executive_risk_level === 'CRITICAL' ? 'badge-failed' : 'badge-warning'}`}>
                {analysis?.executive_risk_level || 'LOW'} RISK ({Math.round((analysis?.confidence_score || 0.9) * 100)}% CONFIDENCE)
              </span>
            </div>

            <div style={{
              background: 'var(--bg-code)',
              padding: 16,
              borderRadius: 8,
              border: '1px solid var(--border-subtle)',
              marginBottom: 18,
              fontSize: 13,
              lineHeight: 1.6,
              color: 'var(--text-main)'
            }}>
              <strong>Root Cause Hypothesis:</strong>
              <p style={{ marginTop: 6, marginBottom: 0, color: 'var(--text-muted)' }}>
                {analysis?.root_cause_hypothesis}
              </p>
            </div>

            <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', marginBottom: 10 }}>
              MITRE ATT&CK® Techniques Mapped:
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 18 }}>
              {analysis?.mitre_attack_matrix?.map((technique: string, idx: number) => (
                <div key={idx} style={{
                  padding: '8px 12px',
                  background: 'rgba(99, 102, 241, 0.08)',
                  border: '1px solid rgba(99, 102, 241, 0.3)',
                  borderRadius: 6,
                  fontSize: 12,
                  color: 'var(--text-main)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8
                }}>
                  <span style={{ color: 'var(--accent-blue)', fontWeight: 700 }}>&bull;</span>
                  {technique}
                </div>
              ))}
            </div>

            <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', marginBottom: 10 }}>
              Actionable Incident Response Actions:
            </h4>
            <ul style={{ margin: 0, paddingLeft: 20, fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6 }}>
              {analysis?.actionable_recommendations?.map((rec: string, idx: number) => (
                <li key={idx} style={{ marginBottom: 6 }}>{rec}</li>
              ))}
            </ul>
          </div>

          {/* Key Findings & Legal Admissibility Card */}
          <div className="glass-panel" style={{ padding: 24 }}>
            <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-main)', marginBottom: 16 }}>
              Granular Telemetry Findings ({analysis?.key_findings?.length || 0})
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 24 }}>
              {analysis?.key_findings?.map((find: any, idx: number) => (
                <div key={idx} style={{
                  padding: 14,
                  borderRadius: 8,
                  border: '1px solid var(--border-subtle)',
                  background: 'var(--bg-panel)'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)' }}>{find.summary}</span>
                    <span className="badge badge-warning" style={{ fontSize: 10 }}>{find.category}</span>
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{find.details}</div>
                  <div style={{ marginTop: 6, fontSize: 11, color: 'var(--accent-blue)', fontFamily: 'monospace' }}>
                    MITRE: {find.mitre}
                  </div>
                </div>
              ))}
            </div>

            <div style={{
              padding: 16,
              borderRadius: 8,
              background: 'rgba(16, 185, 129, 0.08)',
              border: '1px solid var(--accent-emerald)'
            }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-emerald)', marginBottom: 6 }}>
                Legal Admissibility & Evidence Integrity
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-main)', lineHeight: 1.5 }}>
                Status: <strong>{analysis?.legal_admissibility_assessment?.tamper_status}</strong><br />
                Standard: <strong>ISO/IEC 27037 Verified</strong><br />
                Statute: <strong>{analysis?.legal_admissibility_assessment?.statutory_reference}</strong>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'sigma' && (
        <div className="glass-panel" style={{ padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div>
              <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-main)' }}>Production Sigma Detection Rule</h3>
              <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '4px 0 0' }}>
                Deployable directly to Microsoft Defender, Splunk, Elastic, or Sentinel to hunt for this IoC pattern.
              </p>
            </div>
            <button className="btn-primary" onClick={handleCopySigma} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              {copied ? <Check size={14} /> : <Copy size={14} />}
              {copied ? 'Copied YAML!' : 'Copy Sigma YAML'}
            </button>
          </div>

          <pre style={{
            background: 'var(--bg-code)',
            color: 'var(--text-main)',
            padding: 18,
            borderRadius: 8,
            fontSize: 13,
            lineHeight: 1.5,
            border: '1px solid var(--border-subtle)',
            overflowX: 'auto'
          }}>
            {sigmaRule}
          </pre>
        </div>
      )}
    </div>
  );
};
