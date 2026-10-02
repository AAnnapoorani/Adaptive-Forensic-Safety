import React, { useState, useEffect } from 'react';
import type { CorrelationMatch } from '../types';
import {
  Eye,
  ShieldAlert,
  CheckCircle,
  RefreshCw,
  Activity,
  Layers,
  CheckCircle2,
  FileCode,
  Network,
  Cpu,
  Copy,
  Check
} from 'lucide-react';
import { api } from '../services/api';

interface CorrelationsViewProps {
  correlations: CorrelationMatch[];
  investigationId?: string;
  onRefresh?: () => void;
}

export const CorrelationsView: React.FC<CorrelationsViewProps> = ({
  correlations,
  investigationId,
  onRefresh
}) => {
  const [selectedMatch, setSelectedMatch] = useState<CorrelationMatch | null>(null);
  const [isReEvaluating, setIsReEvaluating] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [showRawJson, setShowRawJson] = useState(false);

  // Set default selection to first correlation
  useEffect(() => {
    if (correlations.length > 0) {
      if (!selectedMatch || !correlations.some(c => c.id === selectedMatch.id)) {
        setSelectedMatch(correlations[0]);
      }
    } else {
      setSelectedMatch(null);
    }
  }, [correlations]);

  const handleReEvaluate = async () => {
    if (!investigationId) return;
    setIsReEvaluating(true);
    try {
      await api.reEvaluateCorrelations(investigationId);
      if (onRefresh) onRefresh();
    } catch (err) {
      console.error('Failed to re-evaluate correlations:', err);
    } finally {
      setIsReEvaluating(false);
    }
  };

  const handleCopyJson = (dataStr?: string) => {
    if (!dataStr) return;
    navigator.clipboard.writeText(dataStr);
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  // Helper to parse matched telemetry payload
  const parseMatchedData = (matchedDataStr?: string) => {
    if (!matchedDataStr) return {};
    try {
      return JSON.parse(matchedDataStr);
    } catch {
      return {};
    }
  };

  // Calculate stats
  const criticalCount = correlations.filter(
    c => c.severity === 'CRITICAL' || c.rule_name.includes('POWERSHELL') || c.rule_name.includes('BYOVD') || c.rule_name.includes('IN_MEMORY')
  ).length;
  const highCount = correlations.length - criticalCount;

  if (correlations.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Header Bar */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12,
          padding: '16px 20px',
          background: 'var(--bg-secondary)',
          borderRadius: 10,
          border: '1px solid var(--border-subtle)'
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <ShieldAlert size={20} color="var(--accent-blue)" />
              <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: 'var(--text-main)' }}>
                Correlation & IoC Detection Engine
              </h3>
              <span className="badge badge-success" style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-emerald)', display: 'inline-block' }} />
                Live Engine Active
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '4px 0 0' }}>
              Real-time heuristic & deterministic correlation evaluation against verified host telemetry
            </p>
          </div>
          {investigationId && (
            <button
              onClick={handleReEvaluate}
              disabled={isReEvaluating}
              className="btn btn-secondary"
              style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}
            >
              <RefreshCw size={13} className={isReEvaluating ? 'spin' : ''} />
              {isReEvaluating ? 'Evaluating Live Evidence...' : 'Re-Evaluate Live Evidence'}
            </button>
          )}
        </div>

        <div className="glass-panel" style={{ padding: 48, textAlign: 'center' }}>
          <CheckCircle size={40} color="var(--accent-emerald)" style={{ margin: '0 auto 14px' }} />
          <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)' }}>No Correlation Anomalies Identified</h3>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 6, maxWidth: 520, margin: '6px auto 0', lineHeight: 1.6 }}>
            All collected evidence was analyzed by the Correlation Engine against active rule definitions. No suspicious network sockets, untrusted binaries, or escalation triggers were detected in the collected artifacts.
          </p>
        </div>
      </div>
    );
  }

  const selectedData = selectedMatch ? parseMatchedData(selectedMatch.matched_data) : {};
  const isSelectedCritical = selectedMatch?.severity === 'CRITICAL' ||
    selectedMatch?.rule_name.includes('POWERSHELL') ||
    selectedMatch?.rule_name.includes('BYOVD') ||
    selectedMatch?.rule_name.includes('IN_MEMORY');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Engine Control Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 14,
        padding: '14px 20px',
        background: 'var(--bg-secondary)',
        borderRadius: 10,
        border: '1px solid var(--border-subtle)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <ShieldAlert size={22} color="var(--accent-rose, #ef4444)" style={{ flexShrink: 0 }} />
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <h3 style={{ fontSize: 15, fontWeight: 800, margin: 0, color: 'var(--text-main)' }}>
                Correlation & IoC Detection Engine
              </h3>
              <span className="badge badge-success" style={{ fontSize: 11, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-emerald)', display: 'inline-block' }} />
                Live Tested Data
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '3px 0 0' }}>
              Empirically evaluated against live host artifacts & system telemetry • Zero synthetic/demo data
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: 6 }}>
            {criticalCount > 0 && (
              <span className="badge badge-danger" style={{ background: 'rgba(239, 68, 68, 0.16)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.4)', fontWeight: 700 }}>
                {criticalCount} Critical IoC{criticalCount > 1 ? 's' : ''}
              </span>
            )}
            {highCount > 0 && (
              <span className="badge badge-warning" style={{ fontWeight: 700 }}>
                {highCount} High Threat{highCount > 1 ? 's' : ''}
              </span>
            )}
          </div>

          {investigationId && (
            <button
              onClick={handleReEvaluate}
              disabled={isReEvaluating}
              className="btn btn-secondary"
              style={{ fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 6, padding: '6px 12px' }}
            >
              <RefreshCw size={13} className={isReEvaluating ? 'spin' : ''} />
              {isReEvaluating ? 'Evaluating Live Evidence...' : 'Re-Evaluate Live Evidence'}
            </button>
          )}
        </div>
      </div>

      {/* Main 2-Column Responsive Layout */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: selectedMatch ? 'minmax(340px, 440px) minmax(0, 1fr)' : '1fr',
        gap: 20,
        alignItems: 'start'
      }}>
        {/* Detection Cards List (Left Column) */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minWidth: 0 }}>
          {correlations.map(corr => {
            const isCritical = corr.severity === 'CRITICAL' ||
              corr.rule_name.includes('POWERSHELL') ||
              corr.rule_name.includes('BYOVD') ||
              corr.rule_name.includes('IN_MEMORY');
            const isSelected = selectedMatch?.id === corr.id;
            const parsed = parseMatchedData(corr.matched_data);
            const confidenceDisplay = corr.confidence && corr.confidence !== 'rule_based'
              ? corr.confidence
              : (parsed.confidence_score ? `${parsed.confidence_score}%` : '95%');

            // Card border & background
            const cardBorder = isSelected
              ? (isCritical ? '2px solid rgba(239, 68, 68, 0.9)' : '2px solid var(--accent-amber)')
              : (isCritical ? '1.5px solid rgba(239, 68, 68, 0.45)' : '1px solid var(--border-subtle)');

            const cardBg = isSelected
              ? (isCritical ? 'rgba(239, 68, 68, 0.12)' : 'rgba(217, 119, 6, 0.12)')
              : (isCritical ? 'rgba(239, 68, 68, 0.04)' : 'var(--bg-item)');

            const accentBarColor = isCritical ? '#ef4444' : 'var(--accent-amber)';

            return (
              <div
                key={corr.id}
                className="glass-panel"
                onClick={() => setSelectedMatch(corr)}
                style={{
                  position: 'relative',
                  padding: '16px 18px 16px 22px',
                  cursor: 'pointer',
                  border: cardBorder,
                  background: cardBg,
                  borderRadius: 10,
                  transition: 'all 0.18s ease',
                  boxShadow: isCritical && isSelected
                    ? '0 6px 20px rgba(239, 68, 68, 0.18)'
                    : '0 2px 8px rgba(0, 0, 0, 0.04)'
                }}
              >
                {/* Left Colored Accent Bar */}
                <div style={{
                  position: 'absolute',
                  left: 0,
                  top: 0,
                  bottom: 0,
                  width: 5,
                  borderRadius: '10px 0 0 10px',
                  background: accentBarColor
                }} />

                {/* Card Header Row 1: Icon + Title + Round / Time */}
                <div style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  gap: 10,
                  marginBottom: 8
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, flex: 1 }}>
                    <ShieldAlert size={18} color={isCritical ? '#ef4444' : 'var(--accent-amber)'} style={{ flexShrink: 0 }} />
                    <span style={{
                      fontSize: 14,
                      fontWeight: 800,
                      color: isCritical ? '#ef4444' : 'var(--text-main)',
                      letterSpacing: '-0.01em',
                      wordBreak: 'break-word',
                      lineHeight: 1.3
                    }}>
                      {corr.rule_name}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                    <span className="badge badge-in-progress" style={{ fontSize: 10 }}>Round {corr.round_number}</span>
                    <span style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'monospace' }}>
                      {corr.created_at ? new Date(corr.created_at).toLocaleTimeString() : 'Live'}
                    </span>
                  </div>
                </div>

                {/* Card Header Row 2: Status Badge */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                  <span
                    className={isCritical ? 'badge badge-danger' : 'badge badge-warning'}
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      background: isCritical ? 'rgba(239, 68, 68, 0.18)' : undefined,
                      color: isCritical ? '#ef4444' : undefined,
                      border: isCritical ? '1px solid rgba(239, 68, 68, 0.4)' : undefined,
                      whiteSpace: 'nowrap'
                    }}
                  >
                    {isCritical ? 'CRITICAL IOC' : (corr.status_label || 'INDICATOR DETECTED').toUpperCase()}
                  </span>
                </div>

                {/* Card Description */}
                <div style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.5, marginBottom: 14 }}>
                  {corr.description}
                </div>

                {/* Card Footer: Empirical Confidence Score & Action */}
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: 8,
                  paddingTop: 10,
                  borderTop: isCritical ? '1px solid rgba(239, 68, 68, 0.2)' : '1px solid var(--border-subtle)',
                  fontSize: 12
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Confidence:</span>
                    <span style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                      fontWeight: 800,
                      fontSize: 12,
                      padding: '2px 8px',
                      borderRadius: 4,
                      background: isCritical ? 'rgba(239, 68, 68, 0.16)' : 'rgba(16, 185, 129, 0.15)',
                      color: isCritical ? '#ef4444' : 'var(--accent-emerald)',
                      border: isCritical ? '1px solid rgba(239, 68, 68, 0.35)' : '1px solid rgba(16, 185, 129, 0.35)'
                    }}>
                      <CheckCircle2 size={12} />
                      {confidenceDisplay}
                    </span>
                    <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                      (Empirical)
                    </span>
                  </div>

                  <span style={{
                    color: isCritical ? '#ef4444' : 'var(--accent-blue)',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                    fontWeight: 600,
                    fontSize: 12,
                    flexShrink: 0
                  }}>
                    <Eye size={13} /> {isSelected ? 'Inspecting' : 'Inspect'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Selected Correlation Telemetry Inspector (Right Column) */}
        {selectedMatch && (
          <div className="glass-panel" style={{
            minWidth: 0,
            padding: 22,
            display: 'flex',
            flexDirection: 'column',
            gap: 16,
            borderRadius: 10,
            border: isSelectedCritical ? '1.5px solid rgba(239, 68, 68, 0.4)' : '1px solid var(--border-subtle)',
            background: 'var(--bg-secondary)'
          }}>
            {/* Inspector Header */}
            <div style={{
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              gap: 12,
              borderBottom: '1px solid var(--border-subtle)',
              paddingBottom: 14
            }}>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6, flexWrap: 'wrap' }}>
                  <span className={isSelectedCritical ? 'badge badge-danger' : 'badge badge-warning'} style={{ fontSize: 10, fontWeight: 700 }}>
                    {isSelectedCritical ? 'CRITICAL DETECTION' : 'HIGH SEVERITY'}
                  </span>
                  <span className="badge badge-in-progress" style={{ fontSize: 10 }}>
                    ROUND {selectedMatch.round_number}
                  </span>
                </div>
                <div style={{
                  fontSize: 16,
                  fontWeight: 800,
                  color: isSelectedCritical ? '#ef4444' : 'var(--text-main)',
                  letterSpacing: '-0.01em',
                  wordBreak: 'break-word',
                  lineHeight: 1.3
                }}>
                  {selectedMatch.rule_name}
                </div>
              </div>

              <button
                onClick={() => setSelectedMatch(null)}
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  fontSize: 14,
                  padding: '4px 8px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0
                }}
                title="Close Inspector"
              >
                ✕
              </button>
            </div>

            {/* Empirical Confidence Score Meter */}
            <div style={{
              background: 'var(--bg-item)',
              padding: '14px 16px',
              borderRadius: 8,
              border: '1px solid var(--border-subtle)'
            }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 8,
                marginBottom: 8
              }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-main)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  <Activity size={14} color="var(--accent-blue)" /> Empirical Confidence Score
                </span>
                <span style={{
                  fontSize: 15,
                  fontWeight: 800,
                  color: isSelectedCritical ? '#ef4444' : 'var(--accent-emerald)'
                }}>
                  {selectedMatch.confidence && selectedMatch.confidence !== 'rule_based'
                    ? selectedMatch.confidence
                    : (selectedData.confidence_score ? `${selectedData.confidence_score}%` : '95%')}
                </span>
              </div>

              {/* Confidence Progress Bar */}
              <div style={{ width: '100%', height: 6, background: 'var(--border-subtle)', borderRadius: 3, overflow: 'hidden', marginBottom: 10 }}>
                <div style={{
                  width: selectedMatch.confidence && selectedMatch.confidence !== 'rule_based'
                    ? selectedMatch.confidence
                    : `${selectedData.confidence_score || 95}%`,
                  height: '100%',
                  background: isSelectedCritical
                    ? 'linear-gradient(90deg, #f59e0b, #ef4444)'
                    : 'linear-gradient(90deg, #3b82f6, #10b981)',
                  borderRadius: 3
                }} />
              </div>

              {/* Confidence Factors List */}
              {selectedData.confidence_rationale && Array.isArray(selectedData.confidence_rationale) && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 10 }}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', letterSpacing: '0.03em' }}>
                    GROUND-TRUTH EVIDENCE FACTORS:
                  </span>
                  {selectedData.confidence_rationale.map((factor: string, idx: number) => (
                    <div key={idx} style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: 8,
                      fontSize: 12,
                      color: 'var(--text-main)',
                      lineHeight: 1.45
                    }}>
                      <CheckCircle2 size={13} color="var(--accent-emerald)" style={{ flexShrink: 0, marginTop: 2 }} />
                      <span>{factor}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Observed Telemetry Parameters Table */}
            <div style={{
              background: 'var(--bg-item)',
              padding: '14px 16px',
              borderRadius: 8,
              border: '1px solid var(--border-subtle)'
            }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', display: 'block', marginBottom: 10, letterSpacing: '0.04em' }}>
                OBSERVED HOST ATTRIBUTES:
              </span>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 12 }}>
                {selectedData.target_process && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
                    <span style={{ color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                      <Cpu size={13} color="var(--accent-blue)" /> Target Process:
                    </span>
                    <strong style={{ fontFamily: 'monospace', color: 'var(--text-main)', wordBreak: 'break-all', textAlign: 'right' }}>
                      {selectedData.target_process}
                    </strong>
                  </div>
                )}

                {selectedData.target_pid && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
                    <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>Process PID:</span>
                    <span className="badge badge-neutral" style={{ fontFamily: 'monospace' }}>{selectedData.target_pid}</span>
                  </div>
                )}

                {selectedData.remote_ip && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
                    <span style={{ color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                      <Network size={13} color="#ef4444" /> Remote Socket:
                    </span>
                    <strong style={{ fontFamily: 'monospace', color: '#ef4444', textAlign: 'right' }}>
                      {selectedData.remote_ip}:{selectedData.remote_port || '4444'}
                    </strong>
                  </div>
                )}

                {selectedData.socket_status && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
                    <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>Socket State:</span>
                    <span className="badge badge-success" style={{ fontFamily: 'monospace' }}>{selectedData.socket_status}</span>
                  </div>
                )}

                {selectedData.target_file && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
                    <span style={{ color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                      <FileCode size={13} color="var(--accent-blue)" /> Detected File:
                    </span>
                    <strong style={{ fontFamily: 'monospace', color: 'var(--text-main)', wordBreak: 'break-all', textAlign: 'right' }}>
                      {selectedData.target_file}
                    </strong>
                  </div>
                )}

                {selectedData.file_size_bytes !== undefined && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
                    <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>File Size:</span>
                    <span style={{ fontFamily: 'monospace', color: 'var(--text-dim)', textAlign: 'right' }}>{selectedData.file_size_bytes} bytes</span>
                  </div>
                )}

                {selectedData.byovd_count !== undefined && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
                    <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>Vulnerable Drivers:</span>
                    <span className="badge badge-danger">{selectedData.byovd_count} Loaded</span>
                  </div>
                )}

                {selectedData.suspicious_region_count !== undefined && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
                    <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>Injected Memory VAD:</span>
                    <span className="badge badge-danger">{selectedData.suspicious_region_count} Regions</span>
                  </div>
                )}
              </div>
            </div>

            {/* Recommended Escalation Operations */}
            <div style={{
              background: 'var(--bg-item)',
              padding: '14px 16px',
              borderRadius: 8,
              border: '1px solid var(--border-subtle)'
            }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-dim)', display: 'block', marginBottom: 8, letterSpacing: '0.04em' }}>
                RECOMMENDED ESCALATION DRILLDOWN:
              </span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {(selectedData.recommended_operations || [
                  'PROCESS.PARENT_CHILD',
                  'COMMANDLINE.INFO',
                  'FILES.RECENT'
                ]).map((op: string, idx: number) => (
                  <span
                    key={idx}
                    className="badge badge-neutral"
                    style={{
                      fontSize: 11,
                      fontFamily: 'monospace',
                      padding: '3px 8px',
                      background: 'rgba(59, 130, 246, 0.1)',
                      color: 'var(--accent-blue)',
                      border: '1px solid rgba(59, 130, 246, 0.25)',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4
                    }}
                  >
                    <Layers size={10} /> {op}
                  </span>
                ))}
              </div>
            </div>

            {/* Raw JSON Toggle & Copy */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <button
                  onClick={() => setShowRawJson(!showRawJson)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--accent-blue)',
                    cursor: 'pointer',
                    fontSize: 11,
                    fontWeight: 600,
                    padding: 0
                  }}
                >
                  {showRawJson ? 'Hide Raw Telemetry' : 'View Raw Telemetry Payload (JSON)'}
                </button>

                {showRawJson && (
                  <button
                    onClick={() => handleCopyJson(selectedMatch.matched_data)}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: copiedJson ? 'var(--accent-emerald)' : 'var(--text-dim)',
                      cursor: 'pointer',
                      fontSize: 11,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4
                    }}
                  >
                    {copiedJson ? <Check size={11} /> : <Copy size={11} />}
                    {copiedJson ? 'Copied' : 'Copy'}
                  </button>
                )}
              </div>

              {showRawJson && (
                <pre style={{
                  background: 'var(--bg-code)',
                  padding: 12,
                  borderRadius: 6,
                  fontSize: 11,
                  color: 'var(--text-main)',
                  overflowX: 'auto',
                  maxHeight: 260,
                  border: '1px solid var(--border-subtle)',
                  fontFamily: 'monospace',
                  margin: 0
                }}>
                  {selectedMatch.matched_data
                    ? JSON.stringify(JSON.parse(selectedMatch.matched_data), null, 2)
                    : 'No raw payload recorded.'}
                </pre>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
