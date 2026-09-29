import React, { useState, useEffect, useRef } from 'react';
import { api } from '../services/api';
import type {
  InvestigationDetail,
  InvestigationRound,
  EvidenceArtifact,
  ProvenanceRecord,
  CorrelationMatch,
  TimelineEvent
} from '../types';
import { EvidenceGraphView } from '../components/EvidenceGraphView';
import { TimelineView } from '../components/TimelineView';
import { ProvenanceTable } from '../components/ProvenanceTable';
import { CorrelationsView } from '../components/CorrelationsView';
import { ArtifactsTable } from '../components/ArtifactsTable';
import { WorkflowStepsView } from '../components/WorkflowStepsView';
import { ReportView } from '../components/ReportView';
import { ChainIntegrityCard } from '../components/ChainIntegrityCard';
import { formatDateTime, formatTime } from '../utils/date';

import {
  Shield,
  GitBranch,
  ListOrdered,
  FileJson,
  AlertTriangle,
  Clock,
  ShieldCheck,
  FileText,
  Play,
  ArrowLeft,
  Zap,
  RefreshCw,
  Loader2,
  CheckCircle2,
  Activity
} from 'lucide-react';

interface InvestigationDetailPageProps {
  investigationId: string;
  onBack: () => void;
}

export const InvestigationDetailPage: React.FC<InvestigationDetailPageProps> = ({
  investigationId,
  onBack
}) => {
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [rounds, setRounds] = useState<InvestigationRound[]>([]);
  const [artifacts, setArtifacts] = useState<EvidenceArtifact[]>([]);
  const [provenance, setProvenance] = useState<ProvenanceRecord[]>([]);
  const [correlations, setCorrelations] = useState<CorrelationMatch[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [planData, setPlanData] = useState<any>(null);

  const [activeTab, setActiveTab] = useState<string>('overview');
  const [loading, setLoading] = useState(true);
  const [executing, setExecuting] = useState(false);
  const [lastSynced, setLastSynced] = useState<Date>(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);

  const pollingRef = useRef<any>(null);

  const loadAll = async (showLoadingSpinner: boolean = false) => {
    if (showLoadingSpinner) setLoading(true);
    setIsRefreshing(true);
    try {
      const [det, r, a, p, c, t, pl] = await Promise.all([
        api.getInvestigation(investigationId),
        api.getInvestigationRounds(investigationId),
        api.getInvestigationEvidence(investigationId),
        api.getInvestigationProvenance(investigationId),
        api.getInvestigationCorrelations(investigationId),
        api.getInvestigationTimeline(investigationId),
        api.getInvestigationPlan(investigationId)
      ]);
      setDetail(det);
      setRounds(r);
      setArtifacts(a);
      setProvenance(p);
      setCorrelations(c);
      setTimeline(t);
      setPlanData(pl);
      setLastSynced(new Date());

      // If status changed to COMPLETED or FAILED, clear executing state
      if (det.status === 'COMPLETED' || det.status === 'FAILED') {
        setExecuting(false);
      }
    } catch (err) {
      console.error('Failed to load investigation details:', err);
    } finally {
      if (showLoadingSpinner) setLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadAll(true);
  }, [investigationId]);

  // Real-time auto-polling when investigation is in progress or executing
  useEffect(() => {
    const shouldPoll = executing || detail?.status === 'IN_PROGRESS' || detail?.status === 'CREATED' || detail?.status === 'EXECUTING';

    if (shouldPoll) {
      pollingRef.current = setInterval(() => {
        loadAll(false);
      }, 1800);
    } else if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    };
  }, [investigationId, detail?.status, executing]);

  const handleExecute = async (demo: boolean = false) => {
    setExecuting(true);
    try {
      // Optimistically mark as in progress
      if (detail) {
        setDetail({ ...detail, status: 'IN_PROGRESS' });
      }
      await api.executeInvestigation(investigationId, demo);
      await loadAll(false);
    } catch (err: any) {
      alert(`Execution failed: ${err.message}`);
    } finally {
      setExecuting(false);
    }
  };

  if (loading || !detail) {
    return (
      <div className="container" style={{ textAlign: 'center', padding: '80px 0', color: 'var(--text-muted)' }}>
        <Loader2 size={32} className="spin" style={{ margin: '0 auto 16px', color: 'var(--accent-blue)' }} />
        <div>Connecting to Forensic Case {investigationId}...</div>
      </div>
    );
  }

  const isOngoing = executing || detail.status === 'IN_PROGRESS' || detail.status === 'EXECUTING';

  return (
    <div className="container">
      {/* Top Breadcrumb Navigation */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button className="btn btn-secondary btn-sm" onClick={onBack}>
            <ArrowLeft size={13} /> Back to Dashboard
          </button>
          <span style={{ color: 'var(--text-dim)' }}>/</span>
          <span style={{ fontFamily: 'monospace', color: 'var(--accent-blue)', fontWeight: 600 }}>{detail.id}</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 12, color: 'var(--text-dim)' }}>
          <span>Last synced: {formatTime(lastSynced.toISOString())}</span>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => loadAll(false)}
            disabled={isRefreshing}
            title="Refresh case state"
          >
            <RefreshCw size={13} className={isRefreshing ? 'spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Real-Time Live Execution Progression Banner */}
      {isOngoing && (
        <div style={{
          padding: '16px 20px',
          background: 'var(--active-live-bg)',
          border: 'var(--active-live-border)',
          borderRadius: 10,
          marginBottom: 20,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 16,
          boxShadow: '0 4px 16px rgba(2, 132, 199, 0.1)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{
              width: 36,
              height: 36,
              borderRadius: '50%',
              background: 'rgba(2, 132, 199, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-blue)'
            }}>
              <Activity size={20} className="pulse" />
            </div>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <span>Autonomous Forensic Triage Active</span>
                <span className="badge badge-valid" style={{ fontSize: 11 }}>
                  LIVE OS TELEMETRY
                </span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                Executing read-only collectors &bull; Evaluating correlation rules &bull; Multi-round adaptive escalation...
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 12, color: 'var(--accent-blue)', fontFamily: 'monospace', fontWeight: 600 }}>
              {rounds.length} {rounds.length === 1 ? 'Round Active' : 'Rounds Active'} &bull; {artifacts.length} Artifacts
            </span>
            <Loader2 size={16} className="spin" color="var(--accent-blue)" />
          </div>
        </div>
      )}

      {/* Case Header Card */}
      <div className="glass-panel" style={{ padding: '24px 28px', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <span className={`badge ${detail.status === 'COMPLETED' ? 'badge-completed' : isOngoing ? 'badge-in-progress' : 'badge-neutral'}`}>
                {detail.status === 'COMPLETED' ? (
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <CheckCircle2 size={12} /> COMPLETED &bull; CONVERGED
                  </span>
                ) : isOngoing ? (
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Loader2 size={12} className="spin" /> EXECUTING
                  </span>
                ) : detail.status}
              </span>

              <span className="badge badge-neutral" style={{ fontSize: 12 }}>
                {rounds.length || detail.total_rounds} {rounds.length === 1 ? 'Round' : 'Rounds'}
              </span>

              {detail.metrics.escalation_triggered && (
                <span className="badge badge-warning" style={{ fontSize: 12 }}>
                  <Zap size={12} /> Adaptive Escalation Triggered
                </span>
              )}
            </div>

            <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-main)', marginBottom: 6 }}>
              {detail.intent}
            </h1>

            <div style={{ display: 'flex', alignItems: 'center', gap: 20, fontSize: 12, color: 'var(--text-muted)', flexWrap: 'wrap' }}>
              <span>Case ID: <code style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>{detail.id}</code></span>
              <span>Target Machine: <strong style={{ color: 'var(--text-main)' }}>{detail.machine_id}</strong></span>
              <span>Initiated: <strong style={{ color: 'var(--text-main)' }}>{formatDateTime(detail.created_at)}</strong></span>
              {detail.end_time && (
                <span>Completed: <strong style={{ color: 'var(--accent-emerald)' }}>{formatDateTime(detail.end_time)}</strong></span>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            {detail.status === 'CREATED' && (
              <button
                className="btn btn-primary"
                onClick={() => handleExecute(false)}
                disabled={isOngoing}
                title="Execute safe read-only collectors directly against your host machine"
                style={{ display: 'flex', alignItems: 'center', gap: 8 }}
              >
                <Play size={14} />
                Run Live Forensic Investigation
              </button>
            )}

            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setActiveTab('report')}
            >
              <FileText size={14} />
              View Full Report
            </button>
          </div>
        </div>

        {/* Quick Metrics Strip */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16, marginTop: 24, paddingTop: 20, borderTop: '1px solid var(--border-subtle)' }}>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Evidence Artifacts</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-main)', marginTop: 2 }}>{artifacts.length}</div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Indicators Matched</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: correlations.length > 0 ? 'var(--accent-amber)' : 'var(--accent-emerald)', marginTop: 2 }}>
              {correlations.length}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Timeline Events</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-main)', marginTop: 2 }}>{timeline.length}</div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Provenance Ledger</div>
            <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--accent-emerald)', marginTop: 2 }}>{provenance.length} Records</div>
          </div>
        </div>
      </div>

      {/* Forensic Chain of Custody & Cryptographic Integrity 2.0 Banner */}
      <div style={{ marginBottom: 24 }}>
        <ChainIntegrityCard
          investigationId={investigationId}
          isCompleted={detail.status === 'COMPLETED'}
          onRefresh={() => loadAll(false)}
        />
      </div>

      {/* Navigation Tabs */}
      <div className="tabs-nav">
        <button className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
          <Shield size={15} /> Overview
        </button>
        <button className={`tab-btn ${activeTab === 'graph' ? 'active' : ''}`} onClick={() => setActiveTab('graph')}>
          <GitBranch size={15} /> Evidence Graph
        </button>
        <button className={`tab-btn ${activeTab === 'workflow' ? 'active' : ''}`} onClick={() => setActiveTab('workflow')}>
          <ListOrdered size={15} /> Workflow Steps ({planData?.workflow_steps?.length || 0})
        </button>
        <button className={`tab-btn ${activeTab === 'evidence' ? 'active' : ''}`} onClick={() => setActiveTab('evidence')}>
          <FileJson size={15} /> Evidence ({artifacts.length})
        </button>
        <button className={`tab-btn ${activeTab === 'correlations' ? 'active' : ''}`} onClick={() => setActiveTab('correlations')}>
          <AlertTriangle size={15} /> Indicators ({correlations.length})
        </button>
        <button className={`tab-btn ${activeTab === 'timeline' ? 'active' : ''}`} onClick={() => setActiveTab('timeline')}>
          <Clock size={15} /> Timeline ({timeline.length})
        </button>
        <button className={`tab-btn ${activeTab === 'provenance' ? 'active' : ''}`} onClick={() => setActiveTab('provenance')}>
          <ShieldCheck size={15} /> Provenance ({provenance.length})
        </button>
        <button className={`tab-btn ${activeTab === 'report' ? 'active' : ''}`} onClick={() => setActiveTab('report')}>
          <FileText size={15} /> Final Report
        </button>
      </div>

      {/* Tab Panels */}
      {activeTab === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Executive Summary Card */}
          <div className="glass-panel" style={{ padding: 24 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)', marginBottom: 12 }}>
              Investigation Execution Summary
            </h3>
            <p style={{ fontSize: 14, color: 'var(--text-muted)', lineHeight: 1.6 }}>
              {detail.summary || (isOngoing ? 'Forensic triage is actively executing across rounds...' : 'Investigation initialized. Forensic collectors scheduled according to the evidence requirement graph.')}
            </p>

            {detail.metrics.escalation_triggered && (
              <div style={{ marginTop: 16, padding: '14px 18px', background: 'rgba(217, 119, 6, 0.08)', border: '1px solid var(--accent-amber)', borderRadius: 8 }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-amber)', display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <Zap size={16} />
                  Adaptive Workflow Expansion Milestone
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-main)', lineHeight: 1.5 }}>
                  The correlation engine matched an investigative indicator in Round 1 telemetry. The adaptive engine compiled and executed additional targeted collection operations (Round 2+) without requiring manual intervention, preserving complete cryptographic provenance.
                </div>
              </div>
            )}
          </div>

          {/* Investigation Rounds Overview */}
          <div className="glass-panel" style={{ padding: 24 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-main)', marginBottom: 16 }}>
              Execution Rounds Progression ({rounds.length})
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
              {rounds.map(r => (
                <div key={r.id} style={{
                  padding: 18,
                  borderRadius: 8,
                  background: r.round_number > 1 ? 'rgba(217, 119, 6, 0.08)' : 'var(--bg-item)',
                  border: r.round_number > 1 ? '1px solid rgba(217, 119, 6, 0.4)' : '1px solid var(--border-subtle)'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                    <span className={`badge ${r.round_number > 1 ? 'badge-warning' : 'badge-in-progress'}`}>
                      ROUND {r.round_number}
                    </span>
                    <span className={`badge ${r.status === 'COMPLETED' ? 'badge-completed' : 'badge-in-progress'}`}>{r.status}</span>
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', marginBottom: 6 }}>
                    {r.trigger_reason}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-muted)', marginTop: 12, paddingTop: 10, borderTop: '1px solid var(--border-subtle)' }}>
                    <span>{r.artifacts_count} Artifacts</span>
                    <span>{r.correlation_matches_count} Correlations</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'graph' && planData?.evidence_graph && (
        <EvidenceGraphView graph={planData.evidence_graph} />
      )}

      {activeTab === 'workflow' && (
        <WorkflowStepsView steps={planData?.workflow_steps || []} />
      )}

      {activeTab === 'evidence' && (
        <ArtifactsTable
          artifacts={artifacts}
          investigationId={investigationId}
          onRefresh={() => loadAll(false)}
        />
      )}

      {activeTab === 'correlations' && (
        <CorrelationsView correlations={correlations} />
      )}

      {activeTab === 'timeline' && (
        <TimelineView events={timeline} />
      )}

      {activeTab === 'provenance' && (
        <ProvenanceTable records={provenance} />
      )}

      {activeTab === 'report' && (
        <ReportView investigationId={investigationId} isOngoing={isOngoing} />
      )}
    </div>
  );
};
