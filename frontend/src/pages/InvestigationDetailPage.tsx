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
import { AiAnalystView } from '../components/AiAnalystView';
import { formatDateTime, formatTime } from '../utils/date';

import {
  Shield,
  GitBranch,
  ListOrdered,
  FileJson,
  Clock,
  ShieldCheck,
  FileText,
  Play,
  ArrowLeft,
  Zap,
  RefreshCw,
  Loader2,
  CheckCircle2,
  Activity,
  Sparkles,
  ShieldAlert
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
  const [workflowSubView, setWorkflowSubView] = useState<'dag' | 'steps'>('dag');

  const VALID_TABS = [
    'overview',
    'workflow',
    'evidence',
    'correlations',
    'timeline',
    'provenance',
    'ai-analyst',
    'report'
  ];

  const getTabFromUrl = (): string => {
    try {
      const searchParams = new URLSearchParams(window.location.search);
      const tabParam = searchParams.get('tab')?.toLowerCase();
      if (!tabParam) return 'overview';
      if (tabParam === 'graph' || tabParam === 'dag') return 'workflow';
      if (tabParam === 'artifacts') return 'evidence';
      if (tabParam === 'indicators') return 'correlations';
      if (tabParam === 'ai' || tabParam === 'aianalyst') return 'ai-analyst';
      if (tabParam === 'chain' || tabParam === 'ledger') return 'provenance';
      if (VALID_TABS.includes(tabParam)) return tabParam;
    } catch {
      // Fallback in case of parse error
    }
    return 'overview';
  };

  const [activeTab, setActiveTabState] = useState<string>(getTabFromUrl);

  const [showAiDrawer, setShowAiDrawer] = useState<boolean>(() => {
    try {
      const searchParams = new URLSearchParams(window.location.search);
      const tabParam = searchParams.get('tab')?.toLowerCase();
      return tabParam === 'ai' || tabParam === 'ai-analyst' || tabParam === 'aianalyst';
    } catch {
      return false;
    }
  });

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && showAiDrawer) {
        setShowAiDrawer(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showAiDrawer]);

  const setActiveTab = (tab: string) => {
    setActiveTabState(tab);
    try {
      const url = new URL(window.location.href);
      if (tab === 'overview') {
        url.searchParams.delete('tab');
      } else {
        url.searchParams.set('tab', tab);
      }
      window.history.replaceState({}, '', url.toString());
    } catch {
      // Silently ignore URL update error in restricted envs
    }
  };

  // Sync tab state when user navigates using browser Back/Forward buttons
  useEffect(() => {
    const handlePopState = () => {
      setActiveTabState(getTabFromUrl());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

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
              onClick={() => setShowAiDrawer(true)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 7,
                background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.12), rgba(147, 51, 234, 0.14))',
                border: '1px solid rgba(147, 51, 234, 0.45)',
                color: 'var(--text-main)',
                fontWeight: 600,
                boxShadow: '0 2px 8px rgba(147, 51, 234, 0.12)'
              }}
            >
              <Sparkles size={14} color="#a855f7" />
              AI Analyst
            </button>

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
        <button className={`tab-btn ${activeTab === 'workflow' ? 'active' : ''}`} onClick={() => setActiveTab('workflow')}>
          <ListOrdered size={15} /> Workflow Pipeline ({planData?.workflow_steps?.length || 0})
        </button>
        <button className={`tab-btn ${activeTab === 'evidence' ? 'active' : ''}`} onClick={() => setActiveTab('evidence')}>
          <FileJson size={15} /> Evidence ({artifacts.length})
        </button>
        <button className={`tab-btn ${activeTab === 'correlations' ? 'active' : ''}`} onClick={() => setActiveTab('correlations')}>
          <ShieldAlert size={15} /> Correlation & IoC Engine ({correlations.length})
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


      {activeTab === 'workflow' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Dynamic Milestone Badge & Sub-view Switcher Toolbar */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 12,
            padding: '14px 20px',
            background: 'var(--bg-panel)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 10
          }}>
            {/* Dynamic Milestone Status Badge */}
            <div>
              {isOngoing ? (
                <div style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '7px 16px',
                  borderRadius: 20,
                  background: 'rgba(56, 189, 248, 0.12)',
                  border: '1px solid rgba(56, 189, 248, 0.4)',
                  color: 'var(--accent-blue, #38bdf8)',
                  fontSize: 13,
                  fontWeight: 600
                }}>
                  <Loader2 size={15} className="spin" />
                  <span>Round {detail?.current_round || rounds.length || 1} Forensic Collection in Progress...</span>
                </div>
              ) : (detail?.metrics?.escalation_triggered || rounds.some(r => r.round_number > 1) || planData?.evidence_graph?.nodes?.some((n: any) => n.round_number > 1)) ? (
                <div style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '7px 18px',
                  borderRadius: 20,
                  background: 'linear-gradient(135deg, rgba(245, 158, 11, 0.15) 0%, rgba(168, 85, 247, 0.15) 100%)',
                  border: '1px solid rgba(245, 158, 11, 0.5)',
                  color: '#f59e0b',
                  fontSize: 13,
                  fontWeight: 600,
                  boxShadow: '0 2px 10px rgba(245, 158, 11, 0.1)'
                }}>
                  <Zap size={15} style={{ fill: '#f59e0b' }} />
                  <span>⚡ Round 2 Deeper Drilldown Completed &mdash; <strong style={{ color: '#fbbf24' }}>{artifacts.length} Artifacts Verified</strong></span>
                </div>
              ) : detail?.status === 'COMPLETED' ? (
                <div style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '7px 18px',
                  borderRadius: 20,
                  background: 'rgba(16, 185, 129, 0.12)',
                  border: '1px solid rgba(16, 185, 129, 0.4)',
                  color: '#10b981',
                  fontSize: 13,
                  fontWeight: 600,
                  boxShadow: '0 2px 10px rgba(16, 185, 129, 0.1)'
                }}>
                  <CheckCircle2 size={15} />
                  <span>✓ Round 1 Initial Triage Completed &mdash; <strong style={{ color: '#34d399' }}>{artifacts.length} Artifacts Verified</strong> (No Escalation Required)</span>
                </div>
              ) : (
                <div style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '7px 16px',
                  borderRadius: 20,
                  background: 'var(--bg-item)',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-muted)',
                  fontSize: 13,
                  fontWeight: 600
                }}>
                  <span>Forensic Workflow Initialized &bull; {planData?.workflow_steps?.length || 0} Steps Planned</span>
                </div>
              )}
            </div>

            {/* Sub-view Switcher Toggle */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              background: 'var(--bg-secondary)',
              padding: 3,
              borderRadius: 6,
              border: '1px solid var(--border-subtle)'
            }}>
              <button
                onClick={() => setWorkflowSubView('dag')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '6px 12px',
                  fontSize: 12,
                  fontWeight: 600,
                  borderRadius: 4,
                  cursor: 'pointer',
                  border: workflowSubView === 'dag' ? '1px solid var(--accent-blue)' : '1px solid transparent',
                  background: workflowSubView === 'dag' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                  color: workflowSubView === 'dag' ? 'var(--accent-blue)' : 'var(--text-muted)',
                  transition: 'all 0.15s ease'
                }}
              >
                <GitBranch size={13} />
                Evidence DAG Pipeline
              </button>
              <button
                onClick={() => setWorkflowSubView('steps')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '6px 12px',
                  fontSize: 12,
                  fontWeight: 600,
                  borderRadius: 4,
                  cursor: 'pointer',
                  border: workflowSubView === 'steps' ? '1px solid var(--accent-blue)' : '1px solid transparent',
                  background: workflowSubView === 'steps' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                  color: workflowSubView === 'steps' ? 'var(--accent-blue)' : 'var(--text-muted)',
                  transition: 'all 0.15s ease'
                }}
              >
                <ListOrdered size={13} />
                Steps Execution Ledger ({planData?.workflow_steps?.length || 0})
              </button>
            </div>
          </div>

          {/* Workflow Content: Either DAG Pipeline or Steps Ledger */}
          {workflowSubView === 'dag' ? (
            planData?.evidence_graph ? (
              <EvidenceGraphView graph={planData.evidence_graph} />
            ) : (
              <div className="glass-panel" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
                <Loader2 size={24} className="spin" style={{ margin: '0 auto 12px' }} />
                Loading Evidence Requirement Graph...
              </div>
            )
          ) : (
            <WorkflowStepsView steps={planData?.workflow_steps || []} />
          )}
        </div>
      )}

      {activeTab === 'evidence' && (
        <ArtifactsTable
          artifacts={artifacts}
          investigationId={investigationId}
          onRefresh={() => loadAll(false)}
        />
      )}

      {activeTab === 'correlations' && (
        <CorrelationsView
          correlations={correlations}
          investigationId={investigationId}
          onRefresh={() => loadAll(false)}
        />
      )}

      {activeTab === 'timeline' && (
        <TimelineView events={timeline} />
      )}

      {activeTab === 'provenance' && (
        <ProvenanceTable records={provenance} />
      )}

      {activeTab === 'ai-analyst' && (
        <AiAnalystView investigationId={investigationId} />
      )}

      {activeTab === 'report' && (
        <ReportView investigationId={investigationId} isOngoing={isOngoing} />
      )}

      {/* AI Forensic Analyst Slide-Over Drawer */}
      {showAiDrawer && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          zIndex: 1200,
          display: 'flex',
          justifyContent: 'flex-end',
          background: 'rgba(0, 0, 0, 0.55)',
          backdropFilter: 'blur(5px)',
          animation: 'fadeIn 0.2s ease'
        }}>
          {/* Backdrop Click Dismiss */}
          <div
            onClick={() => setShowAiDrawer(false)}
            style={{ flex: 1, cursor: 'pointer' }}
          />

          {/* Drawer Content */}
          <div style={{
            width: 'min(760px, 94vw)',
            height: '100%',
            background: 'var(--bg-main)',
            borderLeft: '1px solid var(--border-subtle)',
            boxShadow: '-10px 0 40px rgba(0, 0, 0, 0.45)',
            display: 'flex',
            flexDirection: 'column',
            position: 'relative',
            zIndex: 1201,
            animation: 'slideInRight 0.25s ease'
          }}>
            {/* Drawer Header */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '18px 24px',
              borderBottom: '1px solid var(--border-subtle)',
              background: 'var(--bg-secondary)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{
                  width: 36,
                  height: 36,
                  borderRadius: 8,
                  background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(147, 51, 234, 0.25))',
                  border: '1px solid rgba(147, 51, 234, 0.4)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0
                }}>
                  <Sparkles size={18} color="#a855f7" />
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <h3 style={{ fontSize: 16, fontWeight: 800, margin: 0, color: 'var(--text-main)' }}>
                      AI Forensic Analyst Copilot
                    </h3>
                    <span className="badge badge-success" style={{ fontSize: 10 }}>
                      Live Synthesis
                    </span>
                  </div>
                  <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: '2px 0 0' }}>
                    Automated MITRE ATT&CK Mapping • Root Cause Hypothesis • Behavioral Synthesis
                  </p>
                </div>
              </div>

              <button
                onClick={() => setShowAiDrawer(false)}
                style={{
                  background: 'rgba(255, 255, 255, 0.06)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 6,
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  fontSize: 15,
                  width: 32,
                  height: 32,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0
                }}
                title="Close AI Analyst (Esc)"
              >
                ✕
              </button>
            </div>

            {/* Drawer Body */}
            <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
              <AiAnalystView investigationId={investigationId} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
