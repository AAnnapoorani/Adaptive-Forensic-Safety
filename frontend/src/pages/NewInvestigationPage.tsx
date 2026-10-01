import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type { Machine, PlanPreview } from '../types';
import { EvidenceGraphView } from '../components/EvidenceGraphView';
import { Play, Eye, Code, Server, Sparkles, AlertCircle, Layers, FileCode, Copy, Check } from 'lucide-react';

interface NewInvestigationPageProps {
  onInvestigationStarted: (id: string) => void;
  onCancel: () => void;
}

const TEMPLATES: Record<string, string> = {
  suspicious_network_activity: `INVESTIGATE suspicious_network_activity
TARGET "JOCKY-93358801DA45"
ROUND_LIMIT 3
OPTIONS {
  stealth_mode: true,
  evidence_level: "comprehensive"
}
`,
  possible_malware_execution: `# Investigative Intent: Possible Malware Execution
# Examines recently dropped executables, command line parameters,
# parent-child lineages, and system event logs.

INVESTIGATE possible_malware_execution
TARGET "JOCKY-93358801DA45"
ROUND_LIMIT 2
`,
  system_compromise: `# Investigative Intent: System Compromise Assessment
# Full forensic triage across user accounts, active sockets,
# process trees, and audit events.

INVESTIGATE system_compromise
TARGET "JOCKY-93358801DA45"
ROUND_LIMIT 3
`,
  kernel_evasion_analysis: `# Investigative Intent: Kernel-Level Evasion & BYOVD Detection
# Enumerates ALL loaded kernel-mode drivers via direct Win32
# EnumDeviceDrivers (ctypes, low EDR visibility) and cross-references
# each against a curated CVE-linked BYOVD vulnerability database.

INVESTIGATE kernel_evasion_analysis
ROUND_LIMIT 2
`,
  memory_injection_hunt: `# Investigative Intent: In-Memory Code Injection Hunt
# Scans all process virtual address spaces via direct VirtualQueryEx
# (ctypes kernel32) to detect private committed executable regions.

INVESTIGATE memory_injection_hunt
ROUND_LIMIT 2
`,
  byovd_detection: `# Investigative Intent: BYOVD Full-Spectrum Detection
# Combined kernel driver enumeration + in-memory injection scan
# + process lineage analysis. Full-spectrum detection of BYOVD attacks.

INVESTIGATE byovd_detection
ROUND_LIMIT 3
`,
  manual: `# Custom Forensic Workflow Script
# Specify explicit forensic collector primitives

SYSTEM.INFO
PROCESS.LIST
NETWORK.CONNECTIONS
DNS.INFO
FILES.RECENT
TIMELINE.CREATE
REPORT.GENERATE
`
};

const KNOWN_INTENTS: string[] = [
  'suspicious_network_activity',
  'possible_malware_execution',
  'system_compromise',
  'kernel_evasion_analysis',
  'memory_injection_hunt',
  'byovd_detection',
];

const detectIntentFromScript = (code: string): string => {
  const lines = code.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
    const match = trimmed.match(/^INVESTIGATE\s+([a-zA-Z0-9_]+)/i);
    if (match) {
      const parsedIntent = match[1].toLowerCase();
      if (KNOWN_INTENTS.includes(parsedIntent)) {
        return parsedIntent;
      }
    }
  }
  return 'manual';
};

const detectTargetFromScript = (code: string): string | null => {
  const lines = code.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
    const match = trimmed.match(/^TARGET\s+["']?([a-zA-Z0-9_\-\.]+)["']?/i);
    if (match) {
      return match[1];
    }
  }
  return null;
};

export const NewInvestigationPage: React.FC<NewInvestigationPageProps> = ({
  onInvestigationStarted,
  onCancel
}) => {
  const [intent, setIntent] = useState<string>('suspicious_network_activity');
  const [script, setScript] = useState<string>(TEMPLATES['suspicious_network_activity']);
  const [machines, setMachines] = useState<Machine[]>([]);
  const [selectedMachine, setSelectedMachine] = useState<string>('');
  const [previewPlan, setPreviewPlan] = useState<PlanPreview | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [irViewTab, setIrViewTab] = useState<'ir' | 'tokens'>('ir');
  const [copiedIr, setCopiedIr] = useState(false);

  useEffect(() => {
    api.getMachines().then(res => {
      setMachines(res);
      if (res.length > 0) {
        const scriptTarget = detectTargetFromScript(script);
        const match = scriptTarget ? res.find(m => m.id === scriptTarget || m.hostname === scriptTarget) : null;
        setSelectedMachine(match ? match.id : res[0].id);
      }
    }).catch(console.error);
  }, []);

  const handleIntentChange = (newIntent: string) => {
    setIntent(newIntent);
    if (TEMPLATES[newIntent]) {
      setScript(TEMPLATES[newIntent]);
      const scriptTarget = detectTargetFromScript(TEMPLATES[newIntent]);
      if (scriptTarget && machines.length > 0) {
        const match = machines.find(m => m.id === scriptTarget || m.hostname === scriptTarget);
        if (match) setSelectedMachine(match.id);
      }
    }
  };

  const handleScriptChange = (newScript: string) => {
    setScript(newScript);
    const detected = detectIntentFromScript(newScript);
    setIntent(detected);
    const scriptTarget = detectTargetFromScript(newScript);
    if (scriptTarget && machines.length > 0) {
      const match = machines.find(m => m.id === scriptTarget || m.hostname === scriptTarget);
      if (match) setSelectedMachine(match.id);
    }
  };

  const handlePreview = async () => {
    setError(null);
    setLoadingPreview(true);
    try {
      const preview = await api.previewScript({
        intent,
        script
      });
      setPreviewPlan(preview);
    } catch (err: any) {
      setError(`DSL Compilation Error: ${err.message}`);
      setPreviewPlan(null);
    } finally {
      setLoadingPreview(false);
    }
  };


  const handleExecute = async () => {
    setError(null);
    setExecuting(true);
    try {
      // 1. Create investigation
      const inv = await api.createInvestigation({
        intent,
        script,
        machine_id: selectedMachine
      });

      // 2. Immediately transition to detail page so user sees live execution stream
      onInvestigationStarted(inv.id);

      // 3. Launch live OS telemetry execution
      api.executeInvestigation(inv.id, false).catch((err: any) => {
        console.error("Background execution error:", err);
      });
    } catch (err: any) {
      setError(`Failed to create investigation: ${err.message}`);
      setExecuting(false);
    }
  };

  return (
    <div className="container" style={{ maxWidth: 1100 }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Sparkles size={22} color="var(--accent-blue)" />
          Initiate Intent-Driven Forensic Investigation
        </h1>
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
          Specify your investigative objective. SUVADU will parse the intent, construct an evidence graph, compile the initial workflow, and dynamically adapt upon detecting correlation indicators.
        </p>
      </div>

      {error && (
        <div style={{ padding: '12px 16px', background: 'rgba(244, 63, 94, 0.15)', border: '1px solid rgba(244, 63, 94, 0.4)', borderRadius: 8, color: '#fb7185', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
          <AlertCircle size={16} />
          <span>{error}</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 24 }}>
        {/* Left Column: Intent Selector & JOCKY Script Editor */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Intent Card */}
          <div className="glass-panel" style={{ padding: 20 }}>
            <label style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)', display: 'block', marginBottom: 8 }}>
              Investigation Intent (Primary Objective)
            </label>
            <select
              value={intent}
              onChange={e => handleIntentChange(e.target.value)}
              style={{
                width: '100%',
                background: 'var(--bg-input)',
                color: 'var(--text-main)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 8,
                padding: '10px 14px',
                fontSize: 14,
                fontWeight: 500
              }}
            >
              <option value="suspicious_network_activity">INVESTIGATE suspicious_network_activity (Beaconing / C2)</option>
              <option value="possible_malware_execution">INVESTIGATE possible_malware_execution (Dropped Executables)</option>
              <option value="system_compromise">INVESTIGATE system_compromise (Full Host Triage)</option>
              <optgroup label="── Evasion & Kernel Forensics ──">
                <option value="kernel_evasion_analysis">INVESTIGATE kernel_evasion_analysis (BYOVD Driver Scan)</option>
                <option value="memory_injection_hunt">INVESTIGATE memory_injection_hunt (In-Memory Injection)</option>
                <option value="byovd_detection">INVESTIGATE byovd_detection (BYOVD Full-Spectrum)</option>
              </optgroup>
              <option value="manual">Manual Forensic Primitive Script</option>
            </select>
          </div>

          {/* JOCKY Script Editor */}
          <div className="glass-panel" style={{ padding: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
              <label style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Code size={16} color="var(--accent-blue)" />
                SUVADU Script Editor
              </label>
              <span className="badge badge-in-progress" style={{ fontSize: 10 }}>DSL v1.0</span>
            </div>

            <textarea
              value={script}
              onChange={e => handleScriptChange(e.target.value)}
              rows={9}
              style={{
                width: '100%',
                background: 'var(--bg-code)',
                color: 'var(--text-code)',
                fontFamily: 'Fira Code, monospace',
                fontSize: 13,
                padding: 14,
                borderRadius: 8,
                border: '1px solid var(--border-subtle)',
                lineHeight: 1.5,
                resize: 'vertical'
              }}
            />
            <p style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 8 }}>
              Supports high-level directives (<code>INVESTIGATE ...</code>) and forensic primitives (<code>SYSTEM.INFO</code>, <code>PROCESS.LIST</code>, <code>FILE.HASH "path"</code>, etc.).
            </p>
          </div>
        </div>

        {/* Right Column: Target Machine & Execution Controls */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Machine Selection */}
          <div className="glass-panel" style={{ padding: 20 }}>
            <label style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
              <Server size={16} color="#06b6d4" />
              Target Endpoint
            </label>
            <select
              value={selectedMachine}
              onChange={e => setSelectedMachine(e.target.value)}
              style={{
                width: '100%',
                background: 'var(--bg-input)',
                color: 'var(--text-main)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 8,
                padding: '10px 14px',
                fontSize: 13
              }}
            >
              {machines.map(m => (
                <option key={m.id} value={m.id}>
                  {m.hostname} ({m.os_name}) - {m.id}
                </option>
              ))}
            </select>
          </div>

          {/* Execution Environment Selector */}
          <div className="glass-panel" style={{ padding: 18 }}>
            <label style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)', display: 'block', marginBottom: 10 }}>
              Forensic Execution Mode
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 10,
                padding: '12px 14px',
                borderRadius: 6,
                background: 'rgba(56, 189, 248, 0.1)',
                border: '1px solid var(--accent-blue)',
              }}>
                <div style={{ marginTop: 2 }}>
                  <span className="badge badge-valid" style={{ fontSize: 9 }}>● LIVE OS</span>
                </div>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    Real-time System Endpoint Collection
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                    Executes live forensic telemetry collection (processes, network sockets, file artifacts, system event logs) directly from target endpoint.
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <button
              className="btn btn-secondary"
              onClick={handlePreview}
              disabled={loadingPreview || executing}
              style={{ width: '100%', padding: '12px 16px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, fontWeight: 600 }}
            >
              <Eye size={16} />
              {loadingPreview ? 'Compiling & Previewing Plan...' : 'Compile & Preview Plan'}
            </button>

            <button
              className="btn btn-primary"
              onClick={handleExecute}
              disabled={executing || loadingPreview}
              style={{ width: '100%', padding: '12px 16px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
            >
              <Play size={16} />
              {executing ? 'Executing Investigation...' : 'Launch Investigation'}
            </button>

            <button
              className="btn btn-secondary"
              onClick={onCancel}
              style={{ width: '100%', padding: '8px 16px', background: 'transparent', border: 'none', color: 'var(--text-dim)' }}
            >
              Cancel
            </button>
          </div>
        </div>
      </div>

      {/* Plan Preview Section */}
      {previewPlan && (
        <div style={{ marginTop: 30, paddingTop: 24, borderTop: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                <span className="badge badge-in-progress" style={{ fontSize: 11, textTransform: 'uppercase' }}>Dry-Run Preview</span>
                <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>Plan lower-bound verified before execution</span>
              </div>
              <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-main)' }}>
                Forensic Workflow Preview Plan & Evidence Requirement Graph
              </h2>
            </div>
            <button
              className="btn btn-primary btn-sm"
              onClick={handleExecute}
              disabled={executing}
              style={{ display: 'flex', alignItems: 'center', gap: 6 }}
            >
              <Play size={14} /> Launch Investigation
            </button>
          </div>

          {/* Parsed Intent & Initial Operations Highlights */}
          <div className="glass-panel" style={{ padding: 16, marginBottom: 20, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
            <div>
              <span style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, fontWeight: 600 }}>
                Parsed Intent
              </span>
              <div style={{ marginTop: 4, fontSize: 14, fontWeight: 700, color: 'var(--accent-blue)' }}>
                {previewPlan.intent}
              </div>
            </div>

            {previewPlan.ir?.target_id && (
              <div>
                <span style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, fontWeight: 600 }}>
                  Target Endpoint
                </span>
                <div style={{ marginTop: 4, fontSize: 13, fontWeight: 600, color: 'var(--text-main)', fontFamily: 'Fira Code, monospace' }}>
                  {previewPlan.ir.target_id}
                </div>
              </div>
            )}

            {previewPlan.ir?.round_limit && (
              <div>
                <span style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, fontWeight: 600 }}>
                  Round Limit
                </span>
                <div style={{ marginTop: 4, fontSize: 13, fontWeight: 700, color: '#10b981' }}>
                  {previewPlan.ir.round_limit} Rounds Max
                </div>
              </div>
            )}

            <div>
              <span style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5, fontWeight: 600 }}>
                Initial Operations ({previewPlan.initial_operations?.length || previewPlan.workflow.steps.length})
              </span>
              <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {(previewPlan.initial_operations || previewPlan.workflow.steps.map(s => s.operation)).map((op) => (
                  <span
                    key={op}
                    style={{
                      fontSize: 11,
                      fontFamily: 'Fira Code, monospace',
                      padding: '3px 8px',
                      borderRadius: 4,
                      background: 'var(--bg-item)',
                      border: '1px solid var(--border-subtle)',
                      color: 'var(--accent-blue)',
                      fontWeight: 600
                    }}
                  >
                    {op}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Split-Screen: Left: Lexer/Parser IR JSON Structure | Right: Evidence Requirement Graph (DAG) */}
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(340px, 420px) 1fr', gap: 20, marginBottom: 24, alignItems: 'stretch' }}>
            {/* Left Column: Compiler Intermediate Representation (IR) */}
            <div className="glass-panel" style={{ padding: 18, display: 'flex', flexDirection: 'column', height: '100%', minHeight: 480 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Layers size={16} color="var(--accent-blue)" />
                  <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)' }}>
                    Compiler Intermediate Representation (IR)
                  </span>
                </div>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(JSON.stringify(previewPlan.ir || {}, null, 2));
                    setCopiedIr(true);
                    setTimeout(() => setCopiedIr(false), 2000);
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                    background: 'var(--bg-item)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 4,
                    padding: '3px 8px',
                    fontSize: 11,
                    color: 'var(--text-muted)',
                    cursor: 'pointer'
                  }}
                  title="Copy IR JSON"
                >
                  {copiedIr ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                  <span>{copiedIr ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              {/* View Toggle Tabs */}
              <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
                <button
                  onClick={() => setIrViewTab('ir')}
                  style={{
                    padding: '4px 10px',
                    fontSize: 11,
                    fontWeight: 600,
                    borderRadius: 4,
                    border: irViewTab === 'ir' ? '1px solid var(--accent-blue)' : '1px solid var(--border-subtle)',
                    background: irViewTab === 'ir' ? 'rgba(56, 189, 248, 0.15)' : 'var(--bg-item)',
                    color: irViewTab === 'ir' ? 'var(--accent-blue)' : 'var(--text-muted)',
                    cursor: 'pointer'
                  }}
                >
                  <FileCode size={11} style={{ display: 'inline', marginRight: 4 }} />
                  IR Structure
                </button>
                <button
                  onClick={() => setIrViewTab('tokens')}
                  style={{
                    padding: '4px 10px',
                    fontSize: 11,
                    fontWeight: 600,
                    borderRadius: 4,
                    border: irViewTab === 'tokens' ? '1px solid var(--accent-blue)' : '1px solid var(--border-subtle)',
                    background: irViewTab === 'tokens' ? 'rgba(56, 189, 248, 0.15)' : 'var(--bg-item)',
                    color: irViewTab === 'tokens' ? 'var(--accent-blue)' : 'var(--text-muted)',
                    cursor: 'pointer'
                  }}
                >
                  Lexer Tokens ({previewPlan.tokens?.length || 0})
                </button>
              </div>

              {/* IR / Tokens Content Display */}
              <div style={{
                flex: 1,
                background: 'var(--bg-code, #090d16)',
                borderRadius: 8,
                padding: 12,
                border: '1px solid var(--border-subtle)',
                overflowY: 'auto',
                maxHeight: 520
              }}>
                {irViewTab === 'ir' ? (
                  <pre style={{
                    margin: 0,
                    fontFamily: 'Fira Code, monospace',
                    fontSize: 12,
                    lineHeight: 1.5,
                    color: '#e2e8f0',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all'
                  }}>
                    {JSON.stringify(previewPlan.ir || { intent: previewPlan.intent, operations: previewPlan.initial_operations }, null, 2)}
                  </pre>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {(previewPlan.tokens || []).map((tok, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 11, fontFamily: 'Fira Code, monospace', padding: '2px 6px', background: 'rgba(255,255,255,0.03)', borderRadius: 3 }}>
                        <span style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>{tok.type}</span>
                        <span style={{ color: '#f1f5f9' }}>{JSON.stringify(tok.value)}</span>
                        <span style={{ color: 'var(--text-dim)', fontSize: 10 }}>L{tok.line}:C{tok.column}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {previewPlan.ir?.options && Object.keys(previewPlan.ir.options).length > 0 && (
                <div style={{ marginTop: 12, padding: '8px 12px', background: 'var(--bg-item)', borderRadius: 6, border: '1px solid var(--border-subtle)', fontSize: 11 }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Resolved Options:</span>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {Object.entries(previewPlan.ir.options).map(([k, v]) => (
                      <span key={k} className="badge badge-neutral" style={{ fontSize: 10 }}>
                        {k}: {String(v)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Right Column: Evidence Requirement Graph (DAG) */}
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <div style={{ marginBottom: 10, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)', margin: 0 }}>
                  Evidence Requirement Graph (DAG)
                </h3>
                <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>
                  Interactive Nodes & Pre-execution Dependencies
                </span>
              </div>
              <EvidenceGraphView graph={previewPlan.evidence_graph} />
            </div>
          </div>

          {/* Planned Workflow Table */}
          <div className="glass-panel" style={{ padding: 16 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)', marginBottom: 12 }}>
              Expected Workflow Execution Order
            </h3>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 60 }}>Priority</th>
                  <th>Operation</th>
                  <th>Reason / Justification</th>
                  <th>Dependencies</th>
                  <th style={{ width: 100 }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {previewPlan.workflow.steps.map((st) => (
                  <tr key={st.step_id || st.operation}>
                    <td style={{ fontWeight: 700, color: 'var(--accent-blue)' }}>#{st.priority}</td>
                    <td>
                      <code style={{ fontSize: 12, color: 'var(--text-main)', fontWeight: 600 }}>{st.operation}</code>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{st.reason}</td>
                    <td>
                      {st.dependencies && st.dependencies.length > 0 ? (
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {st.dependencies.map((d) => (
                            <span key={d} className="badge badge-neutral" style={{ fontSize: 10 }}>
                              {d}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>None (Root)</span>
                      )}
                    </td>
                    <td>
                      <span className="badge badge-neutral" style={{ fontSize: 10 }}>
                        {st.status || 'SCHEDULED'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
