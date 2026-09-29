import React, { useState } from 'react';
import type { EvidenceGraph, EvidenceNode } from '../types';
import { Network, Cpu, HardDrive, ShieldCheck, GitBranch, ArrowRight, Zap } from 'lucide-react';

interface EvidenceGraphViewProps {
  graph: EvidenceGraph;
}

export const EvidenceGraphView: React.FC<EvidenceGraphViewProps> = ({ graph }) => {
  const [selectedNode, setSelectedNode] = useState<EvidenceNode | null>(null);

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'PROCESS': return <Cpu size={16} color="#38bdf8" />;
      case 'NETWORK': return <Network size={16} color="#06b6d4" />;
      case 'STORAGE': return <HardDrive size={16} color="#a855f7" />;
      case 'AUDIT': return <ShieldCheck size={16} color="#10b981" />;
      default: return <GitBranch size={16} color="#94a3b8" />;
    }
  };

  const getCategoryBorder = (category: string, isAdaptive: boolean) => {
    if (isAdaptive) return '1px solid #f59e0b';
    switch (category) {
      case 'PROCESS': return '1px solid rgba(56, 189, 248, 0.4)';
      case 'NETWORK': return '1px solid rgba(6, 182, 212, 0.4)';
      case 'STORAGE': return '1px solid rgba(168, 85, 247, 0.4)';
      case 'AUDIT': return '1px solid rgba(16, 185, 129, 0.4)';
      default: return '1px solid var(--border-subtle)';
    }
  };

  // Group nodes by round
  const round1Nodes = graph.nodes.filter(n => n.round_number === 1);
  const adaptiveNodes = graph.nodes.filter(n => n.round_number > 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Legend & Stats Banner */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, padding: '12px 18px', background: 'var(--bg-item)', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 18, fontSize: 13 }}>
          <span style={{ color: 'var(--text-muted)' }}>Graph Metrics:</span>
          <span><strong>{graph.total_nodes}</strong> Evidence Nodes</span>
          <span><strong>{graph.total_edges}</strong> Relational Edges</span>
          <span>Intent: <strong style={{ color: 'var(--accent-blue)' }}>{graph.intent}</strong></span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16, fontSize: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: 'rgba(2, 132, 199, 0.2)', border: '1px solid var(--accent-blue)' }} />
            <span style={{ color: 'var(--text-main)', fontWeight: 500 }}>Initial Requirement (Round 1)</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: 'rgba(217, 119, 6, 0.2)', border: '1px solid var(--accent-amber)' }} />
            <span style={{ color: 'var(--accent-amber)', fontWeight: 700 }}>Adaptive Expansion (Round 2+)</span>
          </div>
        </div>
      </div>

      {/* Visual Canvas Representation */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedNode ? '1fr 340px' : '1fr', gap: 20 }}>
        <div className="glass-panel" style={{ padding: 24, minHeight: 460 }}>
          {/* Round 1 Section */}
          <div style={{ marginBottom: 30 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
              <span className="badge badge-in-progress">ROUND 1</span>
              <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-main)' }}>Compiled Evidence Baseline</span>
              <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>({round1Nodes.length} nodes)</span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14 }}>
              {round1Nodes.map(node => (
                <div
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  style={{
                    padding: '14px 16px',
                    borderRadius: 8,
                    background: selectedNode?.id === node.id ? 'rgba(56, 189, 248, 0.12)' : 'var(--bg-item)',
                    border: selectedNode?.id === node.id ? '2px solid var(--accent-blue)' : getCategoryBorder(node.category, false),
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    boxShadow: selectedNode?.id === node.id ? '0 0 15px rgba(56, 189, 248, 0.3)' : undefined
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      {getCategoryIcon(node.category)}
                      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>{node.category}</span>
                    </div>
                    <span className={`badge ${node.status === 'COLLECTED' ? 'badge-completed' : 'badge-neutral'}`} style={{ fontSize: 10 }}>
                      {node.status}
                    </span>
                  </div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-main)', marginBottom: 4 }}>{node.operation}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>{node.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Adaptive Escalation Section */}
          {adaptiveNodes.length > 0 && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <span className="badge badge-warning">
                  <Zap size={12} />
                  ADAPTIVE EXPANSION
                </span>
                <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-main)' }}>Dynamically Generated Operations</span>
                <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>({adaptiveNodes.length} nodes)</span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14 }}>
                {adaptiveNodes.map(node => (
                  <div
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    style={{
                      padding: '14px 16px',
                      borderRadius: 8,
                      background: selectedNode?.id === node.id ? 'rgba(245, 158, 11, 0.15)' : 'var(--bg-item)',
                      border: selectedNode?.id === node.id ? '2px solid #f59e0b' : '1px solid rgba(245, 158, 11, 0.5)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      boxShadow: '0 0 12px rgba(245, 158, 11, 0.15)'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        {getCategoryIcon(node.category)}
                        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-amber)' }}>ROUND {node.round_number} ADAPTIVE</span>
                      </div>
                      <span className={`badge ${node.status === 'COLLECTED' ? 'badge-completed' : 'badge-warning'}`} style={{ fontSize: 10 }}>
                        {node.status}
                      </span>
                    </div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)', marginBottom: 4 }}>{node.operation}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{node.label}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Relationships / Edges List */}
          <div style={{ marginTop: 30, paddingTop: 20, borderTop: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Identified Graph Relationships ({graph.edges.length})
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {graph.edges.map((e, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px', background: 'var(--bg-item)', borderRadius: 6, fontSize: 12, border: '1px solid var(--border-subtle)' }}>
                  <span style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>{e.source.replace('node_', '').toUpperCase()}</span>
                  <span style={{ fontSize: 10, color: e.relationship === 'EXPANDS_TO' ? 'var(--accent-amber)' : 'var(--text-dim)', fontWeight: 700 }}>[{e.relationship}]</span>
                  <ArrowRight size={12} color="var(--text-dim)" />
                  <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>{e.target.replace('node_', '').toUpperCase()}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Selected Node Details Drawer */}
        {selectedNode && (
          <div className="glass-panel" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: 10 }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-muted)' }}>Node Inspection</span>
              <button
                style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: 14 }}
                onClick={() => setSelectedNode(null)}
              >
                ✕
              </button>
            </div>

            <div>
              <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-main)' }}>{selectedNode.operation}</div>
              <div style={{ fontSize: 13, color: 'var(--accent-blue)', marginTop: 2, fontWeight: 600 }}>{selectedNode.label}</div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
              <div>
                <span style={{ color: 'var(--text-dim)', display: 'block', fontSize: 11, marginBottom: 2, fontWeight: 600 }}>CATEGORY</span>
                <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>{selectedNode.category}</span>
              </div>

              <div>
                <span style={{ color: 'var(--text-dim)', display: 'block', fontSize: 11, marginBottom: 2, fontWeight: 600 }}>INVESTIGATION ROUND</span>
                <span className="badge badge-in-progress">Round {selectedNode.round_number}</span>
              </div>

              <div>
                <span style={{ color: 'var(--text-dim)', display: 'block', fontSize: 11, marginBottom: 2, fontWeight: 600 }}>STATUS</span>
                <span className={`badge ${selectedNode.status === 'COLLECTED' ? 'badge-completed' : 'badge-neutral'}`}>
                  {selectedNode.status}
                </span>
              </div>

              <div>
                <span style={{ color: 'var(--text-dim)', display: 'block', fontSize: 11, marginBottom: 2, fontWeight: 600 }}>REQUIREMENT RATIONALE</span>
                <div style={{ padding: '10px 12px', background: 'var(--bg-item)', borderRadius: 6, border: '1px solid var(--border-subtle)', color: 'var(--text-main)', fontSize: 12, lineHeight: 1.5 }}>
                  {selectedNode.reason}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
