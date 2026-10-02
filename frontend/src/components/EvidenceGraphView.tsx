import React, { useState } from 'react';
import type { EvidenceGraph, EvidenceNode } from '../types';
import { Network, Cpu, HardDrive, ShieldCheck, GitBranch, ArrowRight, Zap, Layers, X } from 'lucide-react';
import { EvidenceDAGCanvas } from './EvidenceDAGCanvas';

interface EvidenceGraphViewProps {
  graph: EvidenceGraph;
}

export const EvidenceGraphView: React.FC<EvidenceGraphViewProps> = ({ graph }) => {
  const [selectedNode, setSelectedNode] = useState<EvidenceNode | null>(null);
  const [viewMode, setViewMode] = useState<'dag' | 'cards'>('dag');

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'PROCESS': return <Cpu size={14} color="var(--accent-blue)" />;
      case 'NETWORK': return <Network size={14} color="var(--accent-cyan)" />;
      case 'STORAGE': return <HardDrive size={14} color="var(--accent-violet)" />;
      case 'AUDIT': return <ShieldCheck size={14} color="var(--accent-emerald)" />;
      default: return <GitBranch size={14} color="var(--text-muted)" />;
    }
  };

  const getCategoryBorder = (category: string, isAdaptive: boolean) => {
    if (isAdaptive) return '1px solid var(--accent-amber)';
    switch (category) {
      case 'PROCESS': return '1px solid rgba(56, 189, 248, 0.4)';
      case 'NETWORK': return '1px solid rgba(6, 182, 212, 0.4)';
      case 'STORAGE': return '1px solid rgba(168, 85, 247, 0.4)';
      case 'AUDIT': return '1px solid rgba(16, 185, 129, 0.4)';
      default: return '1px solid var(--border-subtle)';
    }
  };

  const round1Nodes = graph.nodes.filter(n => n.round_number === 1);
  const adaptiveNodes = graph.nodes.filter(n => n.round_number > 1);

  return (
    <div className="glass-panel" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 14, height: '100%' }}>
      {/* Subheader Toolbar with View Toggle */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 8,
        paddingBottom: 10,
        borderBottom: '1px solid var(--border-subtle)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
          <span style={{ color: 'var(--text-muted)', fontWeight: 500 }}>Objective Intent:</span>
          <span style={{ color: 'var(--accent-blue)', fontWeight: 700, fontFamily: 'Fira Code, monospace' }}>
            {graph.intent}
          </span>
        </div>

        {/* View Mode Toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'var(--bg-secondary)', padding: 3, borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
          <button
            onClick={() => setViewMode('dag')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 5,
              padding: '4px 10px',
              fontSize: 11,
              fontWeight: 600,
              borderRadius: 4,
              cursor: 'pointer',
              border: viewMode === 'dag' ? '1px solid var(--accent-blue)' : '1px solid transparent',
              background: viewMode === 'dag' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
              color: viewMode === 'dag' ? 'var(--accent-blue)' : 'var(--text-muted)',
              transition: 'all 0.15s ease'
            }}
          >
            <Network size={12} />
            Visual Topology DAG
          </button>
          <button
            onClick={() => setViewMode('cards')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 5,
              padding: '4px 10px',
              fontSize: 11,
              fontWeight: 600,
              borderRadius: 4,
              cursor: 'pointer',
              border: viewMode === 'cards' ? '1px solid var(--accent-blue)' : '1px solid transparent',
              background: viewMode === 'cards' ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
              color: viewMode === 'cards' ? 'var(--accent-blue)' : 'var(--text-muted)',
              transition: 'all 0.15s ease'
            }}
          >
            <Layers size={12} />
            Grouped Cards
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div>
        {viewMode === 'dag' ? (
          /* Visual DAG Topology View */
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <EvidenceDAGCanvas
              nodes={graph.nodes}
              edges={graph.edges}
              selectedNode={selectedNode}
              onSelectNode={setSelectedNode}
            />

            {/* Selected Node Details Card */}
            {selectedNode && (
              <div
                style={{
                  padding: '12px 16px',
                  background: 'var(--bg-item)',
                  borderRadius: 8,
                  border: '1px solid var(--border-focus)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8,
                  animation: 'fadeIn 0.2s ease-in-out'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    {getCategoryIcon(selectedNode.category)}
                    <span style={{ fontSize: 13, fontWeight: 700, fontFamily: 'Fira Code, monospace', color: 'var(--text-main)' }}>
                      {selectedNode.operation}
                    </span>
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      &mdash; {selectedNode.label}
                    </span>
                    <span className="badge badge-in-progress" style={{ fontSize: 10 }}>
                      Round {selectedNode.round_number}
                    </span>
                    <span className={`badge ${selectedNode.status === 'COLLECTED' ? 'badge-completed' : 'badge-neutral'}`} style={{ fontSize: 10 }}>
                      {selectedNode.status}
                    </span>
                  </div>
                  <button
                    onClick={() => setSelectedNode(null)}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-dim)',
                      cursor: 'pointer',
                      padding: 4,
                      display: 'flex',
                      alignItems: 'center',
                      borderRadius: 4
                    }}
                    title="Close inspection"
                  >
                    <X size={14} />
                  </button>
                </div>

                <div style={{ fontSize: 12, color: 'var(--text-main)', lineHeight: 1.5, background: 'var(--bg-secondary)', padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border-subtle)' }}>
                  <strong style={{ color: 'var(--text-muted)', marginRight: 6 }}>Requirement Rationale:</strong>
                  {selectedNode.reason}
                </div>
              </div>
            )}

            {/* Edge Relationships Pill Summary */}
            <div style={{ paddingTop: 8, borderTop: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Identified Graph Relationships ({graph.edges.length})
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {graph.edges.map((e, i) => (
                  <div
                    key={i}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                      padding: '4px 10px',
                      background: 'var(--bg-item)',
                      borderRadius: 6,
                      fontSize: 11,
                      border: '1px solid var(--border-subtle)'
                    }}
                  >
                    <span style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>{e.source.replace('node_', '').toUpperCase()}</span>
                    <span style={{ fontSize: 9, color: e.relationship === 'EXPANDS_TO' ? 'var(--accent-amber)' : 'var(--text-dim)', fontWeight: 700 }}>
                      [{e.relationship}]
                    </span>
                    <ArrowRight size={11} color="var(--text-dim)" />
                    <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>{e.target.replace('node_', '').toUpperCase()}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          /* Grouped Cards View */
          <div>
            <div style={{ marginBottom: 24 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                <span className="badge badge-in-progress">ROUND 1</span>
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)' }}>Compiled Evidence Baseline</span>
                <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>({round1Nodes.length} nodes)</span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
                {round1Nodes.map(node => (
                  <div
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    style={{
                      padding: '12px 14px',
                      borderRadius: 6,
                      background: selectedNode?.id === node.id ? 'rgba(56, 189, 248, 0.12)' : 'var(--bg-item)',
                      border: selectedNode?.id === node.id ? '2px solid var(--accent-blue)' : getCategoryBorder(node.category, false),
                      cursor: 'pointer',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        {getCategoryIcon(node.category)}
                        <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)' }}>{node.category}</span>
                      </div>
                      <span className={`badge ${node.status === 'COLLECTED' ? 'badge-completed' : 'badge-neutral'}`} style={{ fontSize: 9 }}>
                        {node.status}
                      </span>
                    </div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)', marginBottom: 2 }}>{node.operation}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>{node.label}</div>
                  </div>
                ))}
              </div>
            </div>

            {adaptiveNodes.length > 0 && (
              <div style={{ marginBottom: 24 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                  <span className="badge badge-warning">
                    <Zap size={11} /> ADAPTIVE EXPANSION
                  </span>
                  <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-main)' }}>Dynamically Generated Operations</span>
                  <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>({adaptiveNodes.length} nodes)</span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
                  {adaptiveNodes.map(node => (
                    <div
                      key={node.id}
                      onClick={() => setSelectedNode(node)}
                      style={{
                        padding: '12px 14px',
                        borderRadius: 6,
                        background: selectedNode?.id === node.id ? 'rgba(245, 158, 11, 0.15)' : 'var(--bg-item)',
                        border: selectedNode?.id === node.id ? '2px solid var(--accent-amber)' : '1px solid rgba(245, 158, 11, 0.5)',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          {getCategoryIcon(node.category)}
                          <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--accent-amber)' }}>R{node.round_number} ADAPTIVE</span>
                        </div>
                        <span className={`badge ${node.status === 'COLLECTED' ? 'badge-completed' : 'badge-warning'}`} style={{ fontSize: 9 }}>
                          {node.status}
                        </span>
                      </div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', marginBottom: 2 }}>{node.operation}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{node.label}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Edge Relationships */}
            <div style={{ paddingTop: 14, borderTop: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Identified Graph Relationships ({graph.edges.length})
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {graph.edges.map((e, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 10px', background: 'var(--bg-item)', borderRadius: 6, fontSize: 11, border: '1px solid var(--border-subtle)' }}>
                    <span style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>{e.source.replace('node_', '').toUpperCase()}</span>
                    <span style={{ fontSize: 9, color: e.relationship === 'EXPANDS_TO' ? 'var(--accent-amber)' : 'var(--text-dim)', fontWeight: 700 }}>[{e.relationship}]</span>
                    <ArrowRight size={11} color="var(--text-dim)" />
                    <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>{e.target.replace('node_', '').toUpperCase()}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
