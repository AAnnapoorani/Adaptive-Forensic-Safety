import React, { useState, useRef, useEffect } from 'react';
import type { EvidenceNode, EvidenceEdge } from '../types';
import { Cpu, Network, HardDrive, ShieldCheck, GitBranch, Zap } from 'lucide-react';

interface EvidenceDAGCanvasProps {
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
  selectedNode: EvidenceNode | null;
  onSelectNode: (node: EvidenceNode) => void;
}

interface NodePosition {
  x: number;
  y: number;
  width: number;
  height: number;
  level: number;
}

export const EvidenceDAGCanvas: React.FC<EvidenceDAGCanvasProps> = ({
  nodes,
  edges,
  selectedNode,
  onSelectNode
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerWidth, setContainerWidth] = useState<number>(550);
  const [hoveredEdgeIndex, setHoveredEdgeIndex] = useState<number | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  useEffect(() => {
    const updateWidth = () => {
      if (containerRef.current) {
        const w = containerRef.current.clientWidth;
        if (w > 200) {
          setContainerWidth(w);
        }
      }
    };
    updateWidth();
    window.addEventListener('resize', updateWidth);
    return () => window.removeEventListener('resize', updateWidth);
  }, []);

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'PROCESS': return <Cpu size={13} color="var(--accent-blue)" />;
      case 'NETWORK': return <Network size={13} color="var(--accent-cyan)" />;
      case 'STORAGE': return <HardDrive size={13} color="var(--accent-violet)" />;
      case 'AUDIT': return <ShieldCheck size={13} color="var(--accent-emerald)" />;
      default: return <GitBranch size={13} color="var(--text-muted)" />;
    }
  };

  // 1. Compute Topological Levels
  const nodeLevels: Record<string, number> = {};
  const inDegree: Record<string, number> = {};
  const adj: Record<string, string[]> = {};

  nodes.forEach(n => {
    inDegree[n.id] = 0;
    adj[n.id] = [];
  });

  edges.forEach(e => {
    if (adj[e.source]) adj[e.source].push(e.target);
    if (inDegree[e.target] !== undefined) inDegree[e.target]++;
  });

  // Start with nodes that have inDegree === 0
  const queue: string[] = [];
  nodes.forEach(n => {
    if (inDegree[n.id] === 0) {
      nodeLevels[n.id] = 0;
      queue.push(n.id);
    }
  });

  // Fallback for isolated or cyclical nodes
  nodes.forEach(n => {
    if (nodeLevels[n.id] === undefined) {
      nodeLevels[n.id] = 0;
    }
  });

  while (queue.length > 0) {
    const curr = queue.shift()!;
    const currLevel = nodeLevels[curr];
    for (const nxt of adj[curr] || []) {
      const candidateLevel = currLevel + 1;
      if (nodeLevels[nxt] === undefined || candidateLevel > nodeLevels[nxt]) {
        nodeLevels[nxt] = candidateLevel;
        queue.push(nxt);
      }
    }
  }

  // Group nodes by level
  const levelsMap: Record<number, EvidenceNode[]> = {};
  nodes.forEach(n => {
    const lvl = nodeLevels[n.id] ?? 0;
    if (!levelsMap[lvl]) levelsMap[lvl] = [];
    levelsMap[lvl].push(n);
  });

  const sortedLevels = Object.keys(levelsMap).map(Number).sort((a, b) => a - b);
  const maxLevel = sortedLevels.length > 0 ? Math.max(...sortedLevels) : 0;

  // 2. Position nodes cleanly on canvas
  const nodeCardWidth = 176;
  const nodeCardHeight = 58;
  const levelHeight = 104;
  const topPadding = 28;
  const canvasHeight = Math.max(370, topPadding + (maxLevel + 1) * levelHeight + 10);

  const positions: Record<string, NodePosition> = {};

  sortedLevels.forEach(lvl => {
    const levelNodes = levelsMap[lvl];
    const count = levelNodes.length;
    const y = topPadding + lvl * levelHeight;

    levelNodes.forEach((node, idx) => {
      const slotWidth = containerWidth / (count + 1);
      const x = slotWidth * (idx + 1) - nodeCardWidth / 2;
      positions[node.id] = {
        x: Math.max(12, Math.min(x, containerWidth - nodeCardWidth - 12)),
        y,
        width: nodeCardWidth,
        height: nodeCardHeight,
        level: lvl
      };
    });
  });

  // Colors adapted to theme tokens
  const getRelationshipColor = (rel: string) => {
    switch (rel) {
      case 'PRECEDES': return 'var(--accent-blue, #0284c7)';
      case 'CORRELATES_WITH': return 'var(--accent-violet, #8b5cf6)';
      case 'EXPANDS_TO': return 'var(--accent-amber, #f59e0b)';
      default: return 'var(--text-dim, #64748b)';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {/* Visual Canvas Area */}
      <div
        ref={containerRef}
        style={{
          position: 'relative',
          width: '100%',
          height: canvasHeight,
          background: 'var(--bg-secondary, #ffffff)',
          borderRadius: 8,
          border: '1px solid var(--border-subtle)',
          overflow: 'hidden',
          userSelect: 'none',
          boxShadow: 'inset 0 1px 3px rgba(0, 0, 0, 0.04)'
        }}
      >
        {/* SVG Canvas for Directed Connectors & Labels */}
        <svg
          width={containerWidth}
          height={canvasHeight}
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: '100%',
            height: '100%',
            pointerEvents: 'none'
          }}
        >
          <defs>
            {/* Subtle Theme-Aware Dot Grid */}
            <pattern id="dag-grid-pattern" width="20" height="20" patternUnits="userSpaceOnUse">
              <circle cx="2" cy="2" r="1" fill="var(--border-subtle)" opacity="0.5" />
            </pattern>

            {/* Directed Arrow Markers */}
            <marker
              id="arrow-precedes"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="var(--accent-blue, #0284c7)" />
            </marker>
            <marker
              id="arrow-correlates"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="var(--accent-violet, #8b5cf6)" />
            </marker>
            <marker
              id="arrow-expands"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="var(--accent-amber, #f59e0b)" />
            </marker>
            <marker
              id="arrow-default"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="var(--text-dim, #64748b)" />
            </marker>
          </defs>

          {/* Background Grid */}
          <rect width="100%" height="100%" fill="url(#dag-grid-pattern)" />

          {/* Horizontal Layer Watermark Guides */}
          {sortedLevels.map(lvl => {
            const y = topPadding + lvl * levelHeight;
            return (
              <g key={lvl} opacity="0.35">
                <line
                  x1="12"
                  y1={y + nodeCardHeight / 2}
                  x2={containerWidth - 12}
                  y2={y + nodeCardHeight / 2}
                  stroke="var(--border-subtle)"
                  strokeDasharray="3 3"
                />
                <text
                  x="12"
                  y={y - 6}
                  fill="var(--text-dim)"
                  fontSize="9"
                  fontFamily="Fira Code, monospace"
                  fontWeight="600"
                  letterSpacing="0.05em"
                >
                  TIER {lvl + 1}
                </text>
              </g>
            );
          })}

          {/* Directed Edges */}
          {edges.map((edge, idx) => {
            const src = positions[edge.source];
            const tgt = positions[edge.target];
            if (!src || !tgt) return null;

            const isHovered = hoveredEdgeIndex === idx;
            const isConnectedToHoveredNode =
              hoveredNodeId === edge.source || hoveredNodeId === edge.target;
            const isSelected =
              selectedNode?.id === edge.source || selectedNode?.id === edge.target;

            const x1 = src.x + src.width / 2;
            const y1 = src.y + src.height;
            const x2 = tgt.x + tgt.width / 2;
            const y2 = tgt.y;

            // Check if edge skips a tier directly along the same column
            const levelDiff = tgt.level - src.level;
            const isMultiLevelVertical = levelDiff > 1 && Math.abs(x1 - x2) < 40;

            let pathD = '';
            let midX = (x1 + x2) / 2;
            let midY = (y1 + y2) / 2;

            if (isMultiLevelVertical) {
              // Gracefully arc right without overflowing container
              const availableRight = containerWidth - Math.max(x1, x2) - 30;
              const offset = Math.min(54, Math.max(28, availableRight));
              pathD = `M ${x1} ${y1} C ${x1 + offset} ${(y1 * 2 + y2) / 3}, ${x2 + offset} ${(y1 + y2 * 2) / 3}, ${x2} ${y2}`;
              midX = (x1 + x2) / 2 + offset * 0.72;
              midY = (y1 + y2) / 2;
            } else {
              const curvature = Math.max(24, (y2 - y1) * 0.45);
              pathD = `M ${x1} ${y1} C ${x1} ${y1 + curvature}, ${x2} ${y2 - curvature}, ${x2} ${y2}`;
            }

            const baseColor = getRelationshipColor(edge.relationship);
            let markerId = 'arrow-default';
            if (edge.relationship === 'PRECEDES') markerId = 'arrow-precedes';
            else if (edge.relationship === 'CORRELATES_WITH') markerId = 'arrow-correlates';
            else if (edge.relationship === 'EXPANDS_TO') markerId = 'arrow-expands';

            return (
              <g
                key={idx}
                style={{ pointerEvents: 'auto', cursor: 'pointer' }}
                onMouseEnter={() => setHoveredEdgeIndex(idx)}
                onMouseLeave={() => setHoveredEdgeIndex(null)}
              >
                {/* Thick transparent stroke for easier hover hit target */}
                <path d={pathD} fill="none" stroke="transparent" strokeWidth="16" />

                {/* Glow aura on hover or selection */}
                {(isHovered || isConnectedToHoveredNode || isSelected) && (
                  <path
                    d={pathD}
                    fill="none"
                    stroke={baseColor}
                    strokeWidth="5"
                    opacity="0.25"
                    strokeLinecap="round"
                  />
                )}

                {/* Main Path Stroke */}
                <path
                  d={pathD}
                  fill="none"
                  stroke={baseColor}
                  strokeWidth={isHovered || isSelected ? '2.2' : '1.5'}
                  strokeDasharray={edge.relationship === 'CORRELATES_WITH' ? '4 3' : undefined}
                  markerEnd={`url(#${markerId})`}
                  opacity={hoveredNodeId && !isConnectedToHoveredNode ? 0.3 : 0.85}
                  style={{ transition: 'stroke-width 0.15s ease, opacity 0.15s ease' }}
                />

                {/* Theme-Aware Relationship Badge Pill */}
                <g transform={`translate(${midX}, ${midY})`}>
                  <rect
                    x="-42"
                    y="-9"
                    width="84"
                    height="18"
                    rx="9"
                    fill="var(--bg-card, #ffffff)"
                    stroke={baseColor}
                    strokeWidth={isHovered ? '1.5' : '1'}
                    style={{
                      filter: 'drop-shadow(0 1px 3px rgba(0, 0, 0, 0.1))'
                    }}
                  />
                  <text
                    x="0"
                    y="3"
                    textAnchor="middle"
                    fill={baseColor}
                    fontSize="8.5"
                    fontFamily="Inter, system-ui, sans-serif"
                    fontWeight="700"
                    letterSpacing="0.03em"
                  >
                    {edge.relationship}
                  </text>
                </g>
              </g>
            );
          })}
        </svg>

        {/* HTML Node Layer */}
        {nodes.map(node => {
          const pos = positions[node.id];
          if (!pos) return null;

          const isSelected = selectedNode?.id === node.id;
          const isHovered = hoveredNodeId === node.id;
          const isAdaptive = node.round_number > 1;

          return (
            <div
              key={node.id}
              onClick={() => onSelectNode(node)}
              onMouseEnter={() => setHoveredNodeId(node.id)}
              onMouseLeave={() => setHoveredNodeId(null)}
              style={{
                position: 'absolute',
                left: pos.x,
                top: pos.y,
                width: pos.width,
                height: pos.height,
                borderRadius: 6,
                background: isSelected
                  ? 'rgba(56, 189, 248, 0.14)'
                  : isAdaptive
                  ? 'rgba(245, 158, 11, 0.08)'
                  : 'var(--bg-card, #ffffff)',
                border: isSelected
                  ? '2px solid var(--accent-blue, #0284c7)'
                  : isAdaptive
                  ? '1px solid var(--accent-amber, #f59e0b)'
                  : '1px solid var(--border-subtle)',
                boxShadow: isSelected
                  ? '0 0 12px rgba(56, 189, 248, 0.3)'
                  : isHovered
                  ? '0 4px 10px rgba(0, 0, 0, 0.08)'
                  : '0 1px 3px rgba(0, 0, 0, 0.05)',
                padding: '6px 10px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                transform: isHovered ? 'translateY(-1.5px)' : 'none',
                zIndex: isSelected ? 10 : isHovered ? 8 : 4
              }}
            >
              {/* Top Anchor Dot */}
              <div
                style={{
                  position: 'absolute',
                  top: -4,
                  left: '50%',
                  transform: 'translateX(-50%)',
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  background: 'var(--accent-blue, #0284c7)',
                  border: '1.5px solid var(--bg-card, #ffffff)'
                }}
              />

              {/* Header: Category Icon + Status */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  {getCategoryIcon(node.category)}
                  <span style={{ fontSize: 9.5, fontWeight: 700, color: 'var(--text-muted)' }}>
                    {node.category}
                  </span>
                  {isAdaptive && (
                    <span className="badge badge-warning" style={{ fontSize: 8, padding: '1px 3px' }}>
                      <Zap size={8} style={{ display: 'inline' }} /> R{node.round_number}
                    </span>
                  )}
                </div>
                <span
                  className={`badge ${node.status === 'COLLECTED' ? 'badge-completed' : 'badge-neutral'}`}
                  style={{ fontSize: 8.5, padding: '1px 4px' }}
                >
                  {node.status}
                </span>
              </div>

              {/* Operation Title */}
              <div>
                <div
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    fontFamily: 'Fira Code, monospace',
                    color: isSelected ? 'var(--accent-blue)' : 'var(--text-main)',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis'
                  }}
                >
                  {node.operation}
                </div>
                <div
                  style={{
                    fontSize: 9.5,
                    color: 'var(--text-dim)',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis'
                  }}
                >
                  {node.label}
                </div>
              </div>

              {/* Bottom Anchor Dot */}
              <div
                style={{
                  position: 'absolute',
                  bottom: -4,
                  left: '50%',
                  transform: 'translateX(-50%)',
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  background: 'var(--accent-blue, #0284c7)',
                  border: '1.5px solid var(--bg-card, #ffffff)'
                }}
              />
            </div>
          );
        })}
      </div>

      {/* External Footer Legend Bar (Safely outside the canvas so it never overlaps nodes) */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 10,
          padding: '7px 12px',
          background: 'var(--bg-item, #f8fafc)',
          borderRadius: 6,
          border: '1px solid var(--border-subtle)',
          fontSize: 11,
          color: 'var(--text-muted)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
          <span style={{ fontWeight: 600, color: 'var(--text-main)', fontSize: 10.5 }}>Edge Flow:</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent-blue, #0284c7)' }} />
            <span style={{ color: 'var(--accent-blue, #0284c7)', fontWeight: 600, fontSize: 10.5 }}>PRECEDES</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent-violet, #8b5cf6)' }} />
            <span style={{ color: 'var(--accent-violet, #8b5cf6)', fontWeight: 600, fontSize: 10.5 }}>CORRELATES_WITH</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent-amber, #f59e0b)' }} />
            <span style={{ color: 'var(--accent-amber, #f59e0b)', fontWeight: 600, fontSize: 10.5 }}>EXPANDS_TO</span>
          </div>
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-dim)' }}>
          Click node to inspect rationale
        </div>
      </div>
    </div>
  );
};
