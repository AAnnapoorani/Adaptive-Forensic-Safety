import React, { useState, useRef, useEffect, useMemo } from 'react';
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

interface EdgeRoute {
  edge: EvidenceEdge;
  edgeIndex: number;
  pathD: string;
  badgeX: number;
  badgeY: number;
  baseColor: string;
  markerId: string;
  isMultiLevel: boolean;
}

export const EvidenceDAGCanvas: React.FC<EvidenceDAGCanvasProps> = ({
  nodes,
  edges,
  selectedNode,
  onSelectNode
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerWidth, setContainerWidth] = useState<number>(560);
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

  const getRelationshipColor = (rel: string) => {
    switch (rel) {
      case 'PRECEDES': return 'var(--accent-blue, #0284c7)';
      case 'CORRELATES_WITH': return 'var(--accent-violet, #8b5cf6)';
      case 'EXPANDS_TO': return 'var(--accent-amber, #f59e0b)';
      default: return 'var(--text-dim, #64748b)';
    }
  };

  // ── 1. Topological Sorting & Level Stratification ─────────────────────────────
  const { sortedLevels, levelsMap, maxLevel, maxNodesInAnyTier } = useMemo(() => {
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

    const queue: string[] = [];
    nodes.forEach(n => {
      if (inDegree[n.id] === 0) {
        nodeLevels[n.id] = 0;
        queue.push(n.id);
      }
    });

    nodes.forEach(n => {
      if (nodeLevels[n.id] === undefined) {
        nodeLevels[n.id] = 0;
      }
    });

    while (queue.length > 0) {
      const curr = queue.shift()!;
      const currLevel = nodeLevels[curr];
      for (const nxt of adj[curr] || []) {
        const candidate = currLevel + 1;
        if (nodeLevels[nxt] === undefined || candidate > nodeLevels[nxt]) {
          nodeLevels[nxt] = candidate;
          queue.push(nxt);
        }
      }
    }

    const grouped: Record<number, EvidenceNode[]> = {};
    nodes.forEach(n => {
      const lvl = nodeLevels[n.id] ?? 0;
      if (!grouped[lvl]) grouped[lvl] = [];
      grouped[lvl].push(n);
    });

    const lvls = Object.keys(grouped).map(Number).sort((a, b) => a - b);
    const mxLevel = lvls.length > 0 ? Math.max(...lvls) : 0;
    const mxNodes = lvls.length > 0 ? Math.max(...lvls.map(l => grouped[l]?.length || 1)) : 1;

    return { sortedLevels: lvls, levelsMap: grouped, maxLevel: mxLevel, maxNodesInAnyTier: mxNodes };
  }, [nodes, edges]);

  // ── 2. Canvas Dimensions & Node Layout Calculation ──────────────────────────
  const nodeCardHeight = 56;
  const levelHeight = 138;
  const topPadding = 32;
  const gutterMargin = 76; // Generous exterior corridor on left & right for collision-free bypass routing
  const canvasHeight = Math.max(380, topPadding + (maxLevel + 1) * levelHeight + 16);

  // Guarantee sufficient width so cards never compress or collide horizontally
  const contentWidth = Math.max(containerWidth, maxNodesInAnyTier * 172 + gutterMargin * 2);
  const availWidth = contentWidth - gutterMargin * 2;

  const positions: Record<string, NodePosition> = useMemo(() => {
    const pos: Record<string, NodePosition> = {};

    sortedLevels.forEach(lvl => {
      const tierNodes = levelsMap[lvl] || [];
      const count = tierNodes.length;
      const y = topPadding + lvl * levelHeight;

      // Dynamically calculate card width to guarantee generous spacing
      const cardWidth = Math.min(176, Math.max(140, Math.floor((availWidth - (count - 1) * 22) / count)));
      const totalRowWidth = count * cardWidth + (count - 1) * 22;
      const startX = gutterMargin + (availWidth - totalRowWidth) / 2;

      tierNodes.forEach((node, idx) => {
        const x = startX + idx * (cardWidth + 22);
        pos[node.id] = {
          x,
          y,
          width: cardWidth,
          height: nodeCardHeight,
          level: lvl
        };
      });
    });

    return pos;
  }, [sortedLevels, levelsMap, availWidth, contentWidth]);

  // ── 3. Overlap-Free, Obstacle-Aware Edge Routing ─────────────────────────────
  const edgeRoutes: EdgeRoute[] = useMemo(() => {
    // Track outgoing edges per source node to stagger adjacent badges
    const outgoingCountBySource: Record<string, number> = {};
    const outgoingIndexBySource: Record<string, number> = {};

    edges.forEach(e => {
      outgoingCountBySource[e.source] = (outgoingCountBySource[e.source] || 0) + 1;
    });

    let leftGutterIndex = 0;
    let rightGutterIndex = 0;

    return edges.map((edge, idx) => {
      const src = positions[edge.source];
      const tgt = positions[edge.target];
      if (!src || !tgt) return null as unknown as EdgeRoute;

      const siblingCount = outgoingCountBySource[edge.source] || 1;
      const siblingIdx = outgoingIndexBySource[edge.source] || 0;
      outgoingIndexBySource[edge.source] = siblingIdx + 1;

      const levelDiff = tgt.level - src.level;
      const isMultiLevel = levelDiff >= 2;

      let pathD = '';
      let badgeX = 0;
      let badgeY = 0;

      const baseColor = getRelationshipColor(edge.relationship);
      let markerId = 'arrow-default';
      if (edge.relationship === 'PRECEDES') markerId = 'arrow-precedes';
      else if (edge.relationship === 'CORRELATES_WITH') markerId = 'arrow-correlates';
      else if (edge.relationship === 'EXPANDS_TO') markerId = 'arrow-expands';

      if (isMultiLevel) {
        // ── MULTI-LEVEL SKIP EDGE: Route via exterior margin corridor ──────────
        // This eliminates collisions through intermediate cards and text
        const midSrcX = src.x + src.width / 2;
        const midTgtX = tgt.x + tgt.width / 2;
        const useLeftGutter = (midSrcX + midTgtX) / 2 <= contentWidth / 2;

        if (useLeftGutter) {
          const gutterX = Math.max(24, 38 - leftGutterIndex * 12);
          leftGutterIndex++;

          const startX = src.x;
          const startY = src.y + src.height * 0.65;
          const endX = tgt.x;
          const endY = tgt.y + src.height * 0.35;

          pathD = `M ${startX} ${startY} ` +
                  `C ${gutterX} ${startY}, ${gutterX} ${src.y + src.height + 24}, ${gutterX} ${(startY + endY) / 2} ` +
                  `S ${gutterX} ${endY}, ${endX} ${endY}`;

          badgeX = gutterX + 16;
          badgeY = (startY + endY) / 2;
        } else {
          const gutterX = Math.min(contentWidth - 24, contentWidth - 38 + rightGutterIndex * 12);
          rightGutterIndex++;

          const startX = src.x + src.width;
          const startY = src.y + src.height * 0.65;
          const endX = tgt.x + tgt.width;
          const endY = tgt.y + tgt.height * 0.35;

          pathD = `M ${startX} ${startY} ` +
                  `C ${gutterX} ${startY}, ${gutterX} ${src.y + src.height + 24}, ${gutterX} ${(startY + endY) / 2} ` +
                  `S ${gutterX} ${endY}, ${endX} ${endY}`;

          badgeX = gutterX - 16;
          badgeY = (startY + endY) / 2;
        }
      } else {
        // ── ADJACENT LEVEL EDGE: Clean vertical bezier with vertical gap ──────
        const x1 = src.x + src.width / 2;
        const y1 = src.y + src.height;
        const x2 = tgt.x + tgt.width / 2;
        const y2 = tgt.y;

        const verticalGap = y2 - y1;
        const curveOffset = Math.min(48, Math.max(28, verticalGap * 0.45));

        pathD = `M ${x1} ${y1} C ${x1} ${y1 + curveOffset}, ${x2} ${y2 - curveOffset}, ${x2} ${y2}`;

        // Stagger sibling edge badges vertically so adjacent pills never collide
        const yStagger = siblingCount > 1 ? (siblingIdx % 2 === 0 ? -9 : 9) : 0;
        badgeX = (x1 + x2) / 2;
        badgeY = (y1 + y2) / 2 + yStagger;
      }

      return {
        edge,
        edgeIndex: idx,
        pathD,
        badgeX,
        badgeY,
        baseColor,
        markerId,
        isMultiLevel
      };
    }).filter(Boolean);
  }, [edges, positions, contentWidth]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {/* Scrollable Container Wrapper */}
      <div
        ref={containerRef}
        style={{
          position: 'relative',
          width: '100%',
          overflowX: 'auto',
          borderRadius: 8,
          border: '1px solid var(--border-subtle)',
          background: 'var(--bg-secondary, #ffffff)',
          boxShadow: 'inset 0 1px 3px rgba(0, 0, 0, 0.04)'
        }}
      >
        <div
          style={{
            position: 'relative',
            width: contentWidth,
            height: canvasHeight,
            userSelect: 'none'
          }}
        >
          {/* SVG Canvas for Directed Connectors & Labels */}
          <svg
            width={contentWidth}
            height={canvasHeight}
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              width: contentWidth,
              height: canvasHeight,
              pointerEvents: 'none'
            }}
          >
            <defs>
              {/* Subtle Theme-Aware Dot Grid */}
              <pattern id="dag-grid-pattern" width="22" height="22" patternUnits="userSpaceOnUse">
                <circle cx="2" cy="2" r="1.1" fill="var(--border-subtle)" opacity="0.45" />
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
                <g key={lvl} opacity="0.32">
                  <line
                    x1={gutterMargin - 20}
                    y1={y + nodeCardHeight / 2}
                    x2={contentWidth - gutterMargin + 20}
                    y2={y + nodeCardHeight / 2}
                    stroke="var(--border-subtle)"
                    strokeDasharray="3 3"
                  />
                  <text
                    x={gutterMargin - 20}
                    y={y - 8}
                    fill="var(--text-dim)"
                    fontSize="9.5"
                    fontFamily="Fira Code, monospace"
                    fontWeight="600"
                    letterSpacing="0.06em"
                  >
                    TIER {lvl + 1}
                  </text>
                </g>
              );
            })}

            {/* Directed Edges */}
            {edgeRoutes.map(route => {
              const { edge, edgeIndex, pathD, badgeX, badgeY, baseColor, markerId, isMultiLevel } = route;
              const isHovered = hoveredEdgeIndex === edgeIndex;
              const isConnectedToHoveredNode =
                hoveredNodeId === edge.source || hoveredNodeId === edge.target;
              const isSelected =
                selectedNode?.id === edge.source || selectedNode?.id === edge.target;

              return (
                <g
                  key={edgeIndex}
                  style={{ pointerEvents: 'auto', cursor: 'pointer' }}
                  onMouseEnter={() => setHoveredEdgeIndex(edgeIndex)}
                  onMouseLeave={() => setHoveredEdgeIndex(null)}
                >
                  {/* Thick transparent stroke for easier hover hit target */}
                  <path d={pathD} fill="none" stroke="transparent" strokeWidth="18" />

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
                    strokeWidth={isHovered || isSelected ? '2.4' : '1.6'}
                    strokeDasharray={
                      edge.relationship === 'CORRELATES_WITH'
                        ? '4 3'
                        : isMultiLevel
                        ? '6 3'
                        : undefined
                    }
                    markerEnd={`url(#${markerId})`}
                    opacity={hoveredNodeId && !isConnectedToHoveredNode ? 0.28 : 0.88}
                    style={{ transition: 'stroke-width 0.15s ease, opacity 0.15s ease' }}
                  />

                  {/* Theme-Aware Relationship Badge Pill */}
                  <g transform={`translate(${badgeX}, ${badgeY})`}>
                    <rect
                      x="-38"
                      y="-9"
                      width="76"
                      height="18"
                      rx="9"
                      fill="var(--bg-secondary, #ffffff)"
                      stroke={baseColor}
                      strokeWidth={isHovered ? '1.5' : '1'}
                      style={{
                        filter: 'drop-shadow(0 1px 3px rgba(0, 0, 0, 0.1))'
                      }}
                    />
                    <text
                      x="0"
                      y="3.5"
                      textAnchor="middle"
                      fill={baseColor}
                      fontSize="8"
                      fontFamily="Inter, system-ui, sans-serif"
                      fontWeight="700"
                      letterSpacing="0.04em"
                    >
                      {edge.relationship}
                    </text>
                  </g>
                </g>
              );
            })}
          </svg>

          {/* HTML Node Layer (Solid, Opaque Backgrounds so Nothing Ever Bleeds Through) */}
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
                  // Solid, 100% opaque background base prevents any background text/edge collision
                  background: 'var(--bg-secondary, #ffffff)',
                  border: isSelected
                    ? '2px solid var(--accent-blue, #0284c7)'
                    : isAdaptive
                    ? '1.5px solid var(--accent-amber, #f59e0b)'
                    : '1px solid var(--border-subtle)',
                  boxShadow: isSelected
                    ? '0 0 0 3px rgba(2, 132, 199, 0.22), 0 4px 14px rgba(0, 0, 0, 0.08)'
                    : isHovered
                    ? '0 4px 12px rgba(0, 0, 0, 0.09)'
                    : '0 1px 3px rgba(0, 0, 0, 0.05)',
                  padding: '6px 10px',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  transform: isSelected
                    ? 'translateY(-2px)'
                    : isHovered
                    ? 'translateY(-1.5px)'
                    : 'none',
                  zIndex: isSelected ? 12 : isHovered ? 10 : 5
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
                    background: isSelected ? 'var(--accent-blue, #0284c7)' : 'var(--border-subtle)',
                    border: '1.5px solid var(--bg-secondary, #ffffff)'
                  }}
                />

                {/* Left Bypass Anchor Dot (for Skip-level edges) */}
                <div
                  style={{
                    position: 'absolute',
                    top: '50%',
                    left: -4,
                    transform: 'translateY(-50%)',
                    width: 6,
                    height: 6,
                    borderRadius: '50%',
                    background: isSelected ? 'var(--accent-blue, #0284c7)' : 'var(--border-subtle)',
                    border: '1.5px solid var(--bg-secondary, #ffffff)'
                  }}
                />

                {/* Header: Category Icon + Status Badge */}
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

                {/* Operation Title & Label */}
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
                    title={node.operation}
                  >
                    {node.operation}
                  </div>
                  <div
                    style={{
                      fontSize: 9,
                      color: 'var(--text-dim)',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis'
                    }}
                    title={node.label}
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
                    background: isSelected ? 'var(--accent-blue, #0284c7)' : 'var(--border-subtle)',
                    border: '1.5px solid var(--bg-secondary, #ffffff)'
                  }}
                />
              </div>
            );
          })}
        </div>
      </div>

      {/* External Footer Legend Bar */}
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
