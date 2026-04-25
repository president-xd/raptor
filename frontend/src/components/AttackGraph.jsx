import React, { useEffect, useRef, useState } from 'react';
import Graph from 'graphology';
import Sigma from 'sigma';
import forceAtlas2 from 'graphology-layout-forceatlas2';
import { ZoomIn, ZoomOut, Maximize2, Crosshair } from 'lucide-react';

/* ─── Professional palette — warm tones on dark navy ─── */
const NODE_COLORS = {
  clean:       '#5a7799',   // steel blue — neutral
  compromised: '#dc3545',   // true red — danger
  dc:          '#8a6ec4',   // regal purple — authority
  user:        '#4a90d9',   // professional blue
  technique:   '#28a745',   // green — actionable
};

const EDGE_COLORS = {
  lateral_movement: 'rgba(226,168,50,0.55)',   // amber flow
  observed_in:      'rgba(74,144,217,0.3)',     // steel blue trace
  attack_sequence:  'rgba(220,53,69,0.6)',      // red threat line
  default:          'rgba(90,119,153,0.2)',      // dim steel
};

const LEGEND_ITEMS = [
  { color: NODE_COLORS.clean,       label: 'Clean Host' },
  { color: NODE_COLORS.compromised, label: 'Compromised' },
  { color: NODE_COLORS.dc,          label: 'Domain Controller' },
  { color: NODE_COLORS.user,        label: 'User Account' },
  { color: NODE_COLORS.technique,   label: 'ATT&CK Technique' },
];

export default function AttackGraph({ graphData, onNodeClick }) {
  const containerRef = useRef(null);
  const sigmaRef = useRef(null);
  const hoveredNodeRef = useRef(null);
  const [hoveredNode, setHoveredNode] = useState(null);

  const fallbackCoord = (key, axis) => {
    const seed = `${axis}:${key}`;
    let hash = 0;
    for (let i = 0; i < seed.length; i += 1) {
      hash = ((hash << 5) - hash) + seed.charCodeAt(i);
      hash |= 0;
    }
    const ratio = ((hash >>> 0) % 10000) / 10000;
    return -100 + (ratio * 200);
  };

  useEffect(() => {
    if (!containerRef.current || !graphData) return;

    const graph = new Graph();
    const nodes = graphData.nodes || [];
    const edges = graphData.edges || [];
    const hasProvidedPositions = nodes.every((node) => Number.isFinite(node.x) && Number.isFinite(node.y));

    if (nodes.length === 0) return;

    /* ── Build nodes ── */
    nodes.forEach((node) => {
      try {
        let size = 10;
        let color = node.color || NODE_COLORS.clean;
        const nt = (node.node_type || '').toLowerCase();

        if (nt === 'host') {
          const isDC = node.metadata?.is_dc || (node.label || '').toUpperCase().includes('DC');
          const isComp = node.metadata?.compromised;
          color = isDC ? NODE_COLORS.dc : isComp ? NODE_COLORS.compromised : NODE_COLORS.clean;
          size = isDC ? 20 : 14;
        } else if (nt === 'user') {
          color = NODE_COLORS.user;
          size = 11;
        } else if (nt === 'technique') {
          color = NODE_COLORS.technique;
          size = 12;
        }

        graph.addNode(node.id, {
          label: node.label,
          x: Number.isFinite(node.x) ? node.x : fallbackCoord(node.id, 'x'),
          y: Number.isFinite(node.y) ? node.y : fallbackCoord(node.id, 'y'),
          size,
          color,
          node_type: node.node_type,
          metadata: node.metadata || {},
        });
      } catch (e) { /* skip duplicate */ }
    });

    /* ── Build edges ── */
    edges.forEach((edge) => {
      try {
        const et = (edge.edge_type || '').toLowerCase();
        const edgeColor = EDGE_COLORS[et] || edge.color || EDGE_COLORS.default;
        const edgeSize = et === 'lateral_movement' ? 2.5 : et === 'attack_sequence' ? 2 : 1;

        graph.addEdge(edge.source, edge.target, {
          label: edge.label || '',
          color: edgeColor,
          size: edgeSize,
          type: 'arrow',
        });
      } catch (e) { /* skip duplicate */ }
    });

    /* ── ForceAtlas2 physics (only when coordinates were not precomputed) ── */
    if (!hasProvidedPositions) {
      try {
        const settings = forceAtlas2.inferSettings(graph);
        forceAtlas2.assign(graph, {
          iterations: Math.min(250, Math.max(100, nodes.length * 8)),
          settings: {
            ...settings,
            gravity: 0.8,
            scalingRatio: 6,
            barnesHutOptimize: graph.order > 20,
            strongGravityMode: true,
            slowDown: 3,
          },
        });
      } catch (e) {
        console.warn('ForceAtlas2 failed, using provided layout:', e);
      }
    }

    /* ── Sigma renderer ── */
    if (sigmaRef.current) sigmaRef.current.kill();

    const renderer = new Sigma(graph, containerRef.current, {
      renderLabels: true,
      labelColor: { color: '#c5d0de' },
      labelFont: 'Inter, system-ui, sans-serif',
      labelSize: 13,
      labelWeight: '500',
      labelDensity: 0.7,
      labelGridCellSize: 120,
      edgeLabelColor: { color: '#7a8ba7' },
      edgeLabelFont: 'Inter, system-ui, sans-serif',
      edgeLabelSize: 10,
      defaultEdgeType: 'arrow',
      defaultNodeColor: NODE_COLORS.clean,
      defaultEdgeColor: EDGE_COLORS.default,
      stagePadding: 50,
      allowInvalidContainer: true,
      minCameraRatio: 0.08,
      maxCameraRatio: 8,

      nodeReducer: (node, data) => {
        const res = { ...data };
        const activeHover = hoveredNodeRef.current;
        if (activeHover && activeHover !== node) {
          const isNeighbor = graph.hasEdge(activeHover, node) || graph.hasEdge(node, activeHover);
          if (!isNeighbor) {
            res.color = 'rgba(90,119,153,0.12)';
            res.label = '';
          }
        }
        return res;
      },
      edgeReducer: (edge, data) => {
        const res = { ...data };
        const activeHover = hoveredNodeRef.current;
        if (activeHover) {
          const src = graph.source(edge);
          const tgt = graph.target(edge);
          if (src !== activeHover && tgt !== activeHover) {
            res.color = 'rgba(90,119,153,0.05)';
          } else {
            res.size = (data.size || 1) * 2;
          }
        }
        return res;
      },
    });

    renderer.on('clickNode', ({ node }) => {
      const attrs = graph.getNodeAttributes(node);
      if (onNodeClick) onNodeClick({ id: node, ...attrs });
    });
    renderer.on('enterNode', ({ node }) => {
      hoveredNodeRef.current = node;
      setHoveredNode(node);
    });
    renderer.on('leaveNode', () => {
      hoveredNodeRef.current = null;
      setHoveredNode(null);
    });

    sigmaRef.current = renderer;

    return () => { if (sigmaRef.current) { sigmaRef.current.kill(); sigmaRef.current = null; } };
  }, [graphData, onNodeClick]);

  useEffect(() => { if (sigmaRef.current) sigmaRef.current.refresh(); }, [hoveredNode]);

  const zoom  = (dir) => { if (!sigmaRef.current) return; const c = sigmaRef.current.getCamera(); dir > 0 ? c.animatedZoom({ duration: 250 }) : c.animatedUnzoom({ duration: 250 }); };
  const reset = () => { if (sigmaRef.current) sigmaRef.current.getCamera().animatedReset({ duration: 400 }); };

  const nodeCount = graphData?.nodes?.length || 0;
  const edgeCount = graphData?.edges?.length || 0;

  return (
    <div className="relative w-full h-full rounded-xl overflow-hidden">
      <div ref={containerRef} className="w-full h-full"
           style={{ minHeight: '500px', background: 'radial-gradient(ellipse at 50% 50%, #111d33 0%, #0a1222 80%, #070d18 100%)' }} />

      {/* Zoom controls */}
      <div className="absolute top-4 right-4 flex flex-col gap-1.5">
        {[
          { icon: ZoomIn,    fn: () => zoom(1),  tip: 'Zoom in' },
          { icon: ZoomOut,   fn: () => zoom(-1), tip: 'Zoom out' },
          { icon: Maximize2, fn: reset,          tip: 'Fit graph' },
        ].map(({ icon: Icon, fn, tip }, i) => (
          <button key={i} onClick={fn} title={tip}
            className="p-2 rounded-lg border transition-all duration-200
                       bg-[#141c2e]/90 border-[#263354] text-[#7a8ba7]
                       hover:border-[#e2a832]/40 hover:text-[#e2a832]">
            <Icon className="w-4 h-4" />
          </button>
        ))}
      </div>

      {/* Stats pill */}
      <div className="absolute bottom-4 left-4">
        <div className="px-3 py-1.5 rounded-full text-xs flex items-center gap-2
                        bg-[#141c2e]/90 border border-[#263354]">
          <Crosshair className="w-3 h-3 text-[#e2a832]" />
          <span className="text-[#7a8ba7]">Nodes</span>
          <span className="text-[#e8ecf1] font-semibold">{nodeCount}</span>
          <span className="text-[#263354] mx-0.5">|</span>
          <span className="text-[#7a8ba7]">Edges</span>
          <span className="text-[#e8ecf1] font-semibold">{edgeCount}</span>
        </div>
      </div>

      {/* Legend */}
      <div className="absolute top-4 left-4 p-3 rounded-xl border
                      bg-[#141c2e]/90 border-[#263354]">
        <p className="text-[10px] font-semibold text-[#7a8ba7] mb-2 uppercase tracking-widest">Legend</p>
        <div className="space-y-1.5 text-xs text-[#9aa8bd]">
          {LEGEND_ITEMS.map(({ color, label }) => (
            <div key={label} className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                    style={{ background: color, boxShadow: `0 0 5px ${color}44` }} />
              {label}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
