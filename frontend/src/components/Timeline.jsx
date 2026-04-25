import React from 'react';
import { Clock, Shield, AlertTriangle, ChevronRight } from 'lucide-react';

const PHASE_COLORS = {
  'recon': '#6366f1', 'resource-dev': '#818cf8', 'initial-access': '#f59e0b',
  'execution': '#ef4444', 'persistence': '#8b5cf6', 'privilege-esc': '#ec4899',
  'defense-evasion': '#64748b', 'credential-access': '#f97316', 'discovery': '#3b82f6',
  'lateral-movement': '#f59e0b', 'collection': '#14b8a6', 'c2': '#ef4444',
  'exfiltration': '#dc2626', 'impact': '#991b1b',
};

const CONFIDENCE_STYLES = {
  high: 'badge-high', medium: 'badge-medium', low: 'badge-low',
};

export default function Timeline({ findings, attackSequence }) {
  if (!findings || findings.length === 0) {
    return (
      <div className="glass-card p-8 text-center">
        <Clock className="w-12 h-12 mx-auto text-raptor-muted mb-3" />
        <p className="text-raptor-muted">No timeline data available yet</p>
      </div>
    );
  }

  // Sort by kill chain phase order
  const phaseOrder = [
    'recon', 'resource-dev', 'initial-access', 'execution', 'persistence',
    'privilege-esc', 'defense-evasion', 'credential-access', 'discovery',
    'lateral-movement', 'collection', 'c2', 'exfiltration', 'impact'
  ];

  const sorted = [...findings].sort((a, b) => {
    const ai = phaseOrder.indexOf(a.kill_chain_phase);
    const bi = phaseOrder.indexOf(b.kill_chain_phase);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });

  return (
    <div className="space-y-4">
      {/* Attack Sequence Flow */}
      {attackSequence && attackSequence.length > 0 && (
        <div className="glass-card p-4 mb-6">
          <h3 className="text-sm font-semibold text-raptor-muted uppercase tracking-wider mb-3">
            Attack Flow
          </h3>
          <div className="flex flex-wrap items-center gap-1">
            {attackSequence.map((tid, i) => (
              <React.Fragment key={i}>
                <span className="px-2 py-1 rounded-md bg-raptor-accent/10 text-raptor-accent text-xs font-mono font-semibold">
                  {tid}
                </span>
                {i < attackSequence.length - 1 && (
                  <ChevronRight className="w-3 h-3 text-raptor-muted" />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      )}

      {/* Timeline */}
      <div className="relative">
        {/* Vertical line */}
        <div className="absolute left-6 top-0 bottom-0 w-0.5 bg-gradient-to-b from-raptor-accent via-raptor-accent2 to-raptor-danger" />

        {sorted.map((finding, i) => {
          const color = PHASE_COLORS[finding.kill_chain_phase] || '#6b7280';
          return (
            <div key={i} className="relative pl-16 pb-6 animate-slide-up" style={{ animationDelay: `${i * 0.1}s` }}>
              {/* Dot on timeline */}
              <div className="absolute left-4 w-5 h-5 rounded-full border-2 border-raptor-bg"
                   style={{ backgroundColor: color, top: '4px' }}>
                <div className="absolute inset-0 rounded-full animate-ping opacity-20"
                     style={{ backgroundColor: color }} />
              </div>

              <div className="glass-card p-4 hover:border-raptor-accent/50 transition-all">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-sm font-bold" style={{ color }}>
                        {finding.technique_id}
                      </span>
                      <span className="text-sm font-semibold text-raptor-text">
                        {finding.technique_name}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-xs px-2 py-0.5 rounded-md font-medium"
                            style={{ backgroundColor: `${color}20`, color }}>
                        {finding.kill_chain_phase}
                      </span>
                      <span className={`badge ${CONFIDENCE_STYLES[finding.confidence] || 'badge-unknown'}`}>
                        {finding.confidence}
                      </span>
                    </div>
                    <p className="text-sm text-raptor-muted leading-relaxed">
                      {finding.evidence_summary}
                    </p>
                    {finding.apt_indicators && finding.apt_indicators.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {finding.apt_indicators.map((ind, j) => (
                          <span key={j} className="text-xs px-2 py-0.5 rounded bg-raptor-warning/10 text-raptor-warning">
                            {ind}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
