import React from 'react';
import { Zap, AlertTriangle, ShieldAlert } from 'lucide-react';

const URGENCY_STYLES = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30' },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30' },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30' },
};

export default function Simulation({ predictions, aptGroup, confidence }) {
  if (!predictions || predictions.length === 0) {
    return (
      <div className="glass-card p-8 text-center">
        <Zap className="w-12 h-12 mx-auto text-raptor-muted mb-3" />
        <p className="text-raptor-muted">Run simulation to see predicted next steps</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold gradient-text flex items-center gap-2">
          <ShieldAlert className="w-5 h-5" />
          Predicted Next Steps
        </h3>
        {aptGroup && (
          <span className="text-xs px-3 py-1 rounded-full bg-raptor-danger/10 border border-raptor-danger/30 text-raptor-danger font-medium">
            Simulating: {aptGroup}
          </span>
        )}
      </div>

      {predictions.map((pred, i) => {
        const style = URGENCY_STYLES[pred.urgency] || URGENCY_STYLES.medium;
        return (
          <div key={i} className="glass-card p-5 animate-slide-up" style={{ animationDelay: `${i * 0.15}s` }}>
            <div className="flex items-start justify-between mb-3">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-bold text-raptor-accent font-mono">{pred.technique_id}</span>
                  <span className="text-sm font-semibold text-raptor-text">{pred.technique_name}</span>
                </div>
              </div>
              <span className={`badge ${style.bg} ${style.border} ${style.color} border`}>
                {pred.urgency}
              </span>
            </div>

            <p className="text-sm text-raptor-muted mb-3">{pred.rationale}</p>

            {pred.likely_tools && pred.likely_tools.length > 0 && (
              <div className="mb-3">
                <p className="text-xs text-raptor-muted font-semibold mb-1">Likely Tools:</p>
                <div className="flex flex-wrap gap-1">
                  {pred.likely_tools.map((tool, j) => (
                    <span key={j} className="text-xs px-2 py-0.5 rounded bg-raptor-card text-raptor-warning font-mono">
                      {tool}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {pred.detection_guidance && (
              <div className="p-3 rounded-lg bg-raptor-success/5 border border-raptor-success/20">
                <p className="text-xs text-raptor-success font-semibold mb-1 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" /> Detection Guidance
                </p>
                <p className="text-xs text-raptor-success/80">{pred.detection_guidance}</p>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
