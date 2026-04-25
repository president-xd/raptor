import React from 'react';
import { Target, AlertTriangle, CheckCircle, HelpCircle, Shield } from 'lucide-react';

const CONFIDENCE_CONFIG = {
  HIGH: { icon: CheckCircle, color: 'text-raptor-success', bg: 'bg-raptor-success/10', border: 'border-raptor-success/30' },
  MEDIUM: { icon: AlertTriangle, color: 'text-raptor-warning', bg: 'bg-raptor-warning/10', border: 'border-raptor-warning/30' },
  LOW: { icon: AlertTriangle, color: 'text-raptor-danger', bg: 'bg-raptor-danger/10', border: 'border-raptor-danger/30' },
  UNKNOWN: { icon: HelpCircle, color: 'text-raptor-muted', bg: 'bg-raptor-muted/10', border: 'border-raptor-muted/30' },
};

export default function Attribution({ attributionResults }) {
  if (!attributionResults || attributionResults.length === 0) {
    return (
      <div className="glass-card p-8 text-center">
        <Target className="w-12 h-12 mx-auto text-raptor-muted mb-3" />
        <p className="text-raptor-muted">Attribution data will appear after analysis</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold gradient-text flex items-center gap-2">
        <Shield className="w-5 h-5" />
        APT Attribution
      </h3>

      {attributionResults.map((result, i) => {
        const conf = CONFIDENCE_CONFIG[result.confidence_label] || CONFIDENCE_CONFIG.UNKNOWN;
        const Icon = conf.icon;
        const isTop = i === 0;
        const isReliableTop = isTop && ['HIGH', 'MEDIUM'].includes((result.confidence_label || '').toUpperCase());
        const isUnreliableTop = isTop && !isReliableTop;

        return (
          <div key={i} className={`glass-card p-5 transition-all ${isReliableTop ? 'border-raptor-accent/40 animate-glow' : ''}`}>
            <div className="flex items-start justify-between mb-3">
              <div>
                <div className="flex items-center gap-2">
                  {isReliableTop && <span className="text-xs px-2 py-0.5 rounded-full bg-raptor-accent/20 text-raptor-accent font-semibold">TOP MATCH</span>}
                  {isUnreliableTop && <span className="text-xs px-2 py-0.5 rounded-full bg-raptor-warning/15 text-raptor-warning font-semibold">TENTATIVE</span>}
                  <h4 className="text-lg font-bold text-raptor-text">{result.apt_name}</h4>
                </div>
                {result.aliases && result.aliases.length > 0 && (
                  <p className="text-xs text-raptor-muted mt-0.5">
                    aka {result.aliases.slice(0, 3).join(', ')}
                  </p>
                )}
                {isUnreliableTop && (
                  <p className="text-xs text-raptor-warning mt-1">
                    Confidence too low for trusted attribution. Treat as unconfirmed.
                  </p>
                )}
              </div>
              <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg ${conf.bg} border ${conf.border}`}>
                <Icon className={`w-4 h-4 ${conf.color}`} />
                <span className={`text-sm font-bold ${conf.color}`}>
                  {(result.confidence_score * 100).toFixed(0)}%
                </span>
                <span className={`text-xs ${conf.color}`}>{result.confidence_label}</span>
              </div>
            </div>

            {/* Confidence Bar */}
            <div className="mb-3">
              <div className="progress-bar">
                <div className="progress-bar-fill" style={{ width: `${result.confidence_score * 100}%` }} />
              </div>
            </div>

            {/* Overlapping TTPs */}
            <div className="mb-3">
              <p className="text-xs text-raptor-muted mb-1.5 uppercase tracking-wider font-semibold">
                Overlapping Techniques ({result.overlapping_ttps?.length || 0})
              </p>
              <div className="flex flex-wrap gap-1">
                {(result.overlapping_ttps || []).slice(0, 10).map((ttp, j) => (
                  <span key={j} className="text-xs px-2 py-0.5 rounded bg-raptor-accent/10 text-raptor-accent font-mono">
                    {ttp}
                  </span>
                ))}
                {(result.overlapping_ttps || []).length > 10 && (
                  <span className="text-xs px-2 py-0.5 rounded bg-raptor-card text-raptor-muted">
                    +{result.overlapping_ttps.length - 10} more
                  </span>
                )}
              </div>
            </div>

            {/* Penalties & Bonuses */}
            {result.penalties_applied && result.penalties_applied.length > 0 && (
              <div className="mt-2 space-y-1">
                {result.penalties_applied.map((p, j) => (
                  <p key={j} className="text-xs text-raptor-danger/80 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> {p}
                  </p>
                ))}
              </div>
            )}
            {result.bonuses_applied && result.bonuses_applied.length > 0 && (
              <div className="mt-2 space-y-1">
                {result.bonuses_applied.map((b, j) => (
                  <p key={j} className="text-xs text-raptor-success/80 flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" /> {b}
                  </p>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
