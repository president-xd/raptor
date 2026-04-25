import React from 'react';
import { Cpu, FileCode, Globe, Server, Shield, User, X } from 'lucide-react';

const TYPE_ICONS = {
  host: Server,
  user: User,
  process: Cpu,
  file: FileCode,
  network: Globe,
  technique: Shield,
};

export default function NodeDetail({ node, onClose }) {
  if (!node) return null;

  const nodeType = node.node_type || node.type || 'host';
  const Icon = TYPE_ICONS[nodeType] || Server;

  return (
    <div className="glass-card p-5 animate-slide-up">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3 min-w-0">
          <div
            className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ backgroundColor: `${node.color || '#3b82f6'}22` }}
          >
            <Icon className="w-5 h-5" style={{ color: node.color || '#60a5fa' }} />
          </div>
          <div className="min-w-0">
            <h4 className="font-semibold text-raptor-text truncate">{node.label}</h4>
            <p className="text-xs text-raptor-muted capitalize">{nodeType}</p>
          </div>
        </div>
        <button type="button" onClick={onClose} className="p-1 rounded hover:bg-raptor-card transition-colors">
          <X className="w-4 h-4 text-raptor-muted" />
        </button>
      </div>

      {node.metadata && (
        <div className="space-y-2">
          {Object.entries(node.metadata).map(([key, value]) => (
            <div key={key} className="flex justify-between items-center gap-3 py-1 border-b border-raptor-border/30">
              <span className="text-xs text-raptor-muted capitalize">{key.replace(/_/g, ' ')}</span>
              <span className="text-xs text-raptor-text font-mono text-right break-all">
                {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value || '-')}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
