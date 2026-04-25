import React, { useState } from 'react';
import { Code2, Database, FileText, Loader2, MessageSquare, Send } from 'lucide-react';
import { queryAPI } from '../api';

export default function QueryBar({ investigationId }) {
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);

  const suggestions = [
    "How many hops from initial compromise to domain admin?",
    "Which techniques overlap with Cozy Bear's known playbook?",
    "What should I block right now to contain this attack?",
    "Show all lateral movement paths",
    "What would the attacker do next?",
  ];

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!question.trim() || !investigationId) return;

    setLoading(true);
    try {
      const response = await queryAPI.ask(question, investigationId);
      const result = response.data;
      setAnswer(result);
      setHistory(prev => [...prev, { question, answer: result.answer, type: result.query_type, sources: result.sources || [] }]);
    } catch (err) {
      setAnswer({ answer: 'Error: ' + (err.response?.data?.detail || 'Query failed'), confidence: 'low' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 mb-2">
        <MessageSquare className="w-5 h-5 text-raptor-accent" />
        <h3 className="text-lg font-semibold gradient-text">Ask RAPTOR</h3>
      </div>

      {/* Query Input */}
      <form onSubmit={handleSubmit} className="flex gap-2">
        <input type="text" value={question} onChange={(e) => setQuestion(e.target.value)}
          placeholder="Ask about the investigation in plain English..."
          className="flex-1 px-4 py-3 rounded-lg bg-raptor-card border border-raptor-border text-raptor-text placeholder-raptor-muted/50 focus:outline-none focus:border-raptor-accent focus:ring-1 focus:ring-raptor-accent/30 transition-all"
          disabled={loading || !investigationId} />
        <button type="submit" disabled={loading || !question.trim()}
          className="px-4 py-3 rounded-lg bg-raptor-accent text-white font-medium hover:bg-raptor-accent2 disabled:opacity-50 disabled:cursor-not-allowed transition-all">
          {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Send className="w-5 h-5" />}
        </button>
      </form>

      {/* Suggestions */}
      {!answer && history.length === 0 && (
        <div className="flex flex-wrap gap-2">
          {suggestions.map((s, i) => (
            <button key={i} onClick={() => setQuestion(s)}
              className="text-xs px-3 py-1.5 rounded-full bg-raptor-card border border-raptor-border text-raptor-muted hover:border-raptor-accent hover:text-raptor-accent transition-all">
              {s}
            </button>
          ))}
        </div>
      )}

      {/* Answer */}
      {answer && (
        <div className="glass-card p-4 animate-slide-up">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-xs px-2 py-0.5 rounded bg-raptor-accent/10 text-raptor-accent font-medium">
              {answer.query_type || 'rag'}
            </span>
            {answer.confidence && (
              <span className={`badge ${answer.confidence === 'high' ? 'badge-high' : answer.confidence === 'medium' ? 'badge-medium' : 'badge-low'}`}>
                {answer.confidence}
              </span>
            )}
          </div>
          <p className="text-sm text-raptor-text leading-relaxed whitespace-pre-wrap">{answer.answer}</p>
          <SourceList sources={answer.sources || []} />
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="space-y-2 mt-4 max-h-64 overflow-y-auto">
          {history.slice().reverse().slice(1).map((item, i) => (
            <div key={i} className="p-3 rounded-lg bg-raptor-bg/50 border border-raptor-border/50">
              <p className="text-xs text-raptor-accent font-medium mb-1">Q: {item.question}</p>
              <p className="text-xs text-raptor-muted">{item.answer?.substring(0, 200)}...</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SourceList({ sources }) {
  if (!sources.length) {
    return (
      <div className="query-sources empty">
        <Database className="w-4 h-4" />
        <span>No grounding sources returned.</span>
      </div>
    );
  }

  return (
    <div className="query-sources">
      {sources.slice(0, 6).map((source, index) => (
        <div key={index} className="source-card">
          <div className="source-card-title">
            {source.query ? <Code2 className="w-3.5 h-3.5" /> : source.type === 'threat_report' ? <FileText className="w-3.5 h-3.5" /> : <Database className="w-3.5 h-3.5" />}
            <strong>{source.technique_id || source.title || source.type || 'source'}</strong>
            {source.status && <span>{source.status}</span>}
          </div>
          {source.name && <p>{source.name}</p>}
          {source.apt_group && <p>{source.apt_group}</p>}
          {source.detail && <p>{source.detail}</p>}
          {source.query && (
            <pre>
              <code>{source.query}</code>
            </pre>
          )}
          {source.results && (
            <p>{source.results.length} graph rows returned</p>
          )}
        </div>
      ))}
    </div>
  );
}
