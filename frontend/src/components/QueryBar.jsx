import React, { useState } from 'react';
import { Send, MessageSquare, Loader2 } from 'lucide-react';
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
      setHistory(prev => [...prev, { question, answer: result.answer, type: result.query_type }]);
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
          {answer.sources && answer.sources.length > 0 && (
            <div className="mt-3 pt-2 border-t border-raptor-border">
              <p className="text-xs text-raptor-muted mb-1">Sources:</p>
              <div className="flex flex-wrap gap-1">
                {answer.sources.slice(0, 5).map((s, i) => (
                  <span key={i} className="text-xs px-2 py-0.5 rounded bg-raptor-card text-raptor-muted font-mono">
                    {s.technique_id || s.type || 'source'}
                  </span>
                ))}
              </div>
            </div>
          )}
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
