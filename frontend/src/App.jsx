import React from 'react';
import Dashboard from './components/Dashboard';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('[RAPTOR] Render error:', error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          height: '100vh', gap: '12px', fontFamily: 'monospace', color: '#b42318', background: '#10100e',
        }}>
          <strong style={{ fontSize: '18px' }}>RAPTOR | Render Error</strong>
          <p style={{ color: '#888', maxWidth: '480px', textAlign: 'center' }}>
            {this.state.error.message || 'An unexpected error occurred.'}
          </p>
          <button
            type="button"
            onClick={() => this.setState({ error: null })}
            style={{
              marginTop: '8px', padding: '8px 20px', background: '#b42318', color: '#fff',
              border: 'none', borderRadius: '4px', fontFamily: 'inherit', cursor: 'pointer',
            }}
          >
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  return (
    <ErrorBoundary>
      <Dashboard />
    </ErrorBoundary>
  );
}
