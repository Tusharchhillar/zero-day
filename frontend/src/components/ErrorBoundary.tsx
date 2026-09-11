import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[ErrorBoundary caught error]:', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    this.props.onReset?.();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          padding: '24px',
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--r-lg)',
          margin: '16px 0',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          textAlign: 'center',
          gap: '12px',
        }}>
          <div style={{
            width: 44,
            height: 44,
            borderRadius: '50%',
            background: 'rgba(239, 68, 68, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--danger)',
          }}>
            <AlertTriangle size={22} />
          </div>
          <h3 style={{ fontSize: 16, margin: 0, color: 'var(--ink)' }}>
            {this.props.fallbackTitle || 'Something went wrong displaying this view'}
          </h3>
          <p style={{ fontSize: 13, color: 'var(--muted)', maxWidth: 460, margin: 0 }}>
            {this.state.error?.message || 'An unexpected rendering error occurred.'}
          </p>
          <button className="btn btn-sm btn-primary" onClick={this.handleReset} style={{ marginTop: 8 }}>
            <RefreshCw size={14} /> Try again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
