import type { ReactNode } from 'react';
import { SearchX, AlertTriangle, Loader2 } from 'lucide-react';

export function LoadingState({ rows = 1, variant = 'card' }: { rows?: number; variant?: 'card' | 'chart' }) {
  return (
    <div>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className={`skeleton ${variant === 'chart' ? 'skel-chart' : 'skel-card'}`} style={{ marginBottom: 12 }} />
      ))}
    </div>
  );
}

export function EmptyState({ title = 'Nothing to show', message, icon }: { title?: string; message?: string; icon?: ReactNode }) {
  return (
    <div className="state-box">
      <div className="ic">{icon ?? <SearchX size={34} />}</div>
      <h4>{title}</h4>
      {message && <p>{message}</p>}
    </div>
  );
}

export function ErrorState({ message = 'Something went wrong while loading data.', onRetry }: { message?: string; onRetry?: () => void }) {
  return (
    <div className="state-box">
      <div className="ic" style={{ color: 'var(--sev-critical)' }}><AlertTriangle size={34} /></div>
      <h4>Unable to load</h4>
      <p>{message}</p>
      {onRetry && <button className="btn" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function FullPageLoader({ label = 'Loading workspace…' }: { label?: string }) {
  return (
    <div className="state-box" style={{ minHeight: '60vh' }}>
      <Loader2 size={36} className="spinner" style={{ width: 36, height: 36, borderWidth: 3 }} />
      <h4>{label}</h4>
    </div>
  );
}
