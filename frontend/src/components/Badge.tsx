import type { Severity, SystemStatus } from '../types';

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`sev-badge sev-${severity}`}>
      <span className="sev-dot" />
      {severity}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const tone = (status === 'New' && 'critical') || (status === 'Investigating' && 'high') || (status === 'Acknowledged' && 'medium') || 'low';
  const cls = tone === 'critical' ? 'sev-CRITICAL' : tone === 'high' ? 'sev-HIGH' : tone === 'medium' ? 'sev-MEDIUM' : 'sev-LOW';
  return <span className={`sev-badge ${cls}`}>{status}</span>;
}

export function HealthBadge({ status }: { status: SystemStatus }) {
  return <span className={`status-pill health-${status}`}>{status}</span>;
}
