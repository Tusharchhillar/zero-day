import { useEffect, useState } from 'react';
import { alertService } from '../services';
import type { Alert } from '../types';
import { SeverityBadge } from './Badge';
import { SEV_COLORS, relTime } from '../lib/theme';

export function LiveAlertList({ limit = 8, onSelect }: { limit?: number; onSelect: (a: Alert) => void }) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    alertService.list().then((all) => {
      setAlerts(all.slice(0, limit));
      setLoading(false);
    });
  }, [limit]);

  if (loading) return <div className="skeleton skel-card" />;
  if (alerts.length === 0) return <div className="state-box"><p>No alerts.</p></div>;

  return (
    <div className="live-alert-list">
      {alerts.map((a) => (
        <div className="live-alert" key={a.id} onClick={() => onSelect(a)} role="button" tabIndex={0}
          onKeyDown={(e) => e.key === 'Enter' && onSelect(a)}>
          <div className="rail" style={{ background: SEV_COLORS[a.severity] }} />
          <div className="body">
            <div className="title-row">
              <span className="a-title">{a.threatClass}</span>
              <SeverityBadge severity={a.severity} />
            </div>
            <div className="a-meta" style={{ marginTop: 3 }}>
              {a.source.ip}:{a.source.port} <span className="ip-arrow">→</span> {a.destination.ip}:{a.destination.port} · {a.protocol}
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 4 }}>
              <span style={{ fontSize: 12, color: 'var(--muted)' }}>{a.summary}</span>
              <span className="a-time">{relTime(a.timestamp)}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
