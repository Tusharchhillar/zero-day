import { useEffect, useMemo, useState } from 'react';
import { activityService } from '../services';
import type { ActivityEvent } from '../types';
import { SeverityBadge } from '../components/Badge';
import { LoadingState, EmptyState, ErrorState } from '../components/States';
import { relTime, SEV_COLORS } from '../lib/theme';

type Filter = 'All' | 'Critical' | 'High' | 'Medium' | 'Low' | 'System';

const FILTERS: Filter[] = ['All', 'Critical', 'High', 'Medium', 'Low', 'System'];

const DOT_COLOR: Record<string, string> = {
  CRITICAL: SEV_COLORS.CRITICAL,
  HIGH: SEV_COLORS.HIGH,
  MEDIUM: SEV_COLORS.MEDIUM,
  LOW: SEV_COLORS.LOW,
  SYSTEM: '#38bdf8',
};

const SERVER_ICON: Record<string, string> = {
  'Alert Pipeline': '⇢',
  'Detection Engine': '⚙',
  'Traffic Monitor': '⇄',
  'Database': '▤',
};

function KindTag({ kind }: { kind: ActivityEvent['kind'] }) {
  const label = kind === 'detection' ? 'Detection' : kind === 'system' ? 'System' : 'Status';
  return <span className={`tl-kind ${kind}`}>{label}</span>;
}

export function ActivityPage() {
  const [events, setEvents] = useState<ActivityEvent[] | null>(null);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState<Filter>('All');

  useEffect(() => {
    let alive = true;
    activityService.list()
      .then((e) => alive && setEvents(e))
      .catch(() => alive && setError('Failed to load activity feed.'));
    return () => { alive = false; };
  }, []);

  const filtered = useMemo(() => {
    if (!events) return [];
    if (filter === 'All') return events;
    if (filter === 'System') return events.filter((e) => e.kind === 'system');
    // severity values are uppercase; filter labels are Title-case
    const sev = filter.toUpperCase();
    return events.filter((e) => e.severity !== 'SYSTEM' && e.severity === sev);
  }, [events, filter]);

  const counts = useMemo(() => {
    const c: Record<Filter, number> = { All: events?.length ?? 0, Critical: 0, High: 0, Medium: 0, Low: 0, System: 0 };
    (events ?? []).forEach((e) => {
      if (e.kind === 'system') c.System++;
      else c[e.severity === 'CRITICAL' ? 'Critical' : e.severity === 'HIGH' ? 'High' : e.severity === 'MEDIUM' ? 'Medium' : 'Low']++;
    });
    return c;
  }, [events]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Activity</h1>
          <div className="sub">A live SOC event timeline — threat detections, system events and alert status changes.</div>
        </div>
      </div>

      <div className="card">
        <div className="card-head" style={{ flexWrap: 'wrap', gap: 12 }}>
          <h3>Event Timeline</h3>
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 12, color: 'var(--muted)' }}>now</span>
          </div>
        </div>

        <div style={{ padding: '16px 20px 0' }}>
          <div className="tl-filters" role="group" aria-label="Activity filter">
            {FILTERS.map((f) => {
              const cls = f === 'All' ? 'tl-filter' : `tl-filter ${f.toLowerCase()}`;
              return (
                <button
                  key={f}
                  className={`${cls}${filter === f ? ' active' : ''}`}
                  aria-pressed={filter === f}
                  onClick={() => setFilter(f)}
                >
                  {f} <span style={{ opacity: 0.6, fontFamily: 'var(--font-mono)' }}>{counts[f]}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div style={{ padding: '18px 20px 12px' }}>
          {error ? (
            <ErrorState message={error} onRetry={() => window.location.reload()} />
          ) : !events ? (
            <LoadingState rows={5} />
          ) : filtered.length === 0 ? (
            <EmptyState title="No matching events" message="Try a different filter." />
          ) : (
            <div className="timeline">
              {filtered.map((e) => (
                <div className="tl-item" key={e.id}>
                  <span className="tl-dot" style={{ background: DOT_COLOR[e.severity] }} />
                  <div className="tl-time">
                    {new Date(e.timestamp).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })} · {relTime(e.timestamp)}
                  </div>
                  <div className="tl-card">
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span className="tl-title">{e.title}</span>
                      {e.kind !== 'system' && <SeverityBadge severity={e.severity as any} />}
                      <KindTag kind={e.kind} />
                    </div>
                    <div className="tl-desc">{e.description}</div>
                    <div className="tl-meta">
                      {e.kind === 'detection' && (
                        <>
                          <span>{e.threatClass}</span>
                          {e.sourceIp && <span className="mono">{e.sourceIp} → {e.destIp}</span>}
                          {e.protocol && <span>{e.protocol}</span>}
                          {typeof e.confidence === 'number' && <span>Confidence <b style={{ color: 'var(--ink)' }}>{Math.round(e.confidence * 100)}%</b></span>}
                        </>
                      )}
                      {e.kind === 'status' && (
                        <>
                          {e.alertId && <span className="mono">{e.alertId}</span>}
                          {e.fromStatus && <span><b>{e.fromStatus}</b> → <b style={{ color: 'var(--ink)' }}>{e.toStatus}</b></span>}
                        </>
                      )}
                      {e.kind === 'system' && (
                        <>
                          {e.system && <span>{SERVER_ICON[e.system] ?? '▪'} {e.system}</span>}
                          {e.duration && <span>· {e.duration}</span>}
                        </>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}