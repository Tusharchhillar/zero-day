import { useEffect, useState } from 'react';
import { BarChart, Bar, ResponsiveContainer, Cell } from 'recharts';
import { threatService } from '../services';
import type { ThreatActivityItem } from '../types';
import { SEV_COLORS, CATEGORY_COLORS, fmtDelta } from '../lib/theme';
import { SeverityBadge } from './Badge';

export function ThreatActivity({ onSelect }: { onSelect?: (item: ThreatActivityItem) => void }) {
  const [items, setItems] = useState<ThreatActivityItem[]>([]);

  useEffect(() => {
    threatService.activity().then(setItems);
  }, []);

  if (items.length === 0) return <div className="skeleton skel-chart" />;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {items.map((t) => (
        <div className="threat-card" key={t.category} onClick={() => onSelect?.(t)} role="button" tabIndex={0}
          onKeyDown={(e) => e.key === 'Enter' && onSelect?.(t)}>
          <div className="tc-top">
            <div className="tc-name" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 9, height: 9, borderRadius: 3, background: CATEGORY_COLORS[t.category] }} />
              {t.category}
              <SeverityBadge severity={t.severity} />
            </div>
            <div className="tc-desc" style={{ marginTop: 3 }}>{t.description}</div>
            <div className="threat-meta">
              <span>Detections <b style={{ color: SEV_COLORS[t.severity] }}>{t.count}</b></span>
              <span>Confidence <b>{Math.round(t.confidence * 100)}%</b></span>
              <span>Trend <b style={{ color: t.trend >= 0 ? 'var(--sev-critical)' : 'var(--sev-healthy)' }}>{fmtDelta(t.trend)}</b></span>
            </div>
          </div>
          <div style={{ width: 140, height: 44 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={t.spark.map((v, i) => ({ i, v }))} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
                <Bar dataKey="v">
                  {t.spark.map((_, i) => (
                    <Cell key={i} fill={SEV_COLORS[t.severity]} fillOpacity={0.85} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      ))}
    </div>
  );
}
