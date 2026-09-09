import { useEffect, useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { threatService } from '../services';
import type { ThreatDistributionSlice } from '../types';
import { CATEGORY_COLORS, CATEGORY_ORDER } from '../lib/theme';
import { DemoTag } from './DemoTag';

function DonutTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload as ThreatDistributionSlice;
  const pct = ((d.count / (payload[0].payload.total || 1)) * 100).toFixed(1);
  return (
    <div style={{ background: 'var(--surface-3)', border: '1px solid var(--border-strong)', borderRadius: 10, padding: '10px 12px', boxShadow: 'var(--shadow-md)' }}>
      <div style={{ fontSize: 12.5, fontWeight: 600, marginBottom: 4 }}>{d.category}</div>
      <div style={{ fontSize: 12, color: 'var(--ink-2)' }}>{d.count} detections · {pct}%</div>
      <div style={{ fontSize: 12, color: 'var(--muted)' }}>Severity {d.severity} · conf {Math.round(d.confidence * 100)}%</div>
    </div>
  );
}

export function ThreatDistribution({ height = 280 }: { height?: number }) {
  const [data, setData] = useState<{ total: number; slices: ThreatDistributionSlice[] } | null>(null);

  useEffect(() => {
    threatService.distribution().then(setData);
  }, []);

  if (!data) return <div className="skeleton skel-chart" />;

  // order slices by the canonical category order
  const ordered = CATEGORY_ORDER
    .map((c) => data.slices.find((s) => s.category === c))
    .filter((s): s is ThreatDistributionSlice => !!s)
    .map((s) => ({ ...s, total: data.total }));

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><div className="chart-title">Threat Distribution</div><DemoTag /></div>
        <div className="hint" style={{ fontSize: 12.5, color: 'var(--muted)' }}>
          <b style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--ink)' }}>{data.total}</b> total detections
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 4 }}>
        <ResponsiveContainer width="62%" height={height}>
          <PieChart>
            <Pie data={ordered} dataKey="count" nameKey="category" innerRadius="58%" outerRadius="88%" paddingAngle={3} stroke="none">
              {ordered.map((s) => (
                <Cell key={s.category} fill={CATEGORY_COLORS[s.category]} />
              ))}
            </Pie>
            <Tooltip content={<DonutTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 10 }}>
          {ordered.map((s) => {
            const pct = ((s.count / data.total) * 100).toFixed(1);
            return (
              <div key={s.category} style={{ fontSize: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--ink-2)', marginBottom: 3 }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <span style={{ width: 9, height: 9, borderRadius: 3, background: CATEGORY_COLORS[s.category] }} />
                    {s.category}
                  </span>
                  <b style={{ fontFamily: 'var(--font-mono)', color: 'var(--ink)' }}>{pct}%</b>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
