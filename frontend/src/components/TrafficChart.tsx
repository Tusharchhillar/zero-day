import { useState, useEffect } from 'react';
import {
  ResponsiveContainer, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ComposedChart, Line,
} from 'recharts';
import type { TrafficPoint } from '../types';
import { trafficService } from '../services';
import { DemoTag } from './DemoTag';

const RANGES = ['1H', '6H', '24H', '7D', '30D'];

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: 'var(--surface-3)', border: '1px solid var(--border-strong)', borderRadius: 10, padding: '10px 12px', boxShadow: 'var(--shadow-md)' }}>
      <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 4, fontFamily: 'var(--font-mono)' }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.name} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, marginTop: 2 }}>
          <span style={{ width: 8, height: 8, borderRadius: 2, background: p.color }} />
          <span style={{ color: 'var(--ink-2)' }}>{p.name}:</span>
          <b style={{ fontFamily: 'var(--font-mono)', color: 'var(--ink)' }}>{p.value}</b>
        </div>
      ))}
    </div>
  );
}

export function TrafficChart({ height = 300 }: { height?: number }) {
  const [range, setRange] = useState('24H');
  const [data, setData] = useState<TrafficPoint[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    trafficService.series(range).then((d) => {
      if (alive) { setData(d); setLoading(false); }
    });
    return () => { alive = false; };
  }, [range]);

  if (loading && data.length === 0) return <div className="skeleton skel-chart" />;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className="chart-title">Network Traffic Overview</div>
          <DemoTag />
        </div>
        <div className="time-range" role="tablist" aria-label="Time range">
          {RANGES.map((r) => (
            <button key={r} role="tab" aria-selected={range === r} className={range === r ? 'active' : ''} onClick={() => setRange(r)}>
              {r}
            </button>
          ))}
        </div>
      </div>
      <ResponsiveContainer width="100%" height={height}>
        <ComposedChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="gVol" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.32} />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id="gSus" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.5} />
              <stop offset="100%" stopColor="#f43f5e" stopOpacity={0.05} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(148,163,184,0.08)" vertical={false} />
          <XAxis dataKey="t" tickLine={false} axisLine={false} minTickGap={40} />
          <YAxis yAxisId="mbps" tickLine={false} axisLine={false} width={44} />
          <YAxis yAxisId="flows" orientation="right" tickLine={false} axisLine={false} width={44} />
          <Tooltip content={<ChartTooltip />} />
          <Legend wrapperStyle={{ fontSize: 12, paddingTop: 8 }} iconType="plainline" />
          <Area yAxisId="mbps" type="monotone" dataKey="volume" name="Traffic volume (Mbps)" stroke="#22d3ee" strokeWidth={2} fill="url(#gVol)" />
          <Area yAxisId="mbps" type="monotone" dataKey="suspicious" name="Suspicious (Mbps)" stroke="#f43f5e" strokeWidth={1.6} fill="url(#gSus)" />
          <Line yAxisId="flows" type="monotone" dataKey="flows" name="Flows" stroke="#a78bfa" strokeWidth={1.6} dot={false} strokeDasharray="4 3" />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}
