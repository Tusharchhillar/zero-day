import { useState, useEffect, useRef, useCallback } from 'react';
import {
  ResponsiveContainer, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ComposedChart, Line,
} from 'recharts';
import type { TrafficPoint } from '../types';
import { trafficService } from '../services';

const RANGES = ['1H', '6H', '24H', '7D', '30D'];

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'rgba(6, 12, 28, 0.96)',
      border: '1px solid rgba(0, 212, 255, 0.3)',
      borderRadius: 12,
      padding: '12px 14px',
      boxShadow: '0 0 24px rgba(0, 200, 255, 0.15), 0 8px 32px rgba(0, 0, 0, 0.5)',
      backdropFilter: 'blur(20px)',
    }}>
      <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 6, fontFamily: 'var(--font-mono)' }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.name} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, marginTop: 3 }}>
          <span style={{
            width: 8, height: 8, borderRadius: 3, background: p.color,
            boxShadow: `0 0 8px ${p.color}aa`,
          }} />
          <span style={{ color: 'var(--ink-2)' }}>{p.name}:</span>
          <b style={{ fontFamily: 'var(--font-mono)', color: 'var(--ink)' }}>{p.value}</b>
        </div>
      ))}
    </div>
  );
}

/**
 * Generate a new animated data point that drifts from the last known value,
 * creating a smooth "live monitoring" feel.
 */
function driftPoint(last: TrafficPoint): TrafficPoint {
  const now = new Date();
  const t = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;

  const volume = Math.max(0, last.volume + (Math.random() - 0.48) * 2.5);
  const suspicious = Math.max(0, last.suspicious + (Math.random() - 0.5) * 0.4);
  const flows = Math.max(0, Math.round(last.flows + (Math.random() - 0.45) * 80));

  return { t, volume: +volume.toFixed(2), suspicious: +suspicious.toFixed(2), flows };
}

export function TrafficChart({ height = 300 }: { height?: number }) {
  const [range, setRange] = useState('24H');
  const [data, setData] = useState<TrafficPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [live, setLive] = useState(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const dataRef = useRef<TrafficPoint[]>([]);

  // Keep ref in sync
  useEffect(() => { dataRef.current = data; }, [data]);

  // Fetch initial data
  useEffect(() => {
    let alive = true;
    setLoading(true);
    trafficService.series(range).then((d) => {
      if (alive) { setData(d); setLoading(false); }
    });
    return () => { alive = false; };
  }, [range]);

  // Live animation: append a new drifted point every 2 seconds
  const startLive = useCallback(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    intervalRef.current = setInterval(() => {
      const current = dataRef.current;
      if (current.length === 0) return;
      const last = current[current.length - 1];
      const next = driftPoint(last);
      setData((prev) => {
        const updated = [...prev, next];
        // Keep max 60 points to avoid perf issues
        return updated.length > 60 ? updated.slice(-60) : updated;
      });
    }, 2000);
  }, []);

  useEffect(() => {
    if (live && !loading && data.length > 0) {
      startLive();
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [live, loading, data.length, startLive]);

  if (loading && data.length === 0) return <div className="skeleton skel-chart" />;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div className="chart-title">Network Traffic Overview</div>
          <button
            className={`btn btn-sm ${live ? 'btn-active' : ''}`}
            onClick={() => setLive((v) => !v)}
            style={{ fontSize: 11, height: 26, padding: '0 10px', gap: 5 }}
          >
            <span style={{
              width: 6, height: 6, borderRadius: '50%',
              background: live ? 'var(--sev-healthy)' : 'var(--faint)',
              boxShadow: live ? '0 0 8px rgba(48, 224, 96, 0.6)' : 'none',
              animation: live ? 'pulse-dot 2s ease-in-out infinite' : 'none',
            }} />
            {live ? 'LIVE' : 'PAUSED'}
          </button>
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
              <stop offset="0%" stopColor="#a855f7" stopOpacity={0.4} />
              <stop offset="100%" stopColor="#a855f7" stopOpacity={0.01} />
            </linearGradient>
            <linearGradient id="gSus" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#ff4060" stopOpacity={0.55} />
              <stop offset="100%" stopColor="#ff4060" stopOpacity={0.04} />
            </linearGradient>
            <filter id="glow">
              <feGaussianBlur stdDeviation="2.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <filter id="glowStrong">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <CartesianGrid stroke="rgba(0, 190, 255, 0.07)" vertical={false} strokeDasharray="3 3" />
          <XAxis dataKey="t" tickLine={false} axisLine={false} minTickGap={40} />
          <YAxis yAxisId="mbps" tickLine={false} axisLine={false} width={44} />
          <YAxis yAxisId="flows" orientation="right" tickLine={false} axisLine={false} width={44} />
          <Tooltip content={<ChartTooltip />} />
          <Legend wrapperStyle={{ fontSize: 12, paddingTop: 8 }} iconType="plainline" />
          <Area yAxisId="mbps" type="monotone" dataKey="volume" name="Traffic volume (Mbps)" stroke="#a855f7" strokeWidth={2.5} fill="url(#gVol)" filter="url(#glow)" isAnimationActive={true} animationDuration={800} animationEasing="ease-out" />
          <Area yAxisId="mbps" type="monotone" dataKey="suspicious" name="Suspicious (Mbps)" stroke="#ff4060" strokeWidth={1.8} fill="url(#gSus)" filter="url(#glow)" isAnimationActive={true} animationDuration={800} />
          <Line yAxisId="flows" type="monotone" dataKey="flows" name="Flows" stroke="#8b5cf6" strokeWidth={1.8} dot={false} strokeDasharray="5 4" filter="url(#glowStrong)" isAnimationActive={true} animationDuration={800} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}
