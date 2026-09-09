import { useEffect, useState } from 'react';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, BarChart, Bar, Cell,
} from 'recharts';
import { analyticsService } from '../services';
import type { AnalyticsData } from '../types';
import { LoadingState } from '../components/States';
import { SEV_COLORS } from '../lib/theme';
import { SystemHealth } from '../components/SystemHealth';
import { DemoTag } from '../components/DemoTag';

function Metric({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--r-md)', padding: 16, background: 'var(--bg)' }}>
      <div style={{ fontSize: 12, color: 'var(--muted)' }}>{label}</div>
      <div style={{ fontSize: 22, fontFamily: 'var(--font-mono)', fontWeight: 700, marginTop: 2 }}>{value}</div>
      <div style={{ fontSize: 11.5, color: 'var(--faint)', marginTop: 4 }}>{note}</div>
    </div>
  );
}

export function AnalyticsPage() {
  const [data, setData] = useState<AnalyticsData | null>(null);

  useEffect(() => {
    analyticsService.get().then(setData);
  }, []);

  if (!data) return <LoadingState rows={4} />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Analytics</h1>
          <div className="sub">Detection trends and model performance. Performance and model metrics are waiting on the backend — shown honestly as such.</div>
        </div>
        <div className="page-head-actions"><DemoTag /></div>
      </div>

      {/* Detection trends */}
      <div className="card card-pad">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <div className="chart-title">Detection Trend (per minute)</div>
          <DemoTag />
        </div>
        <ResponsiveContainer width="100%" height={240}>
          <AreaChart data={data.detectionTrend} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
            <defs><linearGradient id="gDet" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} /><stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02} /></linearGradient></defs>
            <CartesianGrid stroke="rgba(148,163,184,0.08)" vertical={false} />
            <XAxis dataKey="t" tickLine={false} axisLine={false} minTickGap={40} />
            <YAxis tickLine={false} axisLine={false} width={40} />
            <Tooltip />
            <Area type="monotone" dataKey="detections" stroke="#22d3ee" strokeWidth={2} fill="url(#gDet)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="grid-2" style={{ marginTop: 20 }}>
        {/* Confidence distribution */}
        <div className="card card-pad">
          <div className="chart-title" style={{ marginBottom: 12 }}>Confidence Distribution</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={data.confidenceDistribution} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
              <CartesianGrid stroke="rgba(148,163,184,0.08)" vertical={false} />
              <XAxis dataKey="bucket" tickLine={false} axisLine={false} tick={{ fontSize: 10 }} />
              <YAxis tickLine={false} axisLine={false} width={36} />
              <Tooltip cursor={{ fill: 'rgba(148,163,184,0.06)' }} />
              <Bar dataKey="count" name="alerts">
                {data.confidenceDistribution.map((_, i) => <Cell key={i} fill={SEV_COLORS[i > 3 ? 'LOW' : i > 1 ? 'MEDIUM' : 'HIGH']} opacity={0.85} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* System health */}
        <div className="card">
          <div className="card-head"><h3>System Health</h3><span className="hint">Components</span></div>
          <div style={{ padding: 16 }}><SystemHealth /></div>
        </div>
      </div>

      {/* Severity trend placeholder with honest label */}
      <div className="section" style={{ marginTop: 20 }}>
        <div className="card card-pad">
          <div className="chart-title" style={{ marginBottom: 4 }}>Severity Trend</div>
          <div style={{ fontSize: 12.5, color: 'var(--faint)', marginBottom: 12 }}>
            <span className="demo-badge" style={{ fontSize: 10 }}>Awaiting Backend Data</span> — severity time-series will populate once the detection API is connected.
          </div>
          <div style={{ height: 200, display: 'grid', placeItems: 'center', border: '1px dashed var(--border)', borderRadius: 'var(--r-md)' }}>
            <div style={{ textAlign: 'center', color: 'var(--muted)' }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 18 }}>—</div>
              <div style={{ fontSize: 12.5, marginTop: 6 }}>No severity trend data yet</div>
            </div>
          </div>
        </div>
      </div>

      {/* Operational metrics */}
      <div className="section" style={{ marginTop: 20 }}>
        <div className="card card-pad">
          <div className="chart-title" style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>Processing & Resource Metrics <span className="demo-tag" style={{ fontSize: 9 }}><span className="dot" />Awaiting Backend</span></div>
          <div className="grid-2">
            <Metric label="Processing Latency" value="Awaiting data" note="Awaiting Backend Data · avg detection latency (ms)" />
            <Metric label="Throughput" value="Awaiting data" note="Awaiting Backend Data · packets/s" />
            <Metric label="CPU Utilization" value="Awaiting data" note="Awaiting Backend Data · %" />
            <Metric label="RAM Utilization" value="Awaiting data" note="Awaiting Backend Data · %" />
          </div>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 16, background: 'var(--accent-dim)', border: '1px solid rgba(34,211,238,0.2)', padding: '10px 12px', borderRadius: 'var(--r-sm)' }}>
            These metrics are intentionally left unfilled rather than fabricating performance claims. They will come from the backend detection engine once connected.
          </div>
        </div>
      </div>

      {/* Model performance */}
      <div className="section" style={{ marginTop: 20 }}>
        <div className="card card-pad">
          <div className="chart-title" style={{ marginBottom: 4 }}>Model Performance</div>
          <div style={{ fontSize: 12.5, color: 'var(--faint)', marginBottom: 16 }}>
            <span className="demo-badge" style={{ fontSize: 10 }}>Awaiting Backend Data</span> — no real accuracy / precision / recall / F1 values are reported.
          </div>
          <div className="grid-2">
            <Metric label="Accuracy" value="—" note="Not reported (backend pending)" />
            <Metric label="Precision" value="—" note="Not reported (backend pending)" />
            <Metric label="Recall" value="—" note="Not reported (backend pending)" />
            <Metric label="F1 Score" value="—" note="Not reported (backend pending)" />
          </div>
        </div>
      </div>
    </>
  );
}
