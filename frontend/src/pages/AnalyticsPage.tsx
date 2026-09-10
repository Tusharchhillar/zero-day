import { useEffect, useState } from 'react';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, BarChart, Bar, Cell,
} from 'recharts';
import { analyticsService } from '../services';
import type { AnalyticsData } from '../types';
import { LoadingState } from '../components/States';
import { SEV_COLORS } from '../lib/theme';
import { SystemHealth } from '../components/SystemHealth';

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
          <div className="sub">Detection trends and model performance.</div>
        </div>
        <div className="page-head-actions" />
      </div>

      {/* Detection trends */}
      <div className="card card-pad">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <div className="chart-title">Detection Trend (per minute)</div>
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
            Severity time-series will populate from live detections.
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
          <div className="chart-title" style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>Processing & Resource Metrics</div>
          <div className="grid-2">
            <Metric label="Processing Latency" value={`${data.metrics.processingLatencyMs.toFixed(1)} ms`} note="avg detection latency" />
            <Metric label="Throughput" value={`${data.metrics.throughputPps.toLocaleString()} pps`} note="packets/second processed" />
            <Metric label="CPU Utilization" value={`${data.metrics.cpu}%`} note="engine process" />
            <Metric label="RAM Utilization" value={`${data.metrics.ram}%`} note="buffer allocation" />
          </div>
        </div>
      </div>

      {/* Model performance */}
      <div className="section" style={{ marginTop: 20 }}>
        <div className="card card-pad">
          <div className="chart-title" style={{ marginBottom: 4 }}>Model Performance</div>
          <div style={{ fontSize: 12.5, color: 'var(--faint)', marginBottom: 16 }}>
            Calculated from engine evaluation metrics.
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
