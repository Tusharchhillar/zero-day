// ---------------------------------------------------------------------------
// Mock ANALYTICS dataset — SIH 26145 (DEMO DATA ONLY)
// ---------------------------------------------------------------------------
import type { AnalyticsData, HealthComponent } from '../types';

function series(n: number, base: number, jitter: number, spikeAt: number[] = []) {
  let v = base;
  const out: { t: string; value: number }[] = [];
  const now = new Date();
  for (let i = 0; i < n; i++) {
    v = Math.max(base * 0.3, v + (Math.random() - 0.5) * jitter);
    if (spikeAt.includes(i)) v += jitter * 2.4;
    const d = new Date(now.getTime() - (n - i) * 60000);
    out.push({ t: d.toTimeString().slice(0, 5), value: Math.round(v) });
  }
  return out;
}

const det = series(48, 34, 30, [14, 27, 40]);

export const mockAnalytics: AnalyticsData = {
  detectionTrend: det.map((d) => ({ t: d.t, detections: d.value })),
  severityTrend: [],
  confidenceDistribution: [
    { bucket: '0.70 – 0.75', count: 12 },
    { bucket: '0.75 – 0.80', count: 21 },
    { bucket: '0.80 – 0.85', count: 34 },
    { bucket: '0.85 – 0.90', count: 44 },
    { bucket: '0.90 – 0.95', count: 38 },
    { bucket: '0.95 – 1.00', count: 27 },
  ],
  metrics: {
    processingLatencyMs: 0,
    throughputPps: 0,
    cpu: 0,
    ram: 0,
  },
  modelPerformance: {
    accuracy: null,
    precision: null,
    recall: null,
    f1: null,
    provider: 'Awaiting Backend Data',
  },
};

export const mockHealthComponents: HealthComponent[] = [
  { name: 'Traffic Monitor', status: 'Healthy', detail: 'Ingesting flows', uptime: '99.98%' },
  { name: 'Detection Engine', status: 'Healthy', detail: '8 detectors online', uptime: '99.96%' },
  { name: 'Alert Pipeline', status: 'Warning', detail: 'High ingestion rate', uptime: '99.91%' },
  { name: 'Database', status: 'Healthy', detail: 'SQLite online', uptime: '100%' },
  { name: 'Dashboard', status: 'Healthy', detail: 'Rendering live', uptime: '99.99%' },
];
