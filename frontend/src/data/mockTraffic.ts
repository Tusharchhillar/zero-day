// ---------------------------------------------------------------------------
// Mock TRAFFIC dataset — SIH 26145 (DEMO DATA ONLY, not a live feed)
// ---------------------------------------------------------------------------
import type { TrafficPoint, TrafficStats } from '../types';

function seed(seed: number) {
  return function () {
    let t = (seed += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Generate a plausible traffic series for a given number of buckets. */
export function generateTrafficSeries(points: number, scale = 1): TrafficPoint[] {
  const rnd = seed(points * 7919 + 13);
  const out: TrafficPoint[] = [];
  const today = new Date();
  let base = 420 * scale;
  let suspicious = 8 * scale;
  const maxPts = Math.min(points, 96);
  for (let i = 0; i < maxPts; i++) {
    base = Math.max(120, base + (rnd() - 0.48) * 90);
    suspicious = Math.max(1, suspicious + (rnd() - 0.42) * 30);
    if (rnd() > 0.93) {
      suspicious += 120 + rnd() * 240; // spike
      base += 160;
    }
    const t = new Date(today.getTime() - (maxPts - i) * (7200 / maxPts) * 1000);
    out.push({
      t: t.toTimeString().slice(0, 5),
      volume: Math.round(base),
      suspicious: Math.round(suspicious),
      flows: Math.round(1400 + rnd() * 4200),
    });
  }
  return out;
}

export const mockTrafficStats: TrafficStats = {
  totalVolumeMbps: 8940,
  flowCount: 128406,
  packetCount: 48221900,
  byteCount: 214.8, // GB
  activeFlows: 3842,
  topSources: [
    { name: '10.12.4.9', value: 1820 },
    { name: '10.12.7.22', value: 1490 },
    { name: '172.16.8.14', value: 1220 },
    { name: '10.20.1.55', value: 980 },
    { name: '192.168.1.101', value: 760 },
  ],
  topDestinations: [
    { name: '10.0.3.11', value: 2100 },
    { name: '172.16.0.30', value: 1720 },
    { name: '10.0.4.77', value: 1410 },
    { name: '192.168.2.5', value: 1110 },
    { name: '10.0.1.9', value: 890 },
  ],
  protocolDistribution: [
    { protocol: 'TCP', value: 58, tone: 'blue' },
    { protocol: 'UDP', value: 27, tone: 'orange' },
    { protocol: 'TLS', value: 11, tone: 'green' },
    { protocol: 'DNS', value: 3, tone: 'yellow' },
    { protocol: 'ICMP', value: 1, tone: 'red' },
  ],
};
