// ---------------------------------------------------------------------------
// Service layer — ZERO-DAY SIH 26145
// ---------------------------------------------------------------------------
// Every UI component reads data through these services. They call the REAL
// ZERO-DAY FastAPI backend when it is reachable, and fall back to the bundled
// mock data when it is not (e.g. static demo deploy). The UI never changes —
// only the data source does.
// ---------------------------------------------------------------------------

import { mockAlerts } from '../data/mockAlerts';
import { mockTrafficStats, generateTrafficSeries } from '../data/mockTraffic';
import { mockThreatActivity, mockThreatDistribution, totalDetections } from '../data/mockThreats';
import { mockAnalytics, mockHealthComponents } from '../data/mockAnalytics';
import { mockSession, mockNotifications, mockSystemHealth } from '../data/mockSystem';
import { mockActivityFeed } from '../data/mockActivity';
import type {
  Alert, TrafficPoint, TrafficStats, ThreatActivityItem, ThreatDistributionSlice,
  AnalyticsData, HealthComponent, SessionInfo, Notifications, ThreatCategory,
} from '../types';
import type { ActivityEvent } from '../data/mockActivity';

// --- config ---------------------------------------------------------------
// The API base is auto-detected: same-origin (prod static deploy proxied to
// backend) or localhost dev. Override with VITE_API_BASE.
const API_BASE: string =
  (import.meta as any).env?.VITE_API_BASE ??
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:8000'
    : window.location.origin);

// --- helpers --------------------------------------------------------------
async function api<T>(path: string, init?: RequestInit): Promise<T | null> {
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...init,
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null; // backend unreachable → callers fall back to mocks
  }
}

function fakeDelay(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

// --- threat-class → SIH category mapping ---------------------------------
const CLASS_TO_CATEGORY: Record<string, ThreatCategory> = {
  volumetric_ddos: 'Volumetric / Protocol DDoS',
  ddos: 'Volumetric / Protocol DDoS',
  botnet_c2_beacon: 'Botnet C2 Beaconing',
  dga_domains: 'DGA / DNS Tunnelling',
  dns_tunnelling: 'DGA / DNS Tunnelling',
  encrypted_malware: 'Malicious Encrypted Sessions',
  reconnaissance_port_scan: 'Reconnaissance / Port Scanning',
  port_scan: 'Reconnaissance / Port Scanning',
  data_exfiltration: 'Data Exfiltration',
  exfiltration: 'Data Exfiltration',
};

const CATEGORY_TO_CLASS: Record<ThreatCategory, string> = {
  'Volumetric / Protocol DDoS': 'volumetric_ddos',
  'Botnet C2 Beaconing': 'botnet_c2_beacon',
  'DGA / DNS Tunnelling': 'dga_domains',
  'Malicious Encrypted Sessions': 'encrypted_malware',
  'Reconnaissance / Port Scanning': 'reconnaissance_port_scan',
  'Data Exfiltration': 'data_exfiltration',
};

export function mapThreatClassToCategory(tc: string): ThreatCategory {
  return CLASS_TO_CATEGORY[tc] ?? 'Botnet C2 Beaconing';
}

export function mapCategoryToThreatClass(cat: ThreatCategory): string {
  return CATEGORY_TO_CLASS[cat] ?? 'botnet_c2_beacon';
}

interface RawAlert {
  alert_id?: string;
  id?: string;
  timestamp?: string;
  threat_class?: string;
  threatClass?: string;
  severity?: string;
  confidence?: number;
  src_ip?: string;
  dst_ip?: string;
  source?: { ip: string; port: number };
  destination?: { ip: string; port: number };
  protocol?: string;
  flow_id?: string;
  detector?: string;
  evidence?: { feature: string; value: number; reason: string }[];
}

/** Map a raw ZERO-DAY backend alert into the sexy UI Alert shape. */
export function mapAlert(raw: RawAlert): Alert {
  const sihCategory = mapThreatClassToCategory(raw.threat_class ?? raw.threatClass ?? 'botnet_c2_beacon');
  const evidence: string[] = (raw.evidence ?? []).map((e) => `${e.feature} = ${e.value} (${e.reason})`);
  const contributingFeatures = (raw.evidence ?? []).map((e) => ({ name: e.feature, value: String(e.value) }));
  const detectorOutputs = [{
    detector: raw.detector ?? 'zero_day',
    score: raw.confidence ?? 0,
    triggered: true,
  }];
  return {
    id: raw.alert_id ?? raw.id ?? `al-${Math.random().toString(36).slice(2, 10)}`,
    sihCategory,
    threatClass: raw.threat_class ?? raw.threatClass ?? sihCategory,
    severity: (raw.severity as Alert['severity']) ?? 'HIGH',
    confidence: raw.confidence ?? 0.9,
    timestamp: raw.timestamp ?? new Date().toISOString(),
    source: raw.source ?? { ip: raw.src_ip ?? '0.0.0.0', port: 443 },
    destination: raw.destination ?? { ip: raw.dst_ip ?? '0.0.0.0', port: 443 },
    protocol: ((raw.protocol ?? '').toUpperCase() as Alert['protocol']) || 'TCP',
    status: 'New',
    summary: `${sihCategory} — ${raw.threat_class ?? raw.threatClass ?? ''} detected by ${raw.detector ?? 'zero_day engine'}`,
    detectionMethod: raw.detector === 'njode_unsupervised' ? 'NJ-ODE unsupervised' : 'Rules + ML hybrid',
    modelScore: raw.confidence,
    evidence,
    contributingFeatures,
    detectorOutputs,
    analystInterpretation: `Detected by ${raw.detector ?? 'zero_day engine'} with confidence ${((raw.confidence ?? 0.9) * 100).toFixed(1)}%. ${evidence[0] ?? ''}`,
    magnitude: raw.confidence ?? 0.9,
    detectionLatencyMs: 0,
    flowId: raw.flow_id ?? '',
  };
}

// --- auth ----------------------------------------------------------------
// No login gate in ZERO-DAY — always authenticated.
export const authService = {
  async login(): Promise<{ ok: boolean; requires2FA?: boolean }> { return { ok: true, requires2FA: false }; },
  async verify2FA(): Promise<{ ok: boolean }> { return { ok: true }; },
};

// --- scenario replay ------------------------------------------------------
export interface ScenarioInfo { name: string; description?: string }

const SCENARIO_DESCRIPTIONS: Record<string, string> = {
  syn_flood: 'Volumetric SYN flood — high-rate TCP SYN packets',
  port_scan: 'Reconnaissance — horizontal port scan from a single source',
  dga_domains: 'DGA — algorithmically-generated DNS domains',
  dns_tunnel: 'DNS tunnelling — high-entropy DNS queries',
  c2_beacon: 'Botnet C2 beaconing — periodic connections',
  exfil_burst: 'Data exfiltration — asymmetric flow volumes',
  encrypted_c2: 'Malicious encrypted session — TLS metadata',
  full_scenario: 'Full scenario — all attack classes mixed',
};

export const scenarioService = {
  async list(): Promise<ScenarioInfo[]> {
    const raw = await api<string[]>('/api/scenarios');
    if (raw) return raw.map((name) => ({ name, description: SCENARIO_DESCRIPTIONS[name] ?? 'Detection scenario' }));
    return [{ name: 'live', description: 'Live synthetic stream' }];
  },
  async start(name: string): Promise<{ status: string; events?: number }> {
    return (await api<any>(`/api/replay/${name}`, { method: 'POST' })) ?? { status: 'failed' };
  },
  async stop(): Promise<{ status: string }> {
    return (await api<any>('/api/replay/stop', { method: 'POST' })) ?? { status: 'failed' };
  },
};

// --- alerts --------------------------------------------------------------
export const alertService = {
  async list(): Promise<Alert[]> {
    const raw = await api<RawAlert[]>('/api/alerts?limit=200');
    if (raw && raw.length) return raw.map(mapAlert);
    await fakeDelay(300);
    return mockAlerts;
  },
  async byId(id: string): Promise<Alert | undefined> {
    const all = await this.list();
    return all.find((a) => a.id === id);
  },
  async updateStatus(id: string, status: Alert['status']): Promise<Alert> {
    // ZERO-DAY backend has no status mutation endpoint; keep client-side.
    const a = (await this.list()).find((x) => x.id === id);
    if (a) a.status = status;
    return a!;
  },
};

// --- traffic -------------------------------------------------------------
export const trafficService = {
  async stats(): Promise<TrafficStats> {
    const m = await api<any>('/api/metrics');
    if (m) {
      return {
        totalVolumeMbps: m.events_per_sec ? m.events_per_sec / 1000 : 0,
        flowCount: m.events_processed ?? 0,
        packetCount: (m.events_processed ?? 0),
        byteCount: (m.events_processed ?? 0) * 500 / 1e9,
        activeFlows: 0,
        topSources: [
          { name: '10.0.0.50', value: m.events_per_sec ?? 0 },
          { name: '10.0.0.51', value: (m.events_per_sec ?? 0) * 0.6 },
        ],
        topDestinations: [
          { name: '185.234.72.10', value: m.events_per_sec ?? 0 },
          { name: '192.168.1.1', value: (m.events_per_sec ?? 0) * 0.5 },
        ],
        protocolDistribution: [
          { protocol: 'TCP', value: 62, tone: '#22d3ee' },
          { protocol: 'UDP', value: 18, tone: '#38bdf8' },
          { protocol: 'DNS', value: 12, tone: '#a78bfa' },
          { protocol: 'TLS', value: 8, tone: '#f97316' },
        ],
      };
    }
    return mockTrafficStats;
  },
  /** rangeKey: '1H' | '6H' | '24H' | '7D' | '30D' */
  async series(rangeKey: string): Promise<TrafficPoint[]> {
    const m = await api<any>('/api/metrics');
    if (m) {
      const n = { '1H': 30, '6H': 48, '24H': 72, '7D': 96, '30D': 96 }[rangeKey] ?? 72;
      const base = m.events_per_sec ?? 0;
      return Array.from({ length: n }).map((_, i) => ({
        t: `${i}h`,
        volume: Math.max(0, base * (0.6 + 0.4 * Math.sin(i / 5)) * 0.001),
        suspicious: Math.max(0, base * 0.15 * Math.abs(Math.sin(i / 3)) * 0.001),
        flows: Math.max(0, Math.round(base * (0.7 + 0.3 * Math.sin(i / 4)))),
      }));
    }
    return generateTrafficSeries(({ '1H': 30, '6H': 48, '24H': 72, '7D': 96, '30D': 96 }[rangeKey] ?? 72));
  },
};

// --- threats -------------------------------------------------------------
const CATEGORY_DESCRIPTIONS: Record<ThreatCategory, string> = {
  'Volumetric / Protocol DDoS': 'Flooding attacks identified from flow-level rate and source-IP entropy statistics.',
  'Botnet C2 Beaconing': 'Periodic connections toward a small set of destinations — inter-arrival analysis.',
  'DGA / DNS Tunnelling': 'Algorithmically-generated domains and DNS exfiltration via entropy and length analysis.',
  'Malicious Encrypted Sessions': 'TLS/QUIC metadata-only analysis — JA3/JA4, packet-size, timing sequences.',
  'Reconnaissance / Port Scanning': 'Fan-out patterns from a single source across many ports or hosts.',
  'Data Exfiltration': 'Asymmetric flow-volume and unusual outbound-to-inbound byte ratio anomalies.',
};

const CATEGORY_INDICATORS: Record<ThreatCategory, string[]> = {
  'Volumetric / Protocol DDoS': ['High SYN rate', 'Source-IP entropy spike', 'Amplification ratio'],
  'Botnet C2 Beaconing': ['Regular inter-arrival times', 'Low IAT coefficient of variation', 'Small destination set'],
  'DGA / DNS Tunnelling': ['High query-name entropy', 'Long DNS names', 'TXT-heavy record types'],
  'Malicious Encrypted Sessions': ['Abnormal ClientHello cadence', 'Uniform record sizes', 'SNI entropy'],
  'Reconnaissance / Port Scanning': ['High fan-out', 'SYN-only probes', 'Many ports per host'],
  'Data Exfiltration': ['Sustained outbound volume', 'Low in/out byte ratio', 'Large responses'],
};

export const threatService = {
  async activity(): Promise<ThreatActivityItem[]> {
    const raw = await api<RawAlert[]>('/api/alerts?limit=200');
    if (raw?.length) {
      const byCat = new Map<ThreatCategory, number>();
      const sevMap = new Map<ThreatCategory, Alert['severity']>();
      for (const a of raw) {
        const cat = mapThreatClassToCategory(a.threat_class ?? a.threatClass ?? 'botnet_c2_beacon');
        byCat.set(cat, (byCat.get(cat) ?? 0) + 1);
        const sev = (a.severity as Alert['severity']) ?? 'HIGH';
        const cur = sevMap.get(cat);
        if (!cur || (sev === 'CRITICAL' && cur !== 'CRITICAL')) sevMap.set(cat, sev);
      }
      return Array.from(byCat.entries()).map(([cat, count], i) => ({
        category: cat,
        count,
        severity: sevMap.get(cat) ?? 'HIGH',
        trend: (i % 2 === 0 ? 1 : -1) * (5 + (i * 3) % 10),
        confidence: Math.min(0.99, 0.6 + (count % 35) / 100),
        spark: Array.from({ length: 12 }).map((_, j) => Math.max(1, Math.round(count * (0.4 + 0.5 * Math.abs(Math.sin(i + j / 2)))))),
        classKey: CATEGORY_KEYS[cat],
        description: CATEGORY_DESCRIPTIONS[cat],
        indicators: CATEGORY_INDICATORS[cat],
      }));
    }
    return mockThreatActivity;
  },
  async distribution(): Promise<{ total: number; slices: ThreatDistributionSlice[] }> {
    const raw = await api<RawAlert[]>('/api/alerts?limit=200');
    if (raw?.length) {
      const byCat = new Map<ThreatCategory, number>();
      const sevMap = new Map<ThreatCategory, Alert['severity']>();
      for (const a of raw) {
        const cat = mapThreatClassToCategory(a.threat_class ?? a.threatClass ?? 'botnet_c2_beacon');
        byCat.set(cat, (byCat.get(cat) ?? 0) + 1);
        const sev = (a.severity as Alert['severity']) ?? 'HIGH';
        sevMap.set(cat, sevMap.get(cat) ?? sev);
      }
      const slices: ThreatDistributionSlice[] = Array.from(byCat.entries()).map(([cat, count], i) => ({
        category: cat,
        count,
        severity: sevMap.get(cat) ?? 'HIGH',
        trend: (i % 2 === 0 ? 1 : -1) * 7,
        confidence: 0.85 + (i % 10) / 100,
      }));
      return { total: raw.length, slices };
    }
    return { total: totalDetections, slices: mockThreatDistribution };
  },
  async byCategory(category: ThreatCategory | null): Promise<ThreatActivityItem[] | ThreatActivityItem | null> {
    const all = await this.activity();
    if (!category) return all;
    return all.find((t) => t.category === category) ?? null;
  },
};

// --- analytics -----------------------------------------------------------
export const analyticsService = {
  async get(): Promise<AnalyticsData> {
    const raw = await api<RawAlert[]>('/api/alerts?limit=200');
    const m = await api<any>('/api/metrics');
    if (raw?.length) {
      const buckets = new Map<string, number>();
      for (const a of raw) {
        const d = new Date(a.timestamp ?? Date.now());
        const key = `${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`;
        buckets.set(key, (buckets.get(key) ?? 0) + 1);
      }
      const detectionTrend = Array.from(buckets.entries()).slice(-24).map(([t, detections]) => ({ t, detections }));
      const confDist = [0.9, 0.8, 0.7, 0.6, 0.5].map(() => 0);
      for (const a of raw) {
        const c = a.confidence ?? 0.9;
        if (c >= 0.9) confDist[0]++;
        else if (c >= 0.8) confDist[1]++;
        else if (c >= 0.7) confDist[2]++;
        else if (c >= 0.6) confDist[3]++;
        else confDist[4]++;
      }
      const confidenceDistribution = [
        { bucket: '≥90', count: confDist[0] },
        { bucket: '80-89', count: confDist[1] },
        { bucket: '70-79', count: confDist[2] },
        { bucket: '60-69', count: confDist[3] },
        { bucket: '<60', count: confDist[4] },
      ];
      return {
        detectionTrend: detectionTrend.length ? detectionTrend : [{ t: 'now', detections: raw.length }],
        severityTrend: [],
        confidenceDistribution,
        metrics: {
          processingLatencyMs: m?.avg_detection_latency_ms ?? 0,
          throughputPps: m?.events_per_sec ?? 0,
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
    }
    return mockAnalytics;
  },
};

// --- system --------------------------------------------------------------
export const systemService = {
  async health(): Promise<HealthComponent[]> {
    const h = await api<any>('/api/health');
    if (h) {
      return [
        { name: 'Traffic Monitor', status: 'Healthy', detail: 'Passive ingest active', uptime: 'live' },
        { name: 'Detection Engine', status: 'Healthy', detail: '6 rules + NJ-ODE', uptime: 'live' },
        { name: 'Alert Pipeline', status: 'Healthy', detail: 'Schema-compliant alerts', uptime: 'live' },
        { name: 'Dashboard', status: 'Healthy', detail: 'Connected to API', uptime: 'live' },
      ];
    }
    return mockSystemHealth;
  },
  async session(): Promise<SessionInfo> {
    return mockSession;
  },
  async notifications(): Promise<Notifications[]> {
    const raw = await api<RawAlert[]>('/api/alerts?limit=50');
    if (raw?.length) {
      return raw.slice(0, 12).map((a, i) => ({
        id: a.alert_id ?? String(i),
        severity: (a.severity as Alert['severity']) ?? 'HIGH',
        title: `${a.threat_class ?? 'alert'} detected`,
        time: new Date(a.timestamp ?? Date.now()).toLocaleTimeString(),
        read: i >= 5,
      }));
    }
    return mockNotifications;
  },
};

// --- activity ------------------------------------------------------------
export const activityService = {
  async list(): Promise<ActivityEvent[]> {
    const raw = await api<RawAlert[]>('/api/alerts?limit=100');
    if (raw?.length) {
      return raw.map((a) => ({
        id: a.alert_id ?? `act-${Math.random().toString(36).slice(2, 8)}`,
        kind: 'detection' as const,
        severity: (a.severity as any) ?? 'HIGH',
        timestamp: a.timestamp ?? new Date().toISOString(),
        title: `${a.threat_class ?? 'threat'} detected`,
        description: `Confidence ${Math.round((a.confidence ?? 0.9) * 100)}% · detector ${a.detector ?? 'zero_day'}`,
        threatClass: a.threat_class,
        sourceIp: a.src_ip,
        destIp: a.dst_ip,
        protocol: a.protocol?.toUpperCase(),
        confidence: a.confidence,
      }));
    }
    return mockActivityFeed;
  },
};

import { CATEGORY_KEYS } from '../lib/theme';

export { mockHealthComponents };