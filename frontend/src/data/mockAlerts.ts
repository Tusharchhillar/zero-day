// ---------------------------------------------------------------------------
// Mock ALERTS dataset — SIH 26145
// ---------------------------------------------------------------------------
// DEMO DATA ONLY. IPs are private/reserved ranges (10.x, 172.16.x, 192.168.x)
// per the spec — never real malicious hosts. Alert values are illustrative
// and do NOT come from a real AI model.
import type { Alert, Severity } from '../types';

// Deterministic pseudo-random generator so the demo is stable between loads.
function mulberry32(seed: number) {
  return function () {
    let t = (seed += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rnd = mulberry32(26145);

const PRIVATE_SUBNETS = ['10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '192.168.'];

function privateIp(): string {
  const pick = rnd();
  if (pick < 0.5) return `10.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 250) + 1}`;
  if (pick < 0.8) return `172.${16 + Math.floor(rnd() * 12)}.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 250) + 1}`;
  return `192.168.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 250) + 1}`;
}

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'HIGH', 'MEDIUM', 'LOW', 'CRITICAL', 'HIGH'];
const STATUSES: Alert['status'][] = ['New', 'New', 'Investigating', 'Investigating', 'Acknowledged', 'Acknowledged', 'Resolved', 'Resolved', 'New'];

const CATEGORIES: {
  category: Alert['sihCategory'];
  threatClass: string;
  method: string;
  modelScore: number;
  evidence: string[];
  features: { name: string; value: string }[];
  detectors: { detector: string; score: number; triggered: boolean }[];
  interpretation: string;
  protocol: Alert['protocol'];
}[] = [
  {
    category: 'Volumetric / Protocol DDoS',
    threatClass: 'VOLUMETRIC_DDOS',
    method: 'Rules + ML hybrid',
    modelScore: 0.982,
    evidence: ['Packet rate above baseline', 'SYN flood pattern', 'High destination concentration'],
    features: [
      { name: 'packets_per_sec', value: '48,210 (baseline 2,104)' },
      { name: 'unique_sources', value: '1,284' },
      { name: 'dst_fanout_ratio', value: '0.97' },
      { name: 'syn_ratio', value: '0.94' },
    ],
    detectors: [
      { detector: 'DDoS (SYN flood)', score: 0.99, triggered: true },
      { detector: 'RF classifier', score: 0.98, triggered: true },
    ],
    interpretation: 'A single destination is receiving a high packet rate from many sources with near-total SYN ratio — consistent with a distributed SYN flood converging on the victim.',
    protocol: 'TCP',
  },
  {
    category: 'Botnet C2 Beaconing',
    threatClass: 'BOTNET_C2_BEACONING',
    method: 'Rules + ML hybrid',
    modelScore: 0.917,
    evidence: ['Periodic connection intervals', 'Low IAT coefficient of variation', 'Regular destination'],
    features: [
      { name: 'iat_cv', value: '0.08' },
      { name: 'median_iat_s', value: '59.8' },
      { name: 'unique_destinations', value: '1' },
    ],
    detectors: [
      { detector: 'Beaconing', score: 0.95, triggered: true },
      { detector: 'RF classifier', score: 0.87, triggered: true },
    ],
    interpretation: 'The host connects to a fixed destination at highly regular intervals (CV 0.08), strongly resembling command-and-control beaconing rather than organic client traffic.',
    protocol: 'TCP',
  },
  {
    category: 'DGA / DNS Tunnelling',
    threatClass: 'DGA_DOMAINS',
    method: 'Rules + ML hybrid',
    modelScore: 0.861,
    evidence: ['High entropy domain names', 'Frequent NXDOMAIN responses', 'Unusual query rate'],
    features: [
      { name: 'dns_query_rate', value: '31.4/s' },
      { name: 'avg_domain_entropy', value: '4.8 bits/char' },
      { name: 'nxdomain_ratio', value: '0.71' },
      { name: 'unique_apex_domains', value: '18' },
    ],
    detectors: [
      { detector: 'DGA Detector', score: 0.88, triggered: true },
      { detector: 'RF classifier', score: 0.82, triggered: true },
    ],
    interpretation: 'The client is issuing DNS queries for algorithmically-generated, high-entropy names at volume, with a high NXDOMAIN rate — the classic DGA look-up pattern.',
    protocol: 'DNS',
  },
  {
    category: 'Malicious Encrypted Sessions',
    threatClass: 'MALICIOUS_ENCRYPTED_SESSION',
    method: 'Rules + ML hybrid',
    modelScore: 0.803,
    evidence: ['Uniform TLS record sizes', 'Suspicious SNI entropy', 'ClientHello cadence'],
    features: [
      { name: 'record_size_cv', value: '0.05' },
      { name: 'sni_entropy', value: '3.9 bits/char' },
      { name: 'clienthello_rate', value: '4.2/s' },
    ],
    detectors: [
      { detector: 'Encrypted Session', score: 0.82, triggered: true },
      { detector: 'RF classifier', score: 0.78, triggered: true },
    ],
    interpretation: 'TLS metadata (record sizes unusually uniform, entropy-laden SNI) suggests a covert channel inside an encrypted session. No decryption performed — analysed from metadata only.',
    protocol: 'TLS',
  },
  {
    category: 'Reconnaissance / Port Scanning',
    threatClass: 'RECONNAISSANCE_PORT_SCAN',
    method: 'Rules + ML hybrid',
    modelScore: 0.846,
    evidence: ['Horizontal scan across hosts', 'High SYN-only probe ratio', 'Unusual fan-out'],
    features: [
      { name: 'unique_dst_hosts', value: '312' },
      { name: 'syn_only_ratio', value: '0.96' },
      { name: 'probe_rate', value: '22.1/s' },
    ],
    detectors: [
      { detector: 'Port Scan', score: 0.92, triggered: true },
      { detector: 'RF classifier', score: 0.77, triggered: true },
    ],
    interpretation: 'A host is sweeping many destinations with SYN-only probes — consistent with automated reconnaissance prior to an attack.',
    protocol: 'TCP',
  },
  {
    category: 'Data Exfiltration',
    threatClass: 'DATA_EXFILTRATION',
    method: 'Rules + ML hybrid',
    modelScore: 0.878,
    evidence: ['Abnormal outbound volume', 'Unusual flow volume', 'Sustained high rate'],
    features: [
      { name: 'outbound_bytes', value: '412 MB' },
      { name: 'in_out_ratio', value: '0.03' },
      { name: 'sustained_mbps', value: '38.6' },
    ],
    detectors: [
      { detector: 'Exfiltration', score: 0.91, triggered: true },
      { detector: 'RF classifier', score: 0.84, triggered: true },
    ],
    interpretation: 'A single internal host is pushing a large, sustained volume of outbound traffic with negligible return — a strong data-exfiltration signature.',
    protocol: 'UDP',
  },
];

const SUMMARIES: Record<Alert['sihCategory'], string[]> = {
  'Volumetric / Protocol DDoS': [
    'High-volume SYN flood converging on an internal server.',
    'UDP reflection burst flooding a database endpoint.',
  ],
  'Botnet C2 Beaconing': [
    'Host beacons to a fixed external endpoint at regular intervals.',
    'Periodic heartbeat traffic suspected as C2 communication.',
  ],
  'DGA / DNS Tunnelling': [
    'High-entropy DNS queries suggest DGA activity.',
    'Elevated DNS query rate with NXDOMAIN responses.',
  ],
  'Malicious Encrypted Sessions': [
    'Uniform TLS record sizes indicate a possible covert channel.',
    'Suspicious encrypted session with high record-size uniformity.',
  ],
  'Reconnaissance / Port Scanning': [
    'Host performing horizontal SYN scan across the network.',
    'Vertical port sweep detected from an internal endpoint.',
  ],
  'Data Exfiltration': [
    'Sustained outbound transfer with negligible return traffic.',
    'Abnormal outbound volume flagged as potential exfiltration.',
  ],
};

function makeCategory(): Alert['sihCategory'] {
  const keys: Alert['sihCategory'][] = [
    'Volumetric / Protocol DDoS',
    'Botnet C2 Beaconing',
    'DGA / DNS Tunnelling',
    'Malicious Encrypted Sessions',
    'Reconnaissance / Port Scanning',
    'Data Exfiltration',
  ];
  return keys[Math.floor(rnd() * keys.length)];
}

// Deterministic base time (a stable "now" so relative timestamps look live).
const NOW = Date.now();
const minutesAgo = (m: number) => new Date(NOW - m * 60000).toISOString();

export const mockAlerts: Alert[] = Array.from({ length: 64 }).map((_, i) => {
  const cat = CATEGORIES[Math.floor(rnd() * CATEGORIES.length)];
  const severity = SEVERITIES[Math.floor(rnd() * SEVERITIES.length)];
  const summaries = SUMMARIES[cat.category];
  const srcPort = 1024 + Math.floor(rnd() * 55000);
  const dstPort = [80, 443, 53, 8080, 22, 3306, 0][Math.floor(rnd() * 7)];
  const mins = i * 3 + Math.floor(rnd() * 6);
  const conf = 0.72 + rnd() * 0.27;
  return {
    id: `AL-${String(26145 + i).padStart(4, '0')}`,
    sihCategory: cat.category,
    threatClass: cat.threatClass,
    severity,
    confidence: Math.round(conf * 1000) / 1000,
    timestamp: minutesAgo(mins),
    source: { ip: privateIp(), port: srcPort },
    destination: { ip: privateIp(), port: dstPort },
    protocol: cat.protocol,
    status: STATUSES[Math.floor(rnd() * STATUSES.length)],
    summary: summaries[Math.floor(rnd() * summaries.length)],
    detectionMethod: cat.method,
    modelScore: Math.round((cat.modelScore * (0.94 + rnd() * 0.1)) * 1000) / 1000,
    evidence: cat.evidence,
    contributingFeatures: cat.features,
    detectorOutputs: cat.detectors,
    analystInterpretation: cat.interpretation,
    magnitude: Math.round((0.55 + rnd() * 0.44) * 100) / 100,
    detectionLatencyMs: Math.round(18 + rnd() * 60),
    flowId: `F-${Math.random().toString(16).slice(2, 10)}`,
  };
});

// Keep _makeCategory referenced to satisfy lint-free unused handling (used for
// deterministic extras if needed later).
export const _categorise = makeCategory;
export const _PRIVATE_SUBNETS = PRIVATE_SUBNETS;
