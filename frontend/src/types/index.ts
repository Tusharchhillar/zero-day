// ---------------------------------------------------------------------------
// SIH 26145 — Shared domain types (frontend)
// ---------------------------------------------------------------------------
// All types model the data the future backend/AI engine will return. Every
// service currently returns MOCK data; these interfaces are the contract a
// real API must satisfy so the UI does not need to change.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type AlertStatus = 'New' | 'Investigating' | 'Acknowledged' | 'Resolved';
export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'TLS' | 'DNS' | 'QUIC';

/** The six SIH 26145 threat categories. */
export type ThreatCategory =
  | 'Volumetric / Protocol DDoS'
  | 'Botnet C2 Beaconing'
  | 'DGA / DNS Tunnelling'
  | 'Malicious Encrypted Sessions'
  | 'Reconnaissance / Port Scanning'
  | 'Data Exfiltration';

export type SystemStatus = 'Healthy' | 'Warning' | 'Offline';

export interface Endpoint {
  ip: string;
  port: number;
}

export interface Alert {
  id: string;
  sihCategory: ThreatCategory;
  threatClass: string;
  severity: Severity;
  confidence: number; // 0..1
  timestamp: string; // ISO
  source: Endpoint;
  destination: Endpoint;
  protocol: Protocol;
  status: AlertStatus;
  summary: string; // short explanation
  detectionMethod: string; // e.g. "Rules + ML hybrid"
  modelScore?: number;
  evidence: string[];
  contributingFeatures: { name: string; value: string }[];
  detectorOutputs: { detector: string; score: number; triggered: boolean }[];
  analystInterpretation: string;
  magnitude: number; // relative overshoot
  detectionLatencyMs: number;
  flowId: string;
}

export interface StatCardData {
  key: string;
  label: string;
  value: string;
  delta?: string; // trend text e.g. "+12.4%"
  deltaDirection?: 'up' | 'down' | 'flat';
  deltaTone?: 'positive' | 'negative' | 'neutral';
  support: string; // supporting info
  icon: string; // icon key resolved by a map
  tone?: 'critical' | 'high' | 'medium' | 'low' | 'healthy' | 'neutral';
}

export interface ThreatDistributionSlice {
  category: ThreatCategory;
  count: number;
  severity: Severity;
  trend: number; // % change
  confidence: number;
}

export interface ThreatActivityItem {
  category: ThreatCategory;
  count: number;
  severity: Severity;
  trend: number; // % change over period
  confidence: number;
  spark: number[]; // mini-series for a trendline
  classKey: string; // short machine key
  description: string;
  indicators: string[]; // observable indicators
}

export interface TrafficPoint {
  t: string; // label
  volume: number; // mbps
  suspicious: number; // mbps
  flows: number; // flows per bucket
}

export interface TrafficStats {
  totalVolumeMbps: number;
  flowCount: number;
  packetCount: number;
  byteCount: number;
  activeFlows: number;
  topSources: { name: string; value: number }[];
  topDestinations: { name: string; value: number }[];
  protocolDistribution: { protocol: string; value: number; tone: string }[];
}

export interface HealthComponent {
  name: string;
  status: SystemStatus;
  detail: string;
  uptime: string;
}

export interface AnalyticsData {
  detectionTrend: { t: string; detections: number }[];
  severityTrend: { t: string; [sev: string]: number | string }[];
  confidenceDistribution: { bucket: string; count: number }[];
  metrics: { processingLatencyMs: number; throughputPps: number; cpu: number; ram: number };
  modelPerformance: {
    accuracy: number | null;
    precision: number | null;
    recall: number | null;
    f1: number | null;
    provider: 'Demo Data' | 'Awaiting Backend Data';
  };
}

export interface SessionInfo {
  authenticated: boolean;
  username: string;
  email: string;
  role: string;
  mfaEnabled: boolean;
  lastLogin: string;
  activeSessions: { device: string; location: string; lastActive: string; current?: boolean }[];
}

export interface Notifications {
  id: string;
  severity: Severity;
  title: string;
  time: string;
  read: boolean;
}
