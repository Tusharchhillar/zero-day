// ---------------------------------------------------------------------------
// Mock ACTIVITY FEED dataset — SIH 26145 (DEMO DATA ONLY)
// A professional SOC event feed: threat detections + system events + status
// changes, with a timeline for display.
// ---------------------------------------------------------------------------
import type { Severity, AlertStatus } from '../types';

export type ActivityKind = 'detection' | 'system' | 'status';
export type ActivitySeverity = Severity | 'SYSTEM';

export interface ActivityEvent {
  id: string;
  kind: ActivityKind;
  severity: ActivitySeverity; // SYSTEM for system events
  title: string;
  description: string;
  timestamp: string; // ISO
  /** Detection-only fields. */
  sourceIp?: string;
  destIp?: string;
  protocol?: string;
  confidence?: number;
  threatClass?: string;
  /** Status-change fields. */
  alertId?: string;
  fromStatus?: AlertStatus;
  toStatus?: AlertStatus;
  /** System fields. */
  system?: string;
  duration?: string;
}

const NOW = Date.now();
const m = (minsAgo: number) => new Date(NOW - minsAgo * 60000).toISOString();

export const mockActivityFeed: ActivityEvent[] = [
  {
    id: 'ev-01', kind: 'detection', severity: 'CRITICAL',
    title: 'Volumetric DDoS spike', threatClass: 'VOLUMETRIC_DDOS',
    description: 'High-rate SYN flood converging on an internal server.',
    timestamp: m(2), sourceIp: '10.24.19.7', destIp: '10.0.3.11', protocol: 'TCP', confidence: 0.96,
  },
  {
    id: 'ev-02', kind: 'status', severity: 'MEDIUM',
    title: 'Alert status updated', alertId: 'AL-2601',
    description: 'AL-2601 moved from Investigating to Acknowledged.',
    timestamp: m(5), fromStatus: 'Investigating', toStatus: 'Acknowledged',
  },
  {
    id: 'ev-03', kind: 'detection', severity: 'HIGH',
    title: 'Malicious encrypted session', threatClass: 'MALICIOUS_ENCRYPTED_SESSION',
    description: 'Uniform TLS record sizes flagged on outbound session.',
    timestamp: m(8), sourceIp: '192.168.14.22', destIp: '172.16.0.31', protocol: 'TLS', confidence: 0.87,
  },
  {
    id: 'ev-04', kind: 'system', severity: 'SYSTEM',
    title: 'Alert pipeline warning',
    description: 'Elevated alert volume; ingestion lag 210 ms.',
    timestamp: m(11), system: 'Alert Pipeline', duration: '210 ms',
  },
  {
    id: 'ev-05', kind: 'detection', severity: 'HIGH',
    title: 'Reconnaissance sweep', threatClass: 'RECONNAISSANCE_PORT_SCAN',
    description: 'Horizontal SYN scan across 300+ hosts.',
    timestamp: m(14), sourceIp: '10.44.3.9', destIp: '10.20.1.0/24', protocol: 'TCP', confidence: 0.91,
  },
  {
    id: 'ev-06', kind: 'status', severity: 'LOW',
    title: 'Alert resolved', alertId: 'AL-2590',
    description: 'AL-2590 closed as Resolved by analyst review.',
    timestamp: m(19), fromStatus: 'Acknowledged', toStatus: 'Resolved',
  },
  {
    id: 'ev-07', kind: 'detection', severity: 'CRITICAL',
    title: 'Data exfiltration burst', threatClass: 'DATA_EXFILTRATION',
    description: 'Sustained high-volume outbound transfer, low return traffic.',
    timestamp: m(23), sourceIp: '172.16.8.40', destIp: '10.0.4.77', protocol: 'UDP', confidence: 0.89,
  },
  {
    id: 'ev-08', kind: 'system', severity: 'SYSTEM',
    title: 'Model reloaded', system: 'Detection Engine',
    description: 'Random Forest classifier (RF) reloaded from checkpoint.',
    timestamp: m(27),
  },
  {
    id: 'ev-09', kind: 'detection', severity: 'MEDIUM',
    title: 'DGA domain look-up burst', threatClass: 'DGA_DOMAINS',
    description: 'Elevated NXDOMAIN rate with high-entropy names.',
    timestamp: m(32), sourceIp: '10.12.4.9', destIp: '10.8.177.3', protocol: 'DNS', confidence: 0.84,
  },
  {
    id: 'ev-10', kind: 'status', severity: 'HIGH',
    title: 'Alert escalated to Investigating', alertId: 'AL-2604',
    description: 'AL-2604 escalated by analyst after new evidence.',
    timestamp: m(36), fromStatus: 'New', toStatus: 'Investigating',
  },
  {
    id: 'ev-11', kind: 'system', severity: 'SYSTEM',
    title: 'Traffic monitor reconnected', system: 'Traffic Monitor',
    description: 'Capture source re-established after brief gap.',
    timestamp: m(41),
  },
  {
    id: 'ev-12', kind: 'detection', severity: 'HIGH',
    title: 'C2 beaconing', threatClass: 'BOTNET_C2_BEACONING',
    description: 'Fixed-endpoint beacon at regular interval (IAT CV 0.08).',
    timestamp: m(48), sourceIp: '192.168.1.101', destIp: '10.33.2.18', protocol: 'TCP', confidence: 0.92,
  },
  {
    id: 'ev-13', kind: 'system', severity: 'SYSTEM',
    title: 'Snapshot archived', system: 'Database',
    description: 'Daily alert snapshot committed to archive (demo).',
    timestamp: m(54),
  },
  {
    id: 'ev-14', kind: 'detection', severity: 'LOW',
    title: 'Low-risk scan pattern', threatClass: 'RECONNAISSANCE_PORT_SCAN',
    description: 'Short port sweep flagged below action threshold.',
    timestamp: m(61), sourceIp: '10.7.21.5', destIp: '10.1.0.44', protocol: 'TCP', confidence: 0.71,
  },
];