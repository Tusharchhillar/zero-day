// ---------------------------------------------------------------------------
// Mock THREATS + distribution dataset — SIH 26145 (DEMO DATA ONLY)
// ---------------------------------------------------------------------------
import type { ThreatActivityItem, ThreatCategory, ThreatDistributionSlice } from '../types';

const SPARKS: Record<string, number[]> = {
  ddos: [44, 52, 49, 61, 58, 74, 88, 96, 121, 138],
  beacon: [30, 33, 38, 36, 42, 51, 58, 64, 71, 82],
  dga: [60, 58, 63, 55, 51, 49, 46, 44, 41, 39],
  encrypted: [20, 24, 22, 30, 34, 37, 42, 46, 52, 55],
  recon: [80, 90, 95, 88, 104, 112, 118, 126, 122, 118],
  exfil: [12, 14, 11, 18, 22, 20, 26, 31, 35, 38],
};

export const mockThreatActivity: ThreatActivityItem[] = [
  {
    category: 'Volumetric / Protocol DDoS',
    classKey: 'ddos',
    count: 138,
    severity: 'CRITICAL',
    trend: 14.2,
    confidence: 0.94,
    spark: SPARKS.ddos,
    description: 'Network-layer floods (SYN / UDP reflection / amplification) saturating a destination with high packet and flow volume.',
    indicators: ['Packet rate above baseline', 'High destination concentration', 'SYN flood pattern', 'Abnormal source fan-out'],
  },
  {
    category: 'Botnet C2 Beaconing',
    classKey: 'beacon',
    count: 82,
    severity: 'HIGH',
    trend: 8.4,
    confidence: 0.91,
    spark: SPARKS.beacon,
    description: 'Periodic connections from infected hosts to fixed command-and-control endpoints at highly regular intervals.',
    indicators: ['Periodic connection intervals', 'Low IAT coefficient of variation', 'Fixed destination'],
  },
  {
    category: 'DGA / DNS Tunnelling',
    classKey: 'dga',
    count: 39,
    severity: 'MEDIUM',
    trend: -8.1,
    confidence: 0.86,
    spark: SPARKS.dga,
    description: 'Algorithmically-generated domain look-ups or DNS-based covert channels tunnelling data through the query stream.',
    indicators: ['High entropy domains', 'Elevated NXDOMAIN rate', 'Unusual query frequency'],
  },
  {
    category: 'Malicious Encrypted Sessions',
    classKey: 'encrypted',
    count: 55,
    severity: 'HIGH',
    trend: 6.7,
    confidence: 0.84,
    spark: SPARKS.encrypted,
    description: 'Suspicious TLS/QUIC sessions inferred from metadata only — record-size uniformity and entropy-laden SNI.',
    indicators: ['Uniform TLS record sizes', 'Suspicious SNI entropy', 'ClientHello cadence'],
  },
  {
    category: 'Reconnaissance / Port Scanning',
    classKey: 'recon',
    count: 118,
    severity: 'HIGH',
    trend: -3.2,
    confidence: 0.88,
    spark: SPARKS.recon,
    description: 'Hosts sweeping networks or ports with SYN-only probes to map the attack surface ahead of a strike.',
    indicators: ['Horizontal / vertical fan-out', 'High SYN-only probe ratio'],
  },
  {
    category: 'Data Exfiltration',
    classKey: 'exfil',
    count: 38,
    severity: 'CRITICAL',
    trend: 21.0,
    confidence: 0.89,
    spark: SPARKS.exfil,
    description: 'Sustained, asymmetric outbound transfers from internal hosts suggesting theft of sensitive data.',
    indicators: ['Abnormal outbound volume', 'Low in/out ratio', 'Sustained high rate'],
  },
];

export const mockThreatDistribution: ThreatDistributionSlice[] = [
  { category: 'Volumetric / Protocol DDoS', count: 138, severity: 'CRITICAL', trend: 14.2, confidence: 0.94 },
  { category: 'Reconnaissance / Port Scanning', count: 118, severity: 'HIGH', trend: -3.2, confidence: 0.88 },
  { category: 'Botnet C2 Beaconing', count: 82, severity: 'HIGH', trend: 8.4, confidence: 0.91 },
  { category: 'Malicious Encrypted Sessions', count: 55, severity: 'HIGH', trend: 6.7, confidence: 0.84 },
  { category: 'DGA / DNS Tunnelling', count: 39, severity: 'MEDIUM', trend: -8.1, confidence: 0.86 },
  { category: 'Data Exfiltration', count: 38, severity: 'CRITICAL', trend: 21.0, confidence: 0.89 },
];

export const totalDetections = mockThreatDistribution.reduce((s, x) => s + x.count, 0);

export const threatCategoryOrder: ThreatCategory[] = [
  'Volumetric / Protocol DDoS',
  'Botnet C2 Beaconing',
  'DGA / DNS Tunnelling',
  'Malicious Encrypted Sessions',
  'Reconnaissance / Port Scanning',
  'Data Exfiltration',
];
