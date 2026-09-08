// ─── Shared types, config, and styles for ZERO-DAY SOC Dashboard ───

export interface Alert {
  id?: string;
  alert_id?: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threat_class: string;
  confidence: number;
  src_ip?: string;
  dst_ip?: string;
  source_ip?: string;
  dest_ip?: string;
  flow_id?: string;
  detector?: string;
  evidence?: EvidenceItem[];
  features?: Record<string, unknown>;
}

export interface EvidenceItem {
  feature: string;
  value: string | number;
  reason: string;
}

export interface Metrics {
  events_processed: number;
  alerts_emitted: number;
  events_per_sec: number;
  severity_distribution: Record<string, number>;
  elapsed_s: number;
  njode_enabled?: boolean;
}

export interface Scenario {
  name: string;
  description?: string;
}

export type View = 'dashboard' | 'alerts' | 'attacks' | 'scenarios';

export const API_BASE = 'http://localhost:8000';
export const WS_URL = 'ws://localhost:8000/ws/alerts';

export const SEVERITY_COLORS: Record<string, string> = {
  LOW: '#00ff88',
  MEDIUM: '#ffd700',
  HIGH: '#ff8c00',
  CRITICAL: '#ff3366',
};

export const SEVERITY_BG: Record<string, string> = {
  LOW: 'rgba(0,255,136,0.1)',
  MEDIUM: 'rgba(255,215,0,0.1)',
  HIGH: 'rgba(255,140,0,0.1)',
  CRITICAL: 'rgba(255,51,102,0.15)',
};

export const THREAT_ICONS: Record<string, string> = {
  port_scan: '🔍',
  reconnaissance_port_scan: '🔍',
  brute_force: '🔨',
  volumetric_ddos: '🌊',
  ddos: '🌊',
  data_exfiltration: '📤',
  exfiltration: '📤',
  lateral_movement: '🔄',
  malware: '🦠',
  encrypted_malware: '🦠',
  phishing: '🎣',
  botnet_c2_beacon: '📡',
  c2_communication: '📡',
  dga_domains: '🔢',
  dns_tunnelling: '🧵',
  privilege_escalation: '⬆️',
  unknown: '❓',
  benign: '✅',
};

import type { CSSProperties } from 'react';

// Shared inline style objects (dark cyber SOC theme)
export const styles: Record<string, CSSProperties> = {
  panel: {
    background: '#0d1117',
    border: '1px solid #1a2332',
    borderRadius: 8,
    overflow: 'hidden',
  },
  panelHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '12px 16px',
    borderBottom: '1px solid #1a2332',
  },
  panelTitle: {
    fontSize: 12,
    fontWeight: 700,
    letterSpacing: 1.5,
    color: '#e0e0e0',
    fontFamily: 'monospace',
  },
  badge: {
    display: 'flex',
    alignItems: 'center',
    gap: 5,
    padding: '2px 8px',
    borderRadius: 4,
    fontSize: 10,
    fontFamily: 'monospace',
    color: '#e0e0e0',
  },
  feedContainer: {
    height: '100%',
    overflowY: 'auto',
    padding: '8px 0',
  },
  alertRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
    padding: '8px 16px',
    borderLeft: '3px solid',
    cursor: 'pointer',
    transition: 'background 0.2s',
  },
  severityBadge: {
    padding: '2px 8px',
    borderRadius: 4,
    fontSize: 11,
    fontWeight: 700,
    fontFamily: 'monospace',
    letterSpacing: 1,
  },
  threatTag: {
    fontFamily: 'monospace',
    fontSize: 12,
    color: '#cbd5e1',
  },
  confidenceTag: {
    fontFamily: 'monospace',
    fontSize: 11,
    color: '#ffd700',
    background: 'rgba(255,215,0,0.1)',
    padding: '2px 6px',
    borderRadius: 4,
  },
  ipText: {
    fontFamily: 'monospace',
    fontSize: 11,
    color: '#9ca3af',
  },
  evidencePanel: {
    background: '#0a0e1a',
    borderTop: '1px solid #1a2332',
    padding: '10px 16px',
  },
  evidenceHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    color: '#00ff88',
    fontFamily: 'monospace',
    fontSize: 11,
    letterSpacing: 1,
    marginBottom: 8,
  },
  evidenceRow: {
    display: 'flex',
    gap: 12,
    alignItems: 'flex-start',
    padding: '6px 0',
    borderBottom: '1px solid #161f2e',
    fontSize: 12,
  },
  evidenceFeature: {
    fontFamily: 'monospace',
    color: '#00ff88',
    minWidth: 140,
    fontWeight: 600,
  },
  evidenceValue: {
    fontFamily: 'monospace',
    color: '#ffd700',
    minWidth: 90,
  },
  evidenceReason: {
    fontFamily: 'monospace',
    color: '#9ca3af',
    flex: 1,
  },
  metricGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))',
    gap: 10,
  },
  metricCard: {
    background: '#0a0e1a',
    border: '1px solid #1a2332',
    borderRadius: 8,
    padding: '12px',
    display: 'flex',
    flexDirection: 'column',
    gap: 6,
  },
  metricValue: {
    fontSize: 20,
    fontWeight: 700,
    color: '#00ff88',
    fontFamily: 'monospace',
  },
  metricLabel: {
    fontSize: 10,
    color: '#6b7280',
    fontFamily: 'monospace',
    letterSpacing: 1,
  },
  attackCard: {
    background: '#0a0e1a',
    border: '1px solid #1a2332',
    borderRadius: 8,
    padding: '12px',
  },
  attackCardHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  scenarioCard: {
    background: '#0a0e1a',
    border: '1px solid #1a2332',
    borderRadius: 8,
    padding: '12px',
  },
  button: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
    border: '1px solid rgba(0,255,136,0.3)',
    background: 'rgba(0,255,136,0.1)',
    color: '#00ff88',
    fontFamily: 'monospace',
    fontSize: 12,
    fontWeight: 600,
    borderRadius: 6,
    padding: '8px 12px',
    cursor: 'pointer',
    transition: 'all 0.2s',
  },
  detailPanel: {
    background: '#0d1117',
    border: '1px solid #1a2332',
    borderRadius: 8,
    overflow: 'hidden',
  },
  detailHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '10px 16px',
    borderBottom: '1px solid #1a2332',
  },
  detailRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '8px 0',
    borderBottom: '1px solid #161f2e',
    gap: 12,
  },
  detailLabel: {
    fontFamily: 'monospace',
    fontSize: 11,
    color: '#6b7280',
    letterSpacing: 0.5,
  },
  evidenceCard: {
    background: '#0a0e1a',
    border: '1px solid #161f2e',
    borderRadius: 6,
    padding: '8px 10px',
    marginBottom: 6,
  },
  layout: {
    display: 'flex',
    height: '100vh',
    width: '100vw',
    background: '#0a0e1a',
    overflow: 'hidden',
  },
  sidebar: {
    width: 220,
    minWidth: 220,
    background: '#0d1117',
    borderRight: '1px solid #1a2332',
    display: 'flex',
    flexDirection: 'column',
    padding: '16px 0',
    overflow: 'hidden',
  },
  logo: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    padding: '0 16px 16px',
    borderBottom: '1px solid #1a2332',
  },
  navItem: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    padding: '10px 16px',
    cursor: 'pointer',
    fontSize: 13,
    fontFamily: 'monospace',
  },
  statusBox: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    padding: '12px 16px',
    marginTop: 'auto',
    borderTop: '1px solid #1a2332',
  },
  miniMetrics: {
    padding: '12px 16px',
    display: 'flex',
    flexDirection: 'column',
    gap: 6,
  },
  miniMetricRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  main: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  topbar: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '14px 20px',
    borderBottom: '1px solid #1a2332',
    background: '#0d1117',
  },
  content: {
    flex: 1,
    padding: 16,
    overflow: 'hidden',
    display: 'flex',
    flexDirection: 'column',
  },
};
