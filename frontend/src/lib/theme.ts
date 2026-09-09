// Theme + label helpers shared across the UI. Keeps presentation logic in one place.
import type { Severity, ThreatCategory } from '../types';

export const SEV_COLORS: Record<Severity, string> = {
  CRITICAL: '#f43f5e',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#38bdf8',
};

export const SEV_LABEL: Record<Severity, string> = SEV_COLORS;

export const MODEL_ACCENT = { a: '#22d3ee', b: '#38bdf8' };

/** Friendly label used in charts for each SIH threat category. */
export const CATEGORY_SHORT: Record<ThreatCategory, string> = {
  'Volumetric / Protocol DDoS': 'DDoS',
  'Botnet C2 Beaconing': 'C2 Beaconing',
  'DGA / DNS Tunnelling': 'DGA / DNS Tunnel',
  'Malicious Encrypted Sessions': 'Malicious TLS',
  'Reconnaissance / Port Scanning': 'Recon / Scan',
  'Data Exfiltration': 'Exfiltration',
};

export const CATEGORY_KEYS: Record<ThreatCategory, string> = {
  'Volumetric / Protocol DDoS': 'ddos',
  'Botnet C2 Beaconing': 'beacon',
  'DGA / DNS Tunnelling': 'dga',
  'Malicious Encrypted Sessions': 'encrypted',
  'Reconnaissance / Port Scanning': 'recon',
  'Data Exfiltration': 'exfil',
};

/** A rank 0..5 used for chart colour ordering (threat priority). */
export const CATEGORY_ORDER: ThreatCategory[] = [
  'Volumetric / Protocol DDoS',
  'Botnet C2 Beaconing',
  'DGA / DNS Tunnelling',
  'Malicious Encrypted Sessions',
  'Reconnaissance / Port Scanning',
  'Data Exfiltration',
];

/** Distinct colour per threat category for donut/stacked charts. */
export const CATEGORY_COLORS: Record<ThreatCategory, string> = {
  'Volumetric / Protocol DDoS': '#f43f5e',
  'Botnet C2 Beaconing': '#f97316',
  'DGA / DNS Tunnelling': '#eab308',
  'Malicious Encrypted Sessions': '#38bdf8',
  'Reconnaissance / Port Scanning': '#a78bfa',
  'Data Exfiltration': '#22d3ee',
};

export function fmtTime(iso: string): string {
  const d = new Date(iso);
  return `${d.toLocaleDateString(undefined, { day: '2-digit', month: 'short' })} · ${d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}`;
}

export function fmtDelta(v: number): string {
  const sign = v >= 0 ? '+' : '';
  return `${sign}${v.toFixed(1)}%`;
}

export function relTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.max(0, Math.floor(diff / 60000));
  if (m < 1) return 'now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
