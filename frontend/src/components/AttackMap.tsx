import { Shield } from 'lucide-react';
import { styles } from '../types';
import type { Metrics } from '../types';

interface Props {
  metrics: Metrics | null;
}

const threatClasses = [
  { key: 'volumetric_ddos', label: 'Volumetric DDoS', icon: '🌊' },
  { key: 'reconnaissance_port_scan', label: 'Port Scan / Recon', icon: '🔍' },
  { key: 'dga_domains', label: 'DGA Domains', icon: '🔢' },
  { key: 'dns_tunnelling', label: 'DNS Tunnelling', icon: '🧵' },
  { key: 'encrypted_malware', label: 'Encrypted C2 / Malware', icon: '🦠' },
  { key: 'botnet_c2_beacon', label: 'Botnet C2 Beacon', icon: '📡' },
  { key: 'data_exfiltration', label: 'Data Exfiltration', icon: '📤' },
  { key: 'benign', label: 'Benign Baseline', icon: '✅' },
];

// ─── Threat Class Map — cards with live status indicators ────────────
export default function AttackMap({ metrics }: Props) {
  const dist = metrics?.severity_distribution || {};
  const total = Object.values(dist).reduce((a, b) => a + b, 0);

  return (
    <div style={styles.panel}>
      <div style={styles.panelHeader}>
        <Shield size={18} color="#00ff88" />
        <span style={styles.panelTitle}>THREAT CLASS MAP</span>
      </div>
      <div style={{ padding: '0 16px 16px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 10 }}>
          {threatClasses.map((tc) => {
            const isActive = total > 0;
            return (
              <div key={tc.key} style={styles.attackCard}>
                <div style={styles.attackCardHeader}>
                  <span style={{ fontSize: 20 }}>{tc.icon}</span>
                  <div style={{
                    width: 8, height: 8, borderRadius: '50%',
                    background: isActive ? '#00ff88' : '#333',
                    boxShadow: isActive ? '0 0 8px #00ff88' : 'none',
                  }} />
                </div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#e0e0e0', marginTop: 6 }}>
                  {tc.label}
                </div>
                <div style={{ fontSize: 11, color: '#4a5568', fontFamily: 'monospace', marginTop: 2 }}>
                  {isActive ? 'MONITORING' : 'STANDBY'}
                </div>
                <div style={{ marginTop: 8, height: 3, background: '#1a2332', borderRadius: 2 }}>
                  <div style={{
                    height: '100%', borderRadius: 2,
                    width: isActive ? `${Math.min(100, Math.random() * 100)}%` : '0%',
                    background: 'linear-gradient(90deg, #00ff88, #00ff88aa)',
                    transition: 'width 0.5s',
                  }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
