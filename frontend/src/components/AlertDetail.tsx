import { Eye } from 'lucide-react';
import { SEVERITY_COLORS, SEVERITY_BG, THREAT_ICONS, styles } from '../types';
import type { Alert } from '../types';

interface Props {
  alert: Alert | null;
  onClose: () => void;
}

// ─── Alert Detail — clickable expansion showing evidence items ───────
export default function AlertDetail({ alert, onClose }: Props) {
  if (!alert) return null;

  return (
    <div style={styles.detailPanel}>
      <div style={styles.detailHeader}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Eye size={16} color="#00ff88" />
          <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#e0e0e0' }}>ALERT DETAIL</span>
        </div>
        <button onClick={onClose} style={{ ...styles.button, padding: '4px 8px' }}>✕</button>
      </div>
      <div style={{ padding: '12px 16px' }}>
        <div style={styles.detailRow}>
          <span style={styles.detailLabel}>Severity</span>
          <span style={{
            ...styles.severityBadge,
            color: SEVERITY_COLORS[alert.severity],
            background: SEVERITY_BG[alert.severity],
            border: `1px solid ${SEVERITY_COLORS[alert.severity]}`,
          }}>{alert.severity}</span>
        </div>
        <div style={styles.detailRow}>
          <span style={styles.detailLabel}>Threat Class</span>
          <span style={{ fontFamily: 'monospace', color: '#e0e0e0' }}>
            {THREAT_ICONS[alert.threat_class]} {alert.threat_class}
          </span>
        </div>
        <div style={styles.detailRow}>
          <span style={styles.detailLabel}>Confidence</span>
          <span style={{ fontFamily: 'monospace', color: '#ffd700' }}>
            {(alert.confidence * 100).toFixed(1)}%
          </span>
        </div>
        <div style={styles.detailRow}>
          <span style={styles.detailLabel}>Source → Dest</span>
          <span style={{ fontFamily: 'monospace', color: '#e0e0e0', fontSize: 12 }}>
            {alert.source_ip} → {alert.dest_ip}
          </span>
        </div>
        <div style={styles.detailRow}>
          <span style={styles.detailLabel}>Timestamp</span>
          <span style={{ fontFamily: 'monospace', color: '#9ca3af', fontSize: 12 }}>
            {alert.timestamp}
          </span>
        </div>

        {alert.evidence && alert.evidence.length > 0 && (
          <div style={{ marginTop: 16 }}>
            <div style={{ fontSize: 11, color: '#4a5568', fontFamily: 'monospace', letterSpacing: 1, marginBottom: 8 }}>
              EVIDENCE ITEMS ({alert.evidence.length})
            </div>
            {alert.evidence.map((ev, i) => (
              <div key={i} style={styles.evidenceCard}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                  <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#00ff88', fontWeight: 600 }}>{ev.feature}</span>
                  <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#ffd700' }}>{String(ev.value)}</span>
                </div>
                <div style={{ fontSize: 11, color: '#9ca3af' }}>{ev.reason}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
