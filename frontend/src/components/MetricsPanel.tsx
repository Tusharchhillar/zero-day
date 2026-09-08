import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { Activity, AlertTriangle, Zap, Server, Clock } from 'lucide-react';
import { styles } from '../types';
import type { Metrics } from '../types';

interface Props {
  metrics: Metrics | null;
}

const PIE_COLORS = ['#00ff88', '#ffd700', '#ff8c00', '#ff3366'];

// ─── System Metrics with Recharts severity distribution ──────────────
export default function MetricsPanel({ metrics }: Props) {
  if (!metrics) {
    return (
      <div style={styles.panel}>
        <div style={styles.panelHeader}>
          <Activity size={18} color="#00ff88" />
          <span style={styles.panelTitle}>SYSTEM METRICS</span>
        </div>
        <div style={{ textAlign: 'center', color: '#4a5568', padding: 40, fontFamily: 'monospace' }}>
          Loading metrics...
        </div>
      </div>
    );
  }

  const pieData = metrics.severity_distribution
    ? Object.entries(metrics.severity_distribution).map(([name, value]) => ({ name, value }))
    : [];

  const formatUptime = (s: number) => {
    if (!s && s !== 0) return '0m';
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = Math.floor(s % 60);
    return h > 0 ? `${h}h ${m}m` : `${m}m ${sec}s`;
  };

  return (
    <div style={styles.panel}>
      <div style={styles.panelHeader}>
        <Activity size={18} color="#00ff88" />
        <span style={styles.panelTitle}>SYSTEM METRICS</span>
      </div>
      <div style={{ padding: '0 16px 16px' }}>
        <div style={styles.metricGrid}>
          <div style={styles.metricCard}>
            <Server size={20} color="#00ff88" />
            <div style={styles.metricValue}>{metrics.events_processed.toLocaleString()}</div>
            <div style={styles.metricLabel}>EVENTS PROCESSED</div>
          </div>
          <div style={styles.metricCard}>
            <AlertTriangle size={20} color="#ff3366" />
            <div style={{ ...styles.metricValue, color: '#ff3366' }}>{metrics.alerts_emitted.toLocaleString()}</div>
            <div style={styles.metricLabel}>ALERTS EMITTED</div>
          </div>
          <div style={styles.metricCard}>
            <Zap size={20} color="#ffd700" />
            <div style={{ ...styles.metricValue, color: '#ffd700' }}>{metrics.events_per_sec.toFixed(1)}</div>
            <div style={styles.metricLabel}>EVENTS / SEC</div>
          </div>
          <div style={styles.metricCard}>
            <Clock size={20} color="#4a9eff" />
            <div style={{ ...styles.metricValue, color: '#4a9eff' }}>{formatUptime(metrics.elapsed_s)}</div>
            <div style={styles.metricLabel}>UPTIME</div>
          </div>
        </div>

        {pieData.length > 0 && (
          <div style={{ marginTop: 16 }}>
            <div style={{ fontSize: 11, color: '#4a5568', fontFamily: 'monospace', letterSpacing: 1, marginBottom: 8, textTransform: 'uppercase' }}>
              Severity Distribution
            </div>
            <div style={{ height: 200 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {pieData.map((_, index) => (
                      <Cell key={index} fill={PIE_COLORS[index % PIE_COLORS.length]} stroke="none" />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#111827', border: '1px solid #1a2332', borderRadius: 6, fontFamily: 'monospace', fontSize: 12 }}
                    itemStyle={{ color: '#e0e0e0' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div style={{ display: 'flex', gap: 16, justifyContent: 'center', flexWrap: 'wrap' }}>
              {pieData.map((entry, i) => (
                <div key={entry.name} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ width: 10, height: 10, borderRadius: 2, background: PIE_COLORS[i % PIE_COLORS.length] }} />
                  <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#9ca3af' }}>{entry.name}: {entry.value}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
