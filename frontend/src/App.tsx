import { useEffect, useState } from 'react';
import {
  Shield, AlertTriangle, Globe, Play,
} from 'lucide-react';
import AlertFeed from './components/AlertFeed';
import MetricsPanel from './components/MetricsPanel';
import AttackMap from './components/AttackMap';
import ScenarioRunner from './components/ScenarioRunner';
import AlertDetail from './components/AlertDetail';
import { API_BASE, styles } from './types';
import type { Alert, Metrics, View } from './types';

// ─── Main SOC Dashboard Layout ───────────────────────────────────────
export default function App() {
  const [view, setView] = useState<View>('dashboard');
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [health, setHealth] = useState<boolean>(false);

  // Poll metrics every 2s
  useEffect(() => {
    const fetchMetrics = () => {
      fetch(`${API_BASE}/api/metrics`)
        .then(r => r.json())
        .then(setMetrics)
        .catch(() => {});
    };
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 2000);
    return () => clearInterval(interval);
  }, []);

  // Health check
  useEffect(() => {
    const checkHealth = () => {
      fetch(`${API_BASE}/api/health`)
        .then(r => { setHealth(r.ok); })
        .catch(() => setHealth(false));
    };
    checkHealth();
    const interval = setInterval(checkHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  const navItems: { key: View; label: string; icon: React.ReactNode }[] = [
    { key: 'dashboard', label: 'Dashboard', icon: <Shield size={18} /> },
    { key: 'alerts', label: 'Alert Feed', icon: <AlertTriangle size={18} /> },
    { key: 'attacks', label: 'Threat Map', icon: <Globe size={18} /> },
    { key: 'scenarios', label: 'Scenarios', icon: <Play size={18} /> },
  ];

  return (
    <div style={styles.layout}>
      {/* Sidebar */}
      <div style={styles.sidebar}>
        <div style={styles.logo}>
          <Shield size={28} color="#00ff88" />
          <div>
            <div style={{ fontSize: 16, fontWeight: 800, color: '#00ff88', fontFamily: 'monospace', letterSpacing: 2 }}>
              ZERO-DAY
            </div>
            <div style={{ fontSize: 9, color: '#4a5568', fontFamily: 'monospace', letterSpacing: 1 }}>
              SIH26145 · SOC
            </div>
          </div>
        </div>

        <nav style={{ marginTop: 20 }}>
          {navItems.map(item => (
            <div
              key={item.key}
              onClick={() => setView(item.key)}
              style={{
                ...styles.navItem,
                background: view === item.key ? 'rgba(0,255,136,0.1)' : 'transparent',
                borderRight: view === item.key ? '3px solid #00ff88' : '3px solid transparent',
                color: view === item.key ? '#00ff88' : '#6b7280',
              }}
            >
              {item.icon}
              <span>{item.label}</span>
            </div>
          ))}
        </nav>

        {/* Backend status indicator */}
        <div style={styles.statusBox}>
          <div style={{
            width: 8, height: 8, borderRadius: '50%',
            background: health ? '#00ff88' : '#ff3366',
            boxShadow: health ? '0 0 8px #00ff88' : '0 0 8px #ff3366',
          }} />
          <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#6b7280' }}>
            Backend: {health ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>

        {metrics && (
          <div style={styles.miniMetrics}>
            <div style={styles.miniMetricRow}>
              <span style={{ color: '#4a5568', fontSize: 10 }}>Events</span>
              <span style={{ color: '#00ff88', fontFamily: 'monospace', fontSize: 11 }}>{metrics.events_processed.toLocaleString()}</span>
            </div>
            <div style={styles.miniMetricRow}>
              <span style={{ color: '#4a5568', fontSize: 10 }}>Alerts</span>
              <span style={{ color: '#ff3366', fontFamily: 'monospace', fontSize: 11 }}>{metrics.alerts_emitted.toLocaleString()}</span>
            </div>
            <div style={styles.miniMetricRow}>
              <span style={{ color: '#4a5568', fontSize: 10 }}>EPS</span>
              <span style={{ color: '#ffd700', fontFamily: 'monospace', fontSize: 11 }}>{metrics.events_per_sec.toFixed(1)}</span>
            </div>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div style={styles.main}>
        <div style={styles.topbar}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <h1 style={{ fontSize: 14, fontWeight: 700, color: '#e0e0e0', fontFamily: 'monospace', letterSpacing: 1 }}>
              {navItems.find(n => n.key === view)?.label.toUpperCase()}
            </h1>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, fontFamily: 'monospace', fontSize: 11, color: '#6b7280' }}>
            <span>SIH 2026</span>
            <span>·</span>
            <span>ZERO-DAY THREAT DETECTION</span>
            <span>·</span>
            <span>{new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: '2-digit' })}</span>
          </div>
        </div>

        <div style={styles.content}>
          {view === 'dashboard' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, height: '100%' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16, overflow: 'auto' }}>
                <MetricsPanel metrics={metrics} />
                <ScenarioRunner />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16, overflow: 'auto' }}>
                <AlertFeed onAlertClick={setSelectedAlert} />
              </div>
            </div>
          )}

          {view === 'alerts' && (
            <div style={{ display: 'grid', gridTemplateColumns: selectedAlert ? '1fr 360px' : '1fr', gap: 16, height: '100%' }}>
              <AlertFeed onAlertClick={setSelectedAlert} />
              <AlertDetail alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
            </div>
          )}

          {view === 'attacks' && (
            <div style={{ overflow: 'auto', height: '100%' }}>
              <AttackMap metrics={metrics} />
              <div style={{ marginTop: 16 }}>
                <AlertFeed onAlertClick={setSelectedAlert} />
              </div>
            </div>
          )}

          {view === 'scenarios' && (
            <div style={{ overflow: 'auto', height: '100%' }}>
              <ScenarioRunner />
              <div style={{ marginTop: 16 }}>
                <MetricsPanel metrics={metrics} />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
