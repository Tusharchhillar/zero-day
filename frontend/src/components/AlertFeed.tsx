import { useEffect, useRef, useState, useCallback } from 'react';
import { AlertTriangle, Wifi, WifiOff, ChevronRight, ChevronDown, Eye } from 'lucide-react';
import {
  API_BASE, WS_URL, SEVERITY_COLORS, SEVERITY_BG, THREAT_ICONS, styles,
} from '../types';
import type { Alert } from '../types';

interface Props {
  onAlertClick: (alert: Alert) => void;
}

// ─── Real-time Alert Feed via WebSocket ──────────────────────────────
export default function AlertFeed({ onAlertClick }: Props) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [expandedAlert, setExpandedAlert] = useState<number | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  const connectWs = useCallback(() => {
    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => setWsConnected(true);
      ws.onclose = () => {
        setWsConnected(false);
        setTimeout(connectWs, 3000);
      };
      ws.onerror = () => setWsConnected(false);

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'alert' && msg.data) {
            setAlerts(prev => [msg.data, ...prev].slice(0, 200));
          }
        } catch { /* ignore malformed */ }
      };
    } catch {
      setTimeout(connectWs, 3000);
    }
  }, []);

  useEffect(() => {
    connectWs();
    // Fetch historical alerts from REST
    fetch(`${API_BASE}/api/alerts?limit=50`)
      .then(r => r.json())
      .then(data => {
        if (Array.isArray(data)) {
          setAlerts(prev => {
            const existing = new Set(prev.map(a => a.timestamp + a.source_ip));
            const newAlerts = data.filter((a: Alert) => !existing.has(a.timestamp + a.source_ip));
            return [...newAlerts, ...prev].slice(0, 200);
          });
        }
      })
      .catch(() => {});
    return () => wsRef.current?.close();
  }, [connectWs]);

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = 0;
  }, [alerts.length]);

  const formatTime = (ts: string) => {
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch { return ts; }
  };

  return (
    <div style={styles.panel}>
      <div style={styles.panelHeader}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertTriangle size={18} color="#ff3366" />
          <span style={styles.panelTitle}>ALERT FEED</span>
          <span style={{ ...styles.badge, background: wsConnected ? 'rgba(0,255,136,0.2)' : 'rgba(255,51,102,0.2)' }}>
            {wsConnected ? <Wifi size={10} /> : <WifiOff size={10} />}
            {wsConnected ? 'LIVE' : 'OFFLINE'}
          </span>
        </div>
        <span style={{ color: '#4a5568', fontFamily: 'monospace', fontSize: 12 }}>
          {alerts.length} alerts
        </span>
      </div>
      <div ref={feedRef} style={styles.feedContainer}>
        {alerts.length === 0 && (
          <div style={{ textAlign: 'center', color: '#4a5568', padding: 40, fontFamily: 'monospace' }}>
            {wsConnected ? 'Waiting for alerts...' : 'Connecting to WebSocket...'}
          </div>
        )}
        {alerts.map((alert, i) => {
          const isExpanded = expandedAlert === i;
          return (
            <div key={i}>
              <div
                style={{
                  ...styles.alertRow,
                  borderLeftColor: SEVERITY_COLORS[alert.severity] || '#4a5568',
                  background: isExpanded ? SEVERITY_BG[alert.severity] || 'transparent' : 'transparent',
                }}
                onClick={() => {
                  setExpandedAlert(isExpanded ? null : i);
                  if (!isExpanded) onAlertClick(alert);
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1 }}>
                  <span style={{
                    ...styles.severityBadge,
                    color: SEVERITY_COLORS[alert.severity] || '#999',
                    background: SEVERITY_BG[alert.severity] || 'rgba(255,255,255,0.05)',
                    border: `1px solid ${SEVERITY_COLORS[alert.severity] || '#333'}`,
                  }}>
                    {alert.severity}
                  </span>
                  <span style={styles.threatTag}>
                    {THREAT_ICONS[alert.threat_class] || '❓'} {alert.threat_class}
                  </span>
                  <span style={styles.confidenceTag}>
                    {(alert.confidence * 100).toFixed(1)}%
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={styles.ipText}>{alert.source_ip} → {alert.dest_ip}</span>
                  <span style={{ color: '#4a5568', fontFamily: 'monospace', fontSize: 11 }}>
                    {formatTime(alert.timestamp)}
                  </span>
                  {isExpanded ? <ChevronDown size={14} color="#4a5568" /> : <ChevronRight size={14} color="#4a5568" />}
                </div>
              </div>
              {isExpanded && alert.evidence && alert.evidence.length > 0 && (
                <div style={styles.evidencePanel}>
                  <div style={styles.evidenceHeader}>
                    <Eye size={14} color="#00ff88" />
                    <span>EVIDENCE ({alert.evidence.length} items)</span>
                  </div>
                  {alert.evidence.map((ev, ei) => (
                    <div key={ei} style={styles.evidenceRow}>
                      <span style={styles.evidenceFeature}>{ev.feature}</span>
                      <span style={styles.evidenceValue}>{String(ev.value)}</span>
                      <span style={styles.evidenceReason}>{ev.reason}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
