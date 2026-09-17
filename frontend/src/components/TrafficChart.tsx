import { useState, useEffect, useRef, useCallback } from 'react';
import {
  ResponsiveContainer, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ComposedChart, Line,
} from 'recharts';
import type { TrafficPoint } from '../types';
import { trafficService, API_BASE } from '../services';

const RANGES = ['1H', '6H', '24H', '7D', '30D'];

// ── Shared persistent state (survives component remounts) ────────────────
const globalChartState = {
  data: [] as TrafficPoint[],
  loading: true,
  lastRange: '24H',
  initialized: false,
};

interface AttackSurgeState {
  active: boolean;
  threatClass: string;
  category: string;
  expireAt: number;
}

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'rgba(6, 12, 28, 0.96)',
      border: '1px solid rgba(0, 212, 255, 0.3)',
      borderRadius: 12,
      padding: '12px 14px',
      boxShadow: '0 0 24px rgba(0, 200, 255, 0.15), 0 8px 32px rgba(0, 0, 0, 0.5)',
      backdropFilter: 'blur(20px)',
    }}>
      <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 6, fontFamily: 'var(--font-mono)' }}>{label || ''}</div>
      {payload.map((p: any, idx: number) => {
        const name = String(p?.name || '');
        const val = typeof p?.value === 'number' ? p.value : 0;
        return (
          <div key={name || idx} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, marginTop: 3 }}>
            <span style={{
              width: 8, height: 8, borderRadius: 3, background: p?.color || '#38bdf8',
              boxShadow: `0 0 8px ${p?.color || '#38bdf8'}aa`,
            }} />
            <span style={{ color: 'var(--ink-2)' }}>{name}:</span>
            <b style={{ fontFamily: 'var(--font-mono)', color: 'var(--ink)' }}>
              {name.includes('Flows') ? val.toLocaleString() : `${val} Mbps`}
            </b>
          </div>
        );
      })}
    </div>
  );
}

/**
 * Generate a new animated data point that reacts in real-time to attack surges,
 * creating an immediate, dramatic visual response when attacks hit the system.
 */
function generateNextPoint(last: TrafficPoint | undefined, surge: AttackSurgeState | null): TrafficPoint {
  const now = new Date();
  const t = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
  const rand = (Math.random() - 0.5);

  const lastVol = (last && typeof last.volume === 'number' && !isNaN(last.volume)) ? last.volume : 180;
  const lastSus = (last && typeof last.suspicious === 'number' && !isNaN(last.suspicious)) ? last.suspicious : 5;

  const isSurge = Boolean(surge && surge.active && surge.expireAt > Date.now());
  const decay = isSurge ? Math.max(0.15, ((surge?.expireAt ?? 0) - Date.now()) / 14000) : 0;

  if (isSurge) {
    const tc = String(surge?.threatClass || '').toLowerCase();
    let volBoost = 240 * decay;
    let susBoost = 160 * decay;
    let flowBoost = 3500 * decay;

    if (tc.includes('ddos') || tc.includes('syn')) {
      volBoost = 420 * decay;
      susBoost = 260 * decay;
      flowBoost = 8500 * decay;
    } else if (tc.includes('exfil') || tc.includes('sql')) {
      volBoost = 290 * decay;
      susBoost = 230 * decay;
      flowBoost = 2200 * decay;
    } else if (tc.includes('scan') || tc.includes('probe') || tc.includes('recon')) {
      volBoost = 150 * decay;
      susBoost = 95 * decay;
      flowBoost = 12000 * decay;
    } else if (tc.includes('beacon') || tc.includes('c2')) {
      volBoost = 130 * decay;
      susBoost = 110 * decay;
      flowBoost = 1400 * decay;
    } else if (tc.includes('tunnel') || tc.includes('dga') || tc.includes('malware')) {
      volBoost = 210 * decay;
      susBoost = 175 * decay;
      flowBoost = 4000 * decay;
    }

    const baselineVol = 180 + 40 * Math.sin(now.getHours() * Math.PI / 12);
    const volume = Math.max(80, Math.min(850, baselineVol + volBoost + rand * 15));
    const suspicious = Math.max(10, Math.min(volume * 0.95, susBoost + rand * 8));
    const flows = Math.max(200, Math.round(volume * 9 + flowBoost + rand * 100));

    return { t, volume: +volume.toFixed(2), suspicious: +suspicious.toFixed(2), flows };
  }

  // Normal Baseline Monitoring (organic diurnal pattern + low suspicious baseline)
  const targetVol = 180 + 50 * Math.sin(now.getHours() * Math.PI / 12);
  const volDelta = (targetVol - lastVol) * 0.08 + rand * 4;
  const volume = Math.max(60, Math.min(380, lastVol + volDelta));

  // Normal suspicious traffic is low (2-5% of volume)
  const targetSus = volume * 0.035;
  const susDelta = (targetSus - lastSus) * 0.1 + rand * 0.6;
  const suspicious = Math.max(0.5, Math.min(volume * 0.12, lastSus + susDelta));

  const flows = Math.max(80, Math.round(volume * (9 + rand * 1.5)));

  return { t, volume: +volume.toFixed(2), suspicious: +suspicious.toFixed(2), flows };
}

export function TrafficChart({ height = 300 }: { height?: number }) {
  const [range, setRange] = useState('24H');
  const [data, setData] = useState<TrafficPoint[]>(() => globalChartState.data);
  const [loading, setLoading] = useState(() => globalChartState.loading);
  const [live, setLive] = useState(true);
  const [surge, setSurge] = useState<AttackSurgeState | null>(null);

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const dataRef = useRef<TrafficPoint[]>(data);
  const surgeRef = useRef<AttackSurgeState | null>(surge);
  const lastAlertCountRef = useRef<number>(-1);
  const lastEventsProcessedRef = useRef<number>(-1);

  // Keep refs in sync
  useEffect(() => { dataRef.current = data; }, [data]);
  useEffect(() => { surgeRef.current = surge; }, [surge]);

  // Trigger an attack surge on the chart
  const triggerSurge = useCallback((threatClass: string, category: string = '') => {
    const newState: AttackSurgeState = {
      active: true,
      threatClass: threatClass || 'Malicious Threat',
      category: category || threatClass,
      expireAt: Date.now() + 14000, // Surge lasts 14 seconds
    };
    setSurge(newState);
    surgeRef.current = newState;
  }, []);

  // Sync local state with global state on mount
  useEffect(() => {
    if (globalChartState.initialized && globalChartState.lastRange === range) {
      setData(globalChartState.data);
      setLoading(globalChartState.loading);
    }
  }, [range]);

  // Fetch initial data
  useEffect(() => {
    if (globalChartState.initialized && globalChartState.lastRange === range) return;

    let alive = true;
    setLoading(true);
    trafficService.series(range).then((d) => {
      if (alive) {
        setData(d);
        globalChartState.data = d;
        globalChartState.loading = false;
        globalChartState.lastRange = range;
        globalChartState.initialized = true;
        setLoading(false);
      }
    });
    return () => { alive = false; };
  }, [range]);

  // WebSocket Live Alert Listener: immediately triggers graph threat spike on incoming alert
  useEffect(() => {
    const wsHost = window.location.hostname || 'localhost';
    const wsUrl = `ws://${wsHost}:9000/ws/alerts`;
    let ws: WebSocket | null = null;
    let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
    let isCancelled = false;

    const connect = () => {
      if (isCancelled) return;
      try {
        ws = new WebSocket(wsUrl);
        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'alert' && msg.data) {
              triggerSurge(msg.data.threat_class || 'attack', msg.data.sih_category || '');
            }
          } catch {
            // Ignore parse errors
          }
        };
        ws.onerror = () => {
          ws?.close();
        };
        ws.onclose = () => {
          if (!isCancelled) {
            reconnectTimeout = setTimeout(connect, 4000);
          }
        };
      } catch {
        if (!isCancelled) {
          reconnectTimeout = setTimeout(connect, 5000);
        }
      }
    };

    connect();

    return () => {
      isCancelled = true;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (ws) {
        ws.onclose = null;
        ws.close();
      }
    };
  }, [triggerSurge]);

  // Fallback Poller: checks /api/metrics & /api/alerts/live to detect new attacks even if WebSocket drops
  useEffect(() => {
    const checkMetrics = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/metrics`);
        if (!res.ok) return;
        const m = await res.json();

        const curAlerts = m.alerts_emitted ?? 0;
        const curEvents = m.events_processed ?? 0;

        // First run: just save baseline
        if (lastAlertCountRef.current === -1) {
          lastAlertCountRef.current = curAlerts;
          lastEventsProcessedRef.current = curEvents;
          return;
        }

        // If alerts increased or significant event jump occurred, trigger surge!
        if (curAlerts > lastAlertCountRef.current) {
          lastAlertCountRef.current = curAlerts;
          triggerSurge('Threat Detected', 'Anomalous Threat Traffic');
        } else if (curEvents - lastEventsProcessedRef.current > 50) {
          lastEventsProcessedRef.current = curEvents;
          triggerSurge('Volumetric Spike', 'High-Rate Flow Injection');
        }
        lastEventsProcessedRef.current = curEvents;
      } catch {
        // Backend offline or unreachable
      }
    };

    pollRef.current = setInterval(checkMetrics, 2000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [triggerSurge]);

  // Live animation loop: append next point every 1.5s
  const startLive = useCallback(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    intervalRef.current = setInterval(() => {
      const current = dataRef.current;
      if (current.length === 0) return;
      const last = current[current.length - 1];
      const next = generateNextPoint(last, surgeRef.current);

      setData((prev) => {
        const updated = [...prev, next];
        // Keep max 60 points
        const trimmed = updated.length > 60 ? updated.slice(-60) : updated;
        globalChartState.data = trimmed;
        return trimmed;
      });

      // Clear surge state once expired
      if (surgeRef.current && surgeRef.current.expireAt <= Date.now()) {
        setSurge(null);
        surgeRef.current = null;
      }
    }, 1500);
  }, []);

  useEffect(() => {
    if (live && !loading && data.length > 0) {
      startLive();
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [live, loading, data.length, startLive]);

  if (loading && data.length === 0) return <div className="skeleton skel-chart" />;

  const isSurgeActive = surge && surge.active && surge.expireAt > Date.now();

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8, flexWrap: 'wrap', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div className="chart-title">Network Traffic Overview</div>
          <button
            className={`btn btn-sm ${live ? 'btn-active' : ''}`}
            onClick={() => setLive((v) => !v)}
            style={{ fontSize: 11, height: 26, padding: '0 10px', gap: 5 }}
          >
            <span style={{
              width: 6, height: 6, borderRadius: '50%',
              background: live ? 'var(--sev-healthy)' : 'var(--faint)',
              boxShadow: live ? '0 0 8px rgba(48, 224, 96, 0.6)' : 'none',
              animation: live ? 'pulse-dot 2s ease-in-out infinite' : 'none',
            }} />
            {live ? 'LIVE' : 'PAUSED'}
          </button>

          {isSurgeActive && (
            <div style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              background: 'rgba(255, 64, 96, 0.15)',
              border: '1px solid rgba(255, 64, 96, 0.4)',
              color: '#ff4060',
              borderRadius: 20,
              padding: '2px 10px',
              fontSize: 11,
              fontWeight: 700,
              letterSpacing: '0.3px',
              animation: 'pulse 1s ease-in-out infinite',
            }}>
              <span style={{
                width: 6, height: 6, borderRadius: '50%', background: '#ff4060',
                boxShadow: '0 0 8px #ff4060',
              }} />
              ⚡ THREAT SURGE: {surge?.threatClass.toUpperCase().replace(/_/g, ' ')}
            </div>
          )}
        </div>
        <div className="time-range" role="tablist" aria-label="Time range">
          {RANGES.map((r) => (
            <button key={r} role="tab" aria-selected={range === r} className={range === r ? 'active' : ''} onClick={() => setRange(r)}>
              {r}
            </button>
          ))}
        </div>
      </div>
      <ResponsiveContainer width="100%" height={height}>
        <ComposedChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="gVol" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#a855f7" stopOpacity={0.4} />
              <stop offset="100%" stopColor="#a855f7" stopOpacity={0.01} />
            </linearGradient>
            <linearGradient id="gSus" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#ff4060" stopOpacity={0.7} />
              <stop offset="100%" stopColor="#ff4060" stopOpacity={0.08} />
            </linearGradient>
            <filter id="glow">
              <feGaussianBlur stdDeviation="2.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <filter id="glowStrong">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <CartesianGrid stroke="rgba(0, 190, 255, 0.07)" vertical={false} strokeDasharray="3 3" />
          <XAxis dataKey="t" tickLine={false} axisLine={false} minTickGap={40} />
          <YAxis yAxisId="mbps" tickLine={false} axisLine={false} width={44} />
          <YAxis yAxisId="flows" orientation="right" tickLine={false} axisLine={false} width={50} />
          <Tooltip content={<ChartTooltip />} />
          <Legend wrapperStyle={{ fontSize: 12, paddingTop: 8 }} iconType="plainline" />
          <Area yAxisId="mbps" type="monotone" dataKey="volume" name="Traffic volume (Mbps)" stroke="#a855f7" strokeWidth={2.5} fill="url(#gVol)" filter="url(#glow)" isAnimationActive={false} />
          <Area yAxisId="mbps" type="monotone" dataKey="suspicious" name="Suspicious (Mbps)" stroke="#ff4060" strokeWidth={2.5} fill="url(#gSus)" filter="url(#glow)" isAnimationActive={false} />
          <Line yAxisId="flows" type="monotone" dataKey="flows" name="Flows" stroke="#38bdf8" strokeWidth={2.0} dot={false} strokeDasharray="5 4" filter="url(#glowStrong)" isAnimationActive={false} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}

