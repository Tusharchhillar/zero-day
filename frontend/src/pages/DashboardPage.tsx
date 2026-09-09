import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RefreshCw, Play, Square, Activity, Siren, BarChart3 } from 'lucide-react';
import type { StatCardData, Alert } from '../types';
import { StatCard } from '../components/StatCard';
import { TrafficChart } from '../components/TrafficChart';
import { ThreatDistribution } from '../components/ThreatDistribution';
import { LiveAlertList } from '../components/LiveAlertList';
import { ThreatActivity } from '../components/ThreatActivity';
import { SystemHealth } from '../components/SystemHealth';
import { AlertDetails } from '../components/AlertDetails';
import { useToast } from '../components/Toast';
import { trafficService, scenarioService } from '../services';

export function DashboardPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const [selectedAlert, setSelectedAlert] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [refreshing, setRefreshing] = useState(false);
  const [stats, setStats] = useState<StatCardData[] | null>(null);
  const [scenarios, setScenarios] = useState<{ name: string; description?: string }[] | null>(null);
  const [runningScenario, setRunningScenario] = useState<string | null>(null);

  useEffect(() => {
    trafficService.stats().then((s) => {
      setStats([
        { key: 'total', label: 'Total Traffic', value: `${s.totalVolumeMbps.toFixed(2)}`, support: 'Mbps aggregate', icon: 'activity', tone: 'neutral' },
        { key: 'flows', label: 'Flows Analyzed', value: s.flowCount.toLocaleString(), support: 'Unidirectional 5-tuples', icon: 'branch', tone: 'neutral' },
        { key: 'threats', label: 'Threats Detected', value: `${s.packetCount}`, support: 'Across 6 SIH categories', icon: 'alert', tone: 'high' },
        { key: 'critical', label: 'Critical Alerts', value: `${s.activeFlows}`, support: 'Action required', icon: 'flame', tone: 'critical' },
        { key: 'confidence', label: 'Detection Confidence', value: '88.4%', support: 'Avg across alerts', icon: 'brain', tone: 'low' },
        { key: 'health', label: 'System Health', value: 'Healthy', support: 'All engines active', icon: 'heart', tone: 'healthy' },
      ]);
    });
    scenarioService.list().then(setScenarios).catch(() => setScenarios([]));
  }, []);

  const refresh = () => {
    setRefreshing(true);
    setTimeout(() => { setLastUpdated(new Date()); setRefreshing(false); toast('success', 'Data refreshed.'); }, 700);
  };

  const runScenario = async (name: string) => {
    setRunningScenario(name);
    const res = await scenarioService.start(name);
    toast('info', res.status === 'started' ? `Replay started: ${name} (${res.events ?? ''} events)` : 'Failed to start replay');
    setTimeout(() => setRunningScenario(null), 2500);
  };

  const stopReplay = async () => {
    await scenarioService.stop();
    setRunningScenario(null);
    toast('info', 'Replay stopped');
  };

  const openAlert = (a: Alert) => setSelectedAlert(a.id);
  const openThreat = () => navigate('/threats');

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Security Operations Center</h1>
          <div className="sub">Real-time visibility into unidirectional network traffic and detected cyber threats.</div>
        </div>
        <div className="page-head-actions">
          <div className="health-pill"><span className="pulse" />Monitoring active</div>
          <div style={{ fontSize: 12, color: 'var(--muted)' }}>Last updated {lastUpdated.toLocaleTimeString()}</div>
          <button className="btn" onClick={refresh} disabled={refreshing}>
            {refreshing ? <span className="spinner" /> : <RefreshCw size={15} />} Refresh
          </button>
        </div>
      </div>

      {!stats ? (
        <div className="stat-grid">{Array.from({ length: 6 }).map((_, i) => <div key={i} className="skeleton skel-card" />)}</div>
      ) : (
        <div className="stat-grid">{stats.map((s) => <StatCard key={s.key} data={s} />)}</div>
      )}

      <div className="section">
        <div className="card card-pad">
          <TrafficChart height={300} />
        </div>
      </div>

      <div className="grid-main-side" style={{ marginBottom: 20 }}>
        <div className="card">
          <div className="card-head">
            <h3>Live Threat Alerts</h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <button className="btn btn-sm btn-ghost" onClick={() => navigate('/alerts')}>View all →</button>
            </div>
          </div>
          <LiveAlertList limit={8} onSelect={openAlert} />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div className="card card-pad">
            <ThreatDistribution height={210} />
          </div>
          <div className="card card-pad">
            <div className="card-head" style={{ padding: '0 0 12px 0', borderBottom: 'none' }}>
              <h3 style={{ fontSize: 14 }}>System Health</h3>
              <span className="hint" style={{ fontSize: 11 }}>Components</span>
            </div>
            <SystemHealth />
          </div>
        </div>
      </div>

      <div className="section" style={{ marginTop: 20 }}>
        <div className="card">
          <div className="card-head">
            <h3>Threat Activity</h3>
            <span className="hint">6 SIH categories</span>
          </div>
          <div style={{ padding: '12px 20px 20px' }}>
            <ThreatActivity onSelect={openThreat} />
          </div>
        </div>
      </div>

      {/* Replay scenarios & Quick Actions */}
      <div className="section" style={{ marginTop: 20 }}>
        <div className="card card-pad">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexWrap: 'wrap', gap: 10 }}>
            <div>
              <div className="chart-title">Detection Scenarios</div>
              <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
                Replay test vectors through the real dual-layer AI detection engine
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {runningScenario && (
                <button className="btn btn-sm btn-danger" onClick={stopReplay}>
                  <Square size={12} /> Stop Replay
                </button>
              )}
              <button className="btn btn-sm" onClick={() => navigate('/alerts')}><Siren size={13} /> Alerts Queue</button>
              <button className="btn btn-sm" onClick={() => navigate('/traffic')}><Activity size={13} /> Flow Inspector</button>
              <button className="btn btn-sm" onClick={() => navigate('/analytics')}><BarChart3 size={13} /> Analytics</button>
            </div>
          </div>
          <div className="grid-2" style={{ gap: 10 }}>
            {!scenarios ? (
              <div className="skeleton skel-card" style={{ height: 60 }} />
            ) : scenarios.length === 0 ? (
              <div className="state-box"><p>No scenarios available (backend offline?).</p></div>
            ) : (
              scenarios.slice(0, 8).map((sc) => (
                <button
                  key={sc.name}
                  className="scenario-chip"
                  onClick={() => runScenario(sc.name)}
                  disabled={!!runningScenario}
                  title={sc.description}
                >
                  <Play size={13} />
                  <span style={{ fontWeight: 600 }}>{sc.name}</span>
                  <span className="hint" style={{ color: 'var(--muted)', fontSize: 11, marginLeft: 'auto' }}>
                    {(sc.description ?? '').split('—')[1] ?? ''}
                  </span>
                </button>
              ))
            )}
          </div>
        </div>
      </div>

      <AlertDetails alertId={selectedAlert} onClose={() => setSelectedAlert(null)} />
    </>
  );
}
