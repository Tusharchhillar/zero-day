import { useEffect, useState } from 'react';
import { TrafficChart } from '../components/TrafficChart';
import { StatCard } from '../components/StatCard';
import type { TrafficStats } from '../types';
import { trafficService } from '../services';
import { LoadingState } from '../components/States';
import { DemoTag } from '../components/DemoTag';

export function TrafficPage() {
  const [stats, setStats] = useState<TrafficStats | null>(null);

  useEffect(() => {
    trafficService.stats().then(setStats);
  }, []);

  const cards = stats ? [
    { key: 'vol', label: 'Traffic Volume', value: `${(stats.totalVolumeMbps).toLocaleString()}`, support: 'Mbps aggregate', icon: 'activity', delta: '+6.2%', deltaDirection: 'up' as const },
    { key: 'flows', label: 'Flow Count', value: stats.flowCount.toLocaleString(), support: 'unidirectional 5-tuples', icon: 'branch', delta: '+4.8%', deltaDirection: 'up' as const },
    { key: 'pkts', label: 'Packet Count', value: (stats.packetCount / 1e6).toFixed(2) + 'M', support: 'captured packets', icon: 'activity', delta: '+5.1%', deltaDirection: 'up' as const },
    { key: 'bytes', label: 'Byte Count', value: stats.byteCount + ' GB', support: 'total volume', icon: 'branch', delta: '+5.9%', deltaDirection: 'up' as const },
    { key: 'active', label: 'Active Flows', value: stats.activeFlows.toLocaleString(), support: 'currently tracked', icon: 'heart', delta: '+2.3%', deltaDirection: 'up' as const },
  ] : [];

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Traffic</h1>
          <div className="sub">Volume, flows and protocol mix across monitored unidirectional traffic.</div>
        </div>
        <div className="page-head-actions"><DemoTag /></div>
      </div>

      {!stats ? (
        <div className="stat-grid">{Array.from({ length: 5 }).map((_, i) => <div key={i} className="skeleton skel-card" />)}</div>
      ) : (
        <div className="stat-grid">{cards.map((c) => <StatCard key={c.key} data={c as any} />)}</div>
      )}

      <div className="section">
        <div className="card card-pad">
          <TrafficChart height={320} />
        </div>
      </div>

      <div className="grid-2">
        {!stats ? <LoadingState /> : (
          <div className="card card-pad">
            <div className="chart-title" style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>Top Source Endpoints <DemoTag /></div>
            {stats.topSources.map((s, i) => (
              <div key={s.name} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5, marginBottom: 4 }}>
                  <span className="mono">{i + 1}. {s.name}</span><b className="mono" style={{ color: 'var(--accent)' }}>{s.value} Mbps</b>
                </div>
                <div style={{ height: 6, background: 'var(--surface-3)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${(s.value / stats.topSources[0].value) * 100}%`, height: '100%', background: 'var(--accent)', opacity: 0.85 }} />
                </div>
              </div>
            ))}
          </div>
        )}
        {!stats ? <LoadingState /> : (
          <div className="card card-pad">
            <div className="chart-title" style={{ marginBottom: 12 }}>Top Destination Endpoints</div>
            {stats.topDestinations.map((s, i) => (
              <div key={s.name} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5, marginBottom: 4 }}>
                  <span className="mono">{i + 1}. {s.name}</span><b className="mono" style={{ color: 'var(--accent-2)' }}>{s.value} Mbps</b>
                </div>
                <div style={{ height: 6, background: 'var(--surface-3)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${(s.value / stats.topDestinations[0].value) * 100}%`, height: '100%', background: 'var(--accent-2)', opacity: 0.8 }} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="section" style={{ marginTop: 20 }}>
        {!stats ? <LoadingState /> : (
          <div className="card card-pad">
            <div className="chart-title" style={{ marginBottom: 16 }}>Protocol Distribution</div>
            <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
              {stats.protocolDistribution.map((p) => (
                <div key={p.protocol} style={{ flex: 1, minWidth: 140 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 5 }}>
                    <span style={{ color: 'var(--ink-2)' }}>{p.protocol}</span><b className="mono">{p.value}%</b>
                  </div>
                  <div style={{ height: 9, background: 'var(--surface-3)', borderRadius: 5, overflow: 'hidden' }}>
                    <div style={{ width: `${p.value}%`, height: '100%', background: 'var(--accent)', borderRadius: 5, opacity: 0.85 }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
