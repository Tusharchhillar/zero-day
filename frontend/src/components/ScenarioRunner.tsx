import { useEffect, useState } from 'react';
import { Play, Square } from 'lucide-react';
import { API_BASE, styles } from '../types';
import type { Scenario } from '../types';

// ─── Scenario Runner — replay attacks via REST ───────────────────────
export default function ScenarioRunner() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [status, setStatus] = useState('');

  const loadScenarios = () => {
    fetch(`${API_BASE}/api/scenarios`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(data => {
        if (Array.isArray(data)) {
          setScenarios(data.map((s: Scenario | string) =>
            typeof s === 'string' ? { name: s } : s
          ));
          setStatus('');
        } else {
          throw new Error('Unexpected shape');
        }
      })
      .catch(() => setStatus('Failed to load scenarios — retrying...'));
  };

  useEffect(() => {
    loadScenarios();
    // Retry every 4s until we get the list (backend may have been down at mount)
    const retry = setInterval(() => {
      if (scenarios.length === 0) loadScenarios();
    }, 4000);
    return () => clearInterval(retry);
  }, [scenarios.length]);

  const startScenario = async (name: string) => {
    setStatus(`Starting ${name}...`);
    try {
      const res = await fetch(`${API_BASE}/api/replay/${name}`, { method: 'POST' });
      if (res.ok) {
        setRunning(name);
        setStatus(`Running: ${name}`);
      } else {
        setStatus(`Failed: ${res.statusText}`);
      }
    } catch {
      setStatus('Connection failed');
    }
  };

  const stopScenario = async () => {
    try {
      await fetch(`${API_BASE}/api/replay/stop`, { method: 'POST' });
      setRunning(null);
      setStatus('Stopped');
    } catch {
      setStatus('Stop failed');
    }
  };

  return (
    <div style={styles.panel}>
      <div style={styles.panelHeader}>
        <Play size={18} color="#00ff88" />
        <span style={styles.panelTitle}>SCENARIO RUNNER</span>
      </div>
      <div style={{ padding: '0 16px 16px' }}>
        {status && (
          <div style={{
            padding: '8px 12px', borderRadius: 6, marginBottom: 12,
            background: 'rgba(0,255,136,0.08)', border: '1px solid rgba(0,255,136,0.2)',
            fontFamily: 'monospace', fontSize: 12, color: '#00ff88',
          }}>
            {status}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 10, marginBottom: 12 }}>
          {scenarios.map((s) => (
            <div key={s.name} style={styles.scenarioCard}>
              <div style={{ fontSize: 13, fontWeight: 600, color: '#e0e0e0' }}>{s.name}</div>
              {s.description && <div style={{ fontSize: 11, color: '#6b7280', marginTop: 4 }}>{s.description}</div>}
              <button
                onClick={() => startScenario(s.name)}
                disabled={running !== null}
                style={{
                  ...styles.button,
                  background: running === s.name ? 'rgba(0,255,136,0.2)' : 'rgba(0,255,136,0.1)',
                  border: `1px solid ${running === s.name ? '#00ff88' : 'rgba(0,255,136,0.3)'}`,
                  opacity: running !== null && running !== s.name ? 0.4 : 1,
                  marginTop: 8,
                }}
              >
                <Play size={12} />
                {running === s.name ? 'Running...' : 'Replay'}
              </button>
            </div>
          ))}
          {scenarios.length === 0 && (
            <div style={{ color: '#4a5568', fontFamily: 'monospace', fontSize: 12, gridColumn: '1 / -1', textAlign: 'center', padding: 20 }}>
              No scenarios available
            </div>
          )}
        </div>

        {running && (
          <button onClick={stopScenario} style={{ ...styles.button, background: 'rgba(255,51,102,0.15)', border: '1px solid #ff3366', color: '#ff3366', width: '100%' }}>
            <Square size={14} />
            Stop Scenario
          </button>
        )}
      </div>
    </div>
  );
}
