import { useEffect, useState } from 'react';
import { alertService } from '../services';
import type { Alert, AlertStatus } from '../types';
import { Drawer } from './Drawer';
import { SeverityBadge, StatusPill } from './Badge';
import { fmtTime, relTime } from '../lib/theme';
import { useToast } from './Toast';
import { LoadingState } from './States';

const STATUSES: AlertStatus[] = ['New', 'Investigating', 'Acknowledged', 'Resolved'];

export function AlertDetails({ alertId, onClose, onStatusChange }: { alertId: string | null; onClose: () => void; onStatusChange?: () => void }) {
  const [alert, setAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(false);
  const [updating, setUpdating] = useState(false);
  const toast = useToast();

  useEffect(() => {
    if (!alertId) { setAlert(null); return; }
    let alive = true;
    setLoading(true);
    alertService.byId(alertId).then((a) => {
      if (alive) { setAlert(a ?? null); setLoading(false); }
    });
    return () => { alive = false; };
  }, [alertId]);

  const updateStatus = async (status: AlertStatus) => {
    if (!alert) return;
    setUpdating(true);
    const updated = await alertService.updateStatus(alert.id, status);
    setAlert(updated);
    setUpdating(false);
    onStatusChange?.();
    toast('success', `Alert ${alert.id} marked as ${status}`);
  };

  return (
    <Drawer
      open={!!alertId}
      onClose={onClose}
      title={alert ? `Alert ${alert.id}` : 'Alert detail'}
      subtitle={alert ? `${alert.threatClass} · ${relTime(alert.timestamp)}` : undefined}
      headRight={alert && <SeverityBadge severity={alert.severity} />}
      footer={
        alert && (
          <>
            {STATUSES.map((s) => (
              <button
                key={s}
                className={`btn btn-sm ${alert.status === s ? 'btn-primary' : ''}`}
                disabled={updating || alert.status === s}
                onClick={() => updateStatus(s)}
              >
                {updating && alert.status !== s ? <span className="spinner" /> : null}
                {s}
              </button>
            ))}
          </>
        )
      }
    >
      {loading && !alert && <LoadingState rows={4} />}
      {!loading && !alert && <div className="state-box"><p>Alert not found.</p></div>}
      {alert && (
        <>
          <div style={{ fontSize: 13.5, color: 'var(--ink-2)', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 'var(--r-md)', padding: 14, marginBottom: 8 }}>
            {alert.summary}
          </div>

          <div className="section-label" style={{ marginTop: 8 }}>Overview</div>
          <div className="detail-grid">
            <div className="detail-item"><span className="k">Threat Category</span><span className="v">{alert.sihCategory}</span></div>
            <div className="detail-item"><span className="k">Status</span><span className="v"><StatusPill status={alert.status} /></span></div>
            <div className="detail-item"><span className="k">Confidence</span><span className="v mono">{Math.round(alert.confidence * 1000) / 10}%</span></div>
            <div className="detail-item"><span className="k">Detected At</span><span className="v mono">{fmtTime(alert.timestamp)}</span></div>
            <div className="detail-item"><span className="k">Detection Method</span><span className="v">{alert.detectionMethod}</span></div>
            <div className="detail-item"><span className="k">Flow ID</span><span className="v mono">{alert.flowId}</span></div>
          </div>

          <div className="section-label">Flow</div>
          <div className="detail-grid">
            <div className="detail-item">
              <span className="k">Source</span>
              <span className="v mono">{alert.source.ip}:{alert.source.port}</span>
            </div>
            <div className="detail-item">
              <span className="k">Destination</span>
              <span className="v mono">{alert.destination.ip}:{alert.destination.port}</span>
            </div>
            <div className="detail-item"><span className="k">Protocol</span><span className="v">{alert.protocol}</span></div>
            <div className="detail-item"><span className="k">Detection Latency</span><span className="v mono">{alert.detectionLatencyMs} ms</span></div>
          </div>

          <div className="section-label">Evidence</div>
          <ul className="evidence-list">
            {alert.evidence.map((e) => <li key={e}>{e}</li>)}
          </ul>

          <div className="section-label">Contributing Features</div>
          {alert.contributingFeatures.length > 0 ? (
            <table className="feat-table">
              <tbody>
                {alert.contributingFeatures.map((f) => (
                  <tr key={f.name}><td>{f.name}</td><td>{f.value}</td></tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="state-box" style={{ padding: 20 }}><p>No feature data (awaiting backend).</p></div>
          )}

          <div className="section-label">Detector Outputs</div>
          {alert.detectorOutputs.map((d) => (
            <div className="detector-row" key={d.detector}>
              <div>
                <div className="d-name">{d.detector}</div>
                <div style={{ fontSize: 11.5, color: 'var(--muted)' }}>Detector output</div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span className="d-score">{d.score.toFixed(2)}</span>
                {d.triggered ? <span className="trigger">TRIGGERED</span> : <span style={{ fontSize: 11, color: 'var(--muted)' }}>idle</span>}
              </div>
            </div>
          ))}

          <div className="section-label" style={{ marginTop: 20 }}>Model Score</div>
          <div className="conf" style={{ padding: '10px 0' }}>
            <span className="bar" style={{ width: 140, height: 8 }}><span style={{ width: `${Math.round((alert.modelScore ?? alert.confidence) * 100)}%` }} /></span>
            <b style={{ fontSize: 15 }}>{(alert.modelScore ?? alert.confidence).toFixed(3)}</b>
            <span style={{ color: 'var(--faint)', fontSize: 11.5 }}>(demo value)</span>
          </div>

          <div className="section-label">Analyst Interpretation</div>
          <div style={{ fontSize: 13, color: 'var(--ink-2)', background: 'var(--accent-dim)', border: '1px solid rgba(34,211,238,0.2)', borderRadius: 'var(--r-md)', padding: 14, lineHeight: 1.55 }}>
            {alert.analystInterpretation}
          </div>

          <div style={{ marginTop: 20, fontSize: 11.5, color: 'var(--faint)' }}>
            Magnitude {alert.magnitude.toFixed(2)} · Severity score and all values are DEMO DATA and do not reflect a real AI model.
          </div>
        </>
      )}
    </Drawer>
  );
}
