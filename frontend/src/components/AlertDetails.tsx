import { useEffect, useState } from 'react';
import { alertService } from '../services';
import type { Alert, AlertStatus } from '../types';
import { Drawer } from './Drawer';
import { SeverityBadge, StatusPill } from './Badge';
import { fmtTime, relTime } from '../lib/theme';
import { useToast } from './Toast';
import { LoadingState } from './States';
import { ErrorBoundary } from './ErrorBoundary';

const STATUSES: AlertStatus[] = ['New', 'Investigating', 'Acknowledged', 'Resolved'];

function formatEvidence(e: any): string {
  if (e === null || e === undefined) return '';
  if (typeof e === 'string') {
    try {
      const parsed = JSON.parse(e);
      if (typeof parsed === 'object' && parsed !== null) {
        return formatEvidence(parsed);
      }
    } catch {
      // not JSON string, return as-is
    }
    return e;
  }
  if (typeof e === 'object') {
    if (e.reason) return String(e.reason);
    if (e.feature) return `${e.feature} = ${e.value ?? ''} ${e.reason ? `(${e.reason})` : ''}`.trim();
    if (e.name) return `${e.name} = ${e.value ?? ''}`;
    try {
      return JSON.stringify(e);
    } catch {
      return '[Forensic Record]';
    }
  }
  return String(e);
}

function formatSafeTime(iso?: string): string {
  if (!iso) return 'N/A';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return fmtTime(iso);
  } catch {
    return String(iso);
  }
}

function formatSafeRelTime(iso?: string): string {
  if (!iso) return 'recently';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return 'recently';
    return relTime(iso);
  } catch {
    return 'recently';
  }
}

export function AlertDetails({
  alertId,
  onClose,
  onStatusChange,
}: {
  alertId: string | null;
  onClose: () => void;
  onStatusChange?: () => void;
}) {
  const [alert, setAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(false);
  const [updating, setUpdating] = useState(false);
  const toast = useToast();

  useEffect(() => {
    if (!alertId) {
      setAlert(null);
      return;
    }
    let alive = true;
    setLoading(true);
    alertService
      .byId(alertId)
      .then((a) => {
        if (alive) {
          setAlert(a ?? null);
          setLoading(false);
        }
      })
      .catch((err) => {
        console.error('[AlertDetails] Failed to load alert:', err);
        if (alive) {
          setAlert(null);
          setLoading(false);
        }
      });
    return () => {
      alive = false;
    };
  }, [alertId]);

  const updateStatus = async (status: AlertStatus) => {
    if (!alert) return;
    setUpdating(true);
    try {
      const updated = await alertService.updateStatus(alert.id, status);
      setAlert(updated);
      onStatusChange?.();
      toast('success', `Alert ${alert.id} marked as ${status}`);
    } catch (err) {
      console.error('[AlertDetails] Status update failed:', err);
      toast('error', 'Failed to update alert status');
    } finally {
      setUpdating(false);
    }
  };

  const confidenceScore =
    typeof alert?.confidence === 'number' && !isNaN(alert.confidence)
      ? alert.confidence
      : 0.9;

  const modelScoreNum =
    typeof alert?.modelScore === 'number' && !isNaN(alert.modelScore)
      ? alert.modelScore
      : confidenceScore;

  const magnitudeNum =
    typeof alert?.magnitude === 'number' && !isNaN(alert.magnitude)
      ? alert.magnitude
      : confidenceScore;

  const latencyMs =
    typeof alert?.detectionLatencyMs === 'number' && !isNaN(alert.detectionLatencyMs)
      ? alert.detectionLatencyMs
      : 0;

  // Normalized evidence array of strings
  const rawEvidence = Array.isArray(alert?.evidence) ? alert!.evidence : [];
  const normalizedEvidence = rawEvidence
    .map(formatEvidence)
    .filter((s) => s.length > 0);

  // Normalized contributing features
  const rawFeatures = Array.isArray(alert?.contributingFeatures)
    ? alert!.contributingFeatures
    : [];

  const normalizedFeatures =
    rawFeatures.length > 0
      ? rawFeatures.map((f: any, i: number) => ({
          name: typeof f === 'object' && f?.name ? String(f.name) : `Feature ${i + 1}`,
          value: typeof f === 'object' ? String(f?.value ?? '') : String(f),
        }))
      : (rawEvidence as any[])
          .filter((e: any) => typeof e === 'object' && e !== null && (e.feature || e.name))
          .map((e: any) => ({
            name: String(e.feature || e.name),
            value: String(e.value ?? ''),
          }));

  // Normalized detector outputs
  const rawDetectors = Array.isArray(alert?.detectorOutputs)
    ? alert!.detectorOutputs
    : [];

  const normalizedDetectors =
    rawDetectors.length > 0
      ? rawDetectors.map((d, i) => ({
          detector: d?.detector || `Detector ${i + 1}`,
          score: typeof d?.score === 'number' && !isNaN(d.score) ? d.score : confidenceScore,
          triggered: Boolean(d?.triggered ?? true),
        }))
      : [
          {
            detector: alert?.detectionMethod || alert?.threatClass || 'ZERO-DAY Engine',
            score: confidenceScore,
            triggered: true,
          },
        ];

  return (
    <Drawer
      open={!!alertId}
      onClose={onClose}
      title={alert ? `Alert ${alert.id}` : 'Alert detail'}
      subtitle={
        alert
          ? `${alert.threatClass || alert.sihCategory || 'Threat'} · ${formatSafeRelTime(alert.timestamp)}`
          : undefined
      }
      headRight={alert ? <SeverityBadge severity={alert.severity || 'HIGH'} /> : null}
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
      <ErrorBoundary fallbackTitle="Could not display alert details" onReset={onClose}>
        {loading && !alert && <LoadingState rows={4} />}
        {!loading && !alert && (
          <div className="state-box">
            <p>Alert not found.</p>
          </div>
        )}
        {alert && (
          <>
            <div
              style={{
                fontSize: 13.5,
                color: 'var(--ink-2)',
                background: 'var(--bg)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--r-md)',
                padding: 14,
                marginBottom: 8,
              }}
            >
              {alert.summary || `${alert.sihCategory} — Detected by ZERO-DAY engine`}
            </div>

            <div className="section-label" style={{ marginTop: 8 }}>
              Overview
            </div>
            <div className="detail-grid">
              <div className="detail-item">
                <span className="k">Threat Category</span>
                <span className="v">{alert.sihCategory || 'Threat'}</span>
              </div>
              <div className="detail-item">
                <span className="k">Status</span>
                <span className="v">
                  <StatusPill status={alert.status || 'New'} />
                </span>
              </div>
              <div className="detail-item">
                <span className="k">Confidence</span>
                <span className="v mono">{Math.round(confidenceScore * 1000) / 10}%</span>
              </div>
              <div className="detail-item">
                <span className="k">Detected At</span>
                <span className="v mono">{formatSafeTime(alert.timestamp)}</span>
              </div>
              <div className="detail-item">
                <span className="k">Detection Method</span>
                <span className="v">{alert.detectionMethod || 'Rules + ML hybrid'}</span>
              </div>
              <div className="detail-item">
                <span className="k">Flow ID</span>
                <span className="v mono">{alert.flowId || 'N/A'}</span>
              </div>
            </div>

            <div className="section-label">Flow</div>
            <div className="detail-grid">
              <div className="detail-item">
                <span className="k">Source</span>
                <span className="v mono">
                  {alert.source?.ip ?? '0.0.0.0'}:{alert.source?.port ?? 443}
                </span>
              </div>
              <div className="detail-item">
                <span className="k">Destination</span>
                <span className="v mono">
                  {alert.destination?.ip ?? '0.0.0.0'}:{alert.destination?.port ?? 443}
                </span>
              </div>
              <div className="detail-item">
                <span className="k">Protocol</span>
                <span className="v">{alert.protocol || 'TCP'}</span>
              </div>
              <div className="detail-item">
                <span className="k">Detection Latency</span>
                <span className="v mono">{latencyMs} ms</span>
              </div>
            </div>

            <div className="section-label">Evidence</div>
            {normalizedEvidence.length > 0 ? (
              <ul className="evidence-list">
                {normalizedEvidence.map((e, idx) => (
                  <li key={idx}>
                    <span style={{ color: 'var(--accent)', marginRight: 4 }}>•</span>
                    <span>{e}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <div style={{ fontSize: 12.5, color: 'var(--muted)', fontStyle: 'italic' }}>
                No forensic evidence text attached.
              </div>
            )}

            <div className="section-label">Contributing Features</div>
            {normalizedFeatures.length > 0 ? (
              <table className="feat-table">
                <tbody>
                  {normalizedFeatures.map((f, idx) => (
                    <tr key={idx}>
                      <td>{f.name}</td>
                      <td>{f.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="state-box" style={{ padding: 16 }}>
                <p>No feature data (awaiting backend featurization).</p>
              </div>
            )}

            <div className="section-label">Detector Outputs</div>
            {normalizedDetectors.map((d, idx) => (
              <div className="detector-row" key={idx}>
                <div>
                  <div className="d-name">{d.detector}</div>
                  <div style={{ fontSize: 11.5, color: 'var(--muted)' }}>Detector output</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span className="d-score">{d.score.toFixed(2)}</span>
                  {d.triggered ? (
                    <span className="trigger">TRIGGERED</span>
                  ) : (
                    <span style={{ fontSize: 11, color: 'var(--muted)' }}>idle</span>
                  )}
                </div>
              </div>
            ))}

            <div className="section-label" style={{ marginTop: 20 }}>
              Model Score
            </div>
            <div className="conf" style={{ padding: '10px 0' }}>
              <span className="bar" style={{ width: 140, height: 8 }}>
                <span
                  style={{
                    width: `${Math.min(100, Math.max(0, Math.round(modelScoreNum * 100)))}%`,
                  }}
                />
              </span>
              <b style={{ fontSize: 15 }}>{modelScoreNum.toFixed(3)}</b>
            </div>

            <div className="section-label">Analyst Interpretation</div>
            <div
              style={{
                fontSize: 13,
                color: 'var(--ink-2)',
                background: 'var(--accent-dim)',
                border: '1px solid rgba(34,211,238,0.2)',
                borderRadius: 'var(--r-md)',
                padding: 14,
                lineHeight: 1.55,
              }}
            >
              {alert.analystInterpretation ||
                `Identified anomalous unidirectional flow signature matching ${alert.sihCategory}.`}
            </div>

            <div style={{ marginTop: 20, fontSize: 11.5, color: 'var(--faint)' }}>
              Magnitude {magnitudeNum.toFixed(2)} · Dual-layer (NJ-ODE + Rule Engine) live score.
            </div>
          </>
        )}
      </ErrorBoundary>
    </Drawer>
  );
}
