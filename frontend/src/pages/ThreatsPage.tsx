import { useEffect, useState } from 'react';
import { threatService } from '../services';
import type { ThreatActivityItem } from '../types';
import { SeverityBadge } from '../components/Badge';
import { Modal } from '../components/Drawer';
import { DemoTag } from '../components/DemoTag';
import { CATEGORY_COLORS, SEV_COLORS, fmtDelta, CATEGORY_KEYS } from '../lib/theme';

export function ThreatsPage() {
  const [items, setItems] = useState<ThreatActivityItem[]>([]);
  const [selected, setSelected] = useState<ThreatActivityItem | null>(null);

  useEffect(() => {
    threatService.activity().then(setItems);
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Threats</h1>
          <div className="sub">The six SIH 26145 threat categories detected from unidirectional traffic.</div>
        </div>
        <div className="page-head-actions"><DemoTag /><span className="hint" style={{ color: 'var(--faint)', fontSize: 12 }}>All counts are demo values</span></div>
      </div>

      {items.length === 0 ? (
        <div className="stat-grid">{Array.from({ length: 6 }).map((_, i) => <div key={i} className="skeleton skel-card" />)}</div>
      ) : (
        <div className="grid-2">
          {items.map((t) => (
            <div className="threat-card" key={t.category} onClick={() => setSelected(t)} role="button" tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && setSelected(t)}>
              <div className="tc-top">
                <div className="tc-name" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 10, height: 10, borderRadius: 4, background: CATEGORY_COLORS[t.category] }} />
                  {t.category}<SeverityBadge severity={t.severity} />
                </div>
                <div className="tc-count" style={{ color: SEV_COLORS[t.severity] }}>{t.count}</div>
                <div className="tc-desc">{t.description}</div>
                <div className="threat-meta">
                  <span>Confidence <b>{Math.round(t.confidence * 100)}%</b></span>
                  <span>Trend <b style={{ color: t.trend >= 0 ? 'var(--sev-critical)' : 'var(--sev-healthy)' }}>{fmtDelta(t.trend)}</b></span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal open={!!selected} onClose={() => setSelected(null)} title={selected?.category ?? ''} width={640}>
        {selected && (
          <>
            <div style={{ display: 'flex', gap: 8, marginBottom: 16, alignItems: 'center' }}>
              <SeverityBadge severity={selected.severity} />
              <span className="hint" style={{ color: 'var(--muted)', fontSize: 12.5 }}>{selected.count} detections · confidence {Math.round(selected.confidence * 100)}% · trend {fmtDelta(selected.trend)}</span>
            </div>
            <p style={{ fontSize: 13.5, color: 'var(--ink-2)', margin: '0 0 16px' }}>{selected.description}</p>
            <div className="section-label" style={{ marginTop: 0 }}>Observable Indicators</div>
            <ul className="evidence-list">
              {selected.indicators.map((ind) => <li key={ind}>{ind}</li>)}
            </ul>
            <div className="section-label">Detection Trend</div>
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 90 }}>
              {selected.spark.map((v, i) => (
                <div key={i} style={{ flex: 1, height: `${(v / Math.max(...selected.spark)) * 100}%`, background: SEV_COLORS[selected.severity], opacity: 0.5 + (i / selected.spark.length) * 0.5, borderRadius: '3px 3px 0 0' }} />
              ))}
            </div>
            <div style={{ marginTop: 16, fontSize: 11.5, color: 'var(--faint)' }}>
              Category key: <span className="mono">{CATEGORY_KEYS[selected.category]}</span> · Detection values are DEMO DATA.
            </div>
          </>
        )}
      </Modal>
    </>
  );
}
