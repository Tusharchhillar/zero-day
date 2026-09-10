import { useEffect, useMemo, useState, useRef, useCallback } from 'react';
import { Download, ChevronLeft, ChevronRight, RefreshCw, Trash2, Pause, Play } from 'lucide-react';
import { alertService } from '../services';
import type { Alert, Severity } from '../types';
import { SeverityBadge, StatusPill } from '../components/Badge';
import { AlertDetails } from '../components/AlertDetails';
import { EmptyState, LoadingState, ErrorState } from '../components/States';
import { relTime, CATEGORY_ORDER } from '../lib/theme';
import { useToast } from '../components/Toast';

const PAGE_SIZE = 10;
const TIME_FILTERS = ['All time', 'Last 24h', 'Last 7d', 'Last 30d'];
const PROTOCOLS = ['All', 'TCP', 'UDP', 'TLS', 'DNS', 'ICMP'];
const CONFIDENCE = ['All', '≥ 90%', '≥ 80%', '≥ 70%'];

type SortKey = 'timestamp' | 'severity' | 'confidence';
const SEV_RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

export function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [threat, setThreat] = useState('All');
  const [sev, setSev] = useState('All');
  const [time, setTime] = useState('All time');
  const [proto, setProto] = useState('All');
  const [conf, setConf] = useState('All');
  const [sortKey, setSortKey] = useState<SortKey>('timestamp');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [clearing, setClearing] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const toast = useToast();
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchAlerts = useCallback(async () => {
    try {
      setRefreshing(true);
      const a = await alertService.list();
      setAlerts(a);
      setError('');
      setLastRefresh(new Date());
    } catch {
      setError('Failed to load alerts.');
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  // Auto-refresh: poll every 5 seconds
  useEffect(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    if (autoRefresh) {
      intervalRef.current = setInterval(fetchAlerts, 5000);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [autoRefresh, fetchAlerts]);

  const handleClearAll = async () => {
    if (!confirm('Clear all alerts? This cannot be undone.')) return;
    setClearing(true);
    try {
      const ok = await alertService.clearAll();
      if (ok) {
        setAlerts([]);
        setSelected(null);
        setPage(0);
        toast('success', 'All alerts cleared.');
      } else {
        toast('error', 'Failed to clear alerts.');
      }
    } catch {
      toast('error', 'Failed to clear alerts.');
    } finally {
      setClearing(false);
    }
  };

  const filtered = useMemo(() => {
    if (!alerts) return [];
    const cutoff = time === 'Last 24h' ? 24 : time === 'Last 7d' ? 168 : time === 'Last 30d' ? 720 : 0;
    let rows = alerts;
    if (search) {
      const q = search.toLowerCase();
      rows = rows.filter((a) => a.id.toLowerCase().includes(q) || a.source.ip.includes(q) || a.destination.ip.includes(q) || a.threatClass.toLowerCase().includes(q));
    }
    if (threat !== 'All') rows = rows.filter((a) => a.sihCategory === threat);
    if (sev !== 'All') rows = rows.filter((a) => a.severity === sev);
    if (proto !== 'All') rows = rows.filter((a) => a.protocol === proto);
    if (conf !== 'All') {
      const min = parseInt(conf.replace(/\D/g, ''), 10) / 100;
      rows = rows.filter((a) => a.confidence >= min);
    }
    if (cutoff) rows = rows.filter((a) => Date.now() - new Date(a.timestamp).getTime() <= cutoff * 3600000);
    rows = [...rows].sort((a, b) => {
      if (sortKey === 'timestamp') return sortDir === 'asc' ? new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime() : new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      if (sortKey === 'severity') return sortDir === 'asc' ? SEV_RANK[a.severity] - SEV_RANK[b.severity] : SEV_RANK[b.severity] - SEV_RANK[a.severity];
      return sortDir === 'asc' ? a.confidence - b.confidence : b.confidence - a.confidence;
    });
    return rows;
  }, [alerts, search, threat, sev, time, proto, conf, sortKey, sortDir]);

  // Clamp current page to the valid range after filtering changes.
  useEffect(() => {
    const max = Math.max(0, Math.floor((filtered.length - 1) / PAGE_SIZE));
    setPage((p) => Math.min(p, max));
  }, [filtered.length]);

  const pageRows = filtered.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));

  const toggleSort = (k: SortKey) => {
    if (sortKey === k) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(k); setSortDir('desc'); }
  };

  const toggleSortIcon = (k: SortKey) => k === sortKey ? (sortDir === 'asc' ? ' ▲' : ' ▼') : '';

  const exportCsv = () => {
    const header = ['ID', 'Category', 'Severity', 'Source', 'Destination', 'Protocol', 'Confidence', 'Detected At', 'Status'];
    const rows = filtered.map((a) => [a.id, a.sihCategory, a.severity, `${a.source.ip}:${a.source.port}`, `${a.destination.ip}:${a.destination.port}`, a.protocol, a.confidence.toFixed(3), a.timestamp, a.status].map((x) => `"${x}"`).join(','));
    const blob = new Blob([[header.join(','), ...rows].join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.download = `sih26145_alerts_${Date.now()}.csv`; link.click();
    URL.revokeObjectURL(url);
    toast('success', `Exported ${filtered.length} alerts to CSV.`);
  };

  if (error) return <ErrorState message={error} onRetry={() => window.location.reload()} />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Alerts</h1>
          <div className="sub">Detected threats across the monitored unidirectional traffic.</div>
        </div>
        <div className="page-head-actions">
          {lastRefresh && (
            <span style={{ fontSize: 11, color: 'var(--muted)' }}>
              {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button
            className="btn"
            onClick={fetchAlerts}
            disabled={refreshing}
            title="Refresh alerts"
          >
            <RefreshCw size={15} className={refreshing ? 'spin' : ''} /> Refresh
          </button>
          <button
            className={`btn ${autoRefresh ? 'btn-active' : ''}`}
            onClick={() => setAutoRefresh(!autoRefresh)}
            title={autoRefresh ? 'Stop auto-refresh (5s)' : 'Start auto-refresh (5s)'}
          >
            {autoRefresh ? <Pause size={15} /> : <Play size={15} />}
            {autoRefresh ? 'Auto' : 'Auto'}
          </button>
          <button className="btn btn-danger" onClick={handleClearAll} disabled={clearing || !alerts?.length}>
            <Trash2 size={15} /> Clear All
          </button>
          <button className="btn" onClick={exportCsv}><Download size={15} /> Export</button>
        </div>
      </div>

      <div className="card">
        <div className="card-head" style={{ flexWrap: 'wrap', gap: 12 }}>
          <div className="search-box" style={{ width: 260 }}>
            <span>⌕</span>
            <input placeholder="Search ID, IP, class…" value={search} onChange={(e) => { setSearch(e.target.value); setPage(0); }} aria-label="Search alerts" />
          </div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
            <select className="select" value={threat} onChange={(e) => { setThreat(e.target.value); setPage(0); }} aria-label="Threat filter">
              <option>All</option>
              {CATEGORY_ORDER.map((c) => <option key={c}>{c}</option>)}
            </select>
            <select className="select" value={sev} onChange={(e) => { setSev(e.target.value); setPage(0); }} aria-label="Severity filter">
              <option>All</option>
              <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
            </select>
            <select className="select" value={time} onChange={(e) => { setTime(e.target.value); setPage(0); }} aria-label="Time filter">
              {TIME_FILTERS.map((t) => <option key={t}>{t}</option>)}
            </select>
            <select className="select" value={proto} onChange={(e) => { setProto(e.target.value); setPage(0); }} aria-label="Protocol filter">
              {PROTOCOLS.map((p) => <option key={p}>{p}</option>)}
            </select>
            <select className="select" value={conf} onChange={(e) => { setConf(e.target.value); setPage(0); }} aria-label="Confidence filter">
              {CONFIDENCE.map((c) => <option key={c}>{c}</option>)}
            </select>
          </div>
          <span style={{ fontSize: 12.5, color: 'var(--muted)', marginLeft: 'auto' }}><b style={{ color: 'var(--ink)', fontFamily: 'var(--font-mono)' }}>{filtered.length}</b> alerts</span>
        </div>

        {!alerts ? (
          <LoadingState rows={4} />
        ) : pageRows.length === 0 ? (
          <EmptyState title="No alerts match" message="Try adjusting the filters or search query." />
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Threat</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th style={{ cursor: 'pointer' }} onClick={() => toggleSort('confidence')}>Confidence{toggleSortIcon('confidence')}</th>
                  <th style={{ cursor: 'pointer' }} onClick={() => toggleSort('timestamp')}>Detected At{toggleSortIcon('timestamp')}</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {pageRows.map((a) => (
                  <tr key={a.id} onClick={() => setSelected(a.id)}>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td style={{ fontWeight: 600, color: 'var(--ink)', maxWidth: 200, whiteSpace: 'normal' }}>{a.sihCategory}</td>
                    <td><span className="ip">{a.source.ip}</span><span className="ip-arrow">:</span>{a.source.port}</td>
                    <td><span className="ip">{a.destination.ip}</span><span className="ip-arrow">:</span>{a.destination.port}</td>
                    <td>{a.protocol}</td>
                    <td>
                      <div className="conf">
                        <span className="bar"><span style={{ width: `${a.confidence * 100}%` }} /></span>
                        {Math.round(a.confidence * 100)}%
                      </div>
                    </td>
                    <td style={{ color: 'var(--muted)' }}>{relTime(a.timestamp)}</td>
                    <td><StatusPill status={a.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="pagination">
          <span>Showing {pageRows.length ? page * PAGE_SIZE + 1 : 0}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of {filtered.length}</span>
          <div className="page-arrows">
            <button className="btn btn-sm" disabled={page === 0} onClick={() => setPage(page - 1)} aria-label="Previous page"><ChevronLeft size={16} /></button>
            <span style={{ alignSelf: 'center', fontSize: 12.5 }}>Page {page + 1} / {pages}</span>
            <button className="btn btn-sm" disabled={page >= pages - 1} onClick={() => setPage(page + 1)} aria-label="Next page"><ChevronRight size={16} /></button>
          </div>
        </div>
      </div>

      <AlertDetails
        alertId={selected}
        onClose={() => setSelected(null)}
        onStatusChange={() => {
          alertService.list().then(setAlerts);
        }}
      />
    </>
  );
}
