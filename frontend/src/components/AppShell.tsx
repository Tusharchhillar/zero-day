import { useEffect, useState, useRef, type ReactNode } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Bell, Siren, Activity, Radar, BarChart3, Settings,
  HeartPulse, ListChecks, PanelLeftClose, PanelLeftOpen, ShieldCheck,
} from 'lucide-react';
import { systemService, alertService } from '../services';
import type { Notifications } from '../types';
import { SeverityBadge } from './Badge';

interface NavEntry { to: string; label: string; icon: ReactNode; badgeKey?: 'alerts' }

const NAV_GROUPS: { label: string; items: NavEntry[] }[] = [
  {
    label: 'Monitoring',
    items: [
      { to: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
      { to: '/alerts', label: 'Alerts', icon: <Siren size={18} />, badgeKey: 'alerts' },
      { to: '/traffic', label: 'Traffic', icon: <Activity size={18} /> },
      { to: '/threats', label: 'Threats', icon: <Radar size={18} /> },
      { to: '/analytics', label: 'Analytics', icon: <BarChart3 size={18} /> },
    ],
  },
  {
    label: 'System',
    items: [
      { to: '/health', label: 'System Health', icon: <HeartPulse size={18} /> },
      { to: '/activity', label: 'Activity Log', icon: <ListChecks size={18} /> },
    ],
  },
];

function SidebarContent({
  collapsed,
  alertCount,
}: {
  collapsed: boolean;
  alertCount: number;
}) {
  return (
    <>
      <div className="sidebar-head">
        <div
          className="brand-mark"
          style={{ width: 36, height: 36, fontSize: 13, borderRadius: 10, flexShrink: 0 }}
        >
          TW
        </div>
        {!collapsed && (
          <div className="brand-text">
            <div className="b1">Threatwave</div>
            <div className="b2">Cyber Threat Intel</div>
          </div>
        )}
      </div>

      <nav className="sidebar-nav" aria-label="Main navigation">
        {NAV_GROUPS.map((g) => (
          <div key={g.label} style={{ marginBottom: 8 }}>
            {!collapsed && <div className="nav-group-label">{g.label}</div>}
            {g.items.map((it) => {
              const count = it.badgeKey === 'alerts' && alertCount > 0 ? alertCount : null;
              return (
                <NavLink
                  key={it.to}
                  to={it.to}
                  className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                  title={collapsed ? `${it.label}${count ? ` (${count})` : ''}` : undefined}
                >
                  <span className="nav-ic">{it.icon}</span>
                  {!collapsed && <span>{it.label}</span>}
                  {!collapsed && count && <span className="nav-count">{count}</span>}
                  {collapsed && count && (
                    <span
                      style={{
                        position: 'absolute',
                        top: 6,
                        right: 8,
                        width: 7,
                        height: 7,
                        borderRadius: '50%',
                        background: 'var(--sev-critical)',
                        boxShadow: '0 0 6px rgba(244, 63, 94, 0.5)',
                      }}
                    />
                  )}
                </NavLink>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="sidebar-foot">
        <NavLink
          to="/settings"
          className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          title={collapsed ? 'Settings' : undefined}
        >
          <span className="nav-ic"><Settings size={18} /></span>
          {!collapsed && <span>Settings</span>}
        </NavLink>
      </div>
    </>
  );
}

function NotificationPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [items, setItems] = useState<Notifications[]>([]);
  const popoverRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open && items.length === 0) {
      systemService.notifications().then(setItems);
    }
  }, [open, items.length]);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (popoverRef.current && !popoverRef.current.contains(e.target as Node)) {
        onClose();
      }
    }
    if (open) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div ref={popoverRef} className="popover" style={{ width: 360, right: 0 }}>
      <div
        style={{
          padding: '12px 16px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          background: 'var(--surface-2)',
        }}
      >
        <b style={{ fontSize: 13, color: 'var(--ink)' }}>SOC Alerts & Notifications</b>
        <span
          style={{
            fontSize: 10,
            padding: '2px 7px',
            borderRadius: 'var(--r-full)',
            background: 'var(--accent-dim)',
            color: 'var(--accent)',
            fontWeight: 600,
            letterSpacing: '0.04em',
          }}
        >
          LIVE FEED
        </span>
      </div>
      <div style={{ maxHeight: 360, overflowY: 'auto' }}>
        {items.length === 0 && (
          <div className="state-box" style={{ padding: 24, textAlign: 'center', color: 'var(--muted)' }}>
            <p>Loading notifications…</p>
          </div>
        )}
        {items.map((n) => (
          <div
            key={n.id}
            style={{
              display: 'flex',
              gap: 12,
              padding: '11px 16px',
              borderBottom: '1px solid var(--border-soft)',
              cursor: 'pointer',
              background: n.read ? 'transparent' : 'rgba(0, 200, 255, 0.03)',
              alignItems: 'flex-start',
              transition: 'background 180ms ease',
            }}
            onClick={onClose}
            onMouseEnter={(e) => {
              if (n.read) (e.currentTarget as HTMLElement).style.background = 'rgba(0, 200, 255, 0.04)';
            }}
            onMouseLeave={(e) => {
              if (n.read) (e.currentTarget as HTMLElement).style.background = 'transparent';
            }}
          >
            <SeverityBadge severity={n.severity} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 12.5, color: 'var(--ink)', fontWeight: 500, lineHeight: 1.4 }}>
                {n.title}
              </div>
              <div style={{ fontSize: 11, color: 'var(--faint)', marginTop: 2 }}>{n.time}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function AppShell({
  children,
  collapsed,
  setCollapsed,
}: {
  children: ReactNode;
  collapsed: boolean;
  setCollapsed: (c: boolean | ((prev: boolean) => boolean)) => void;
}) {
  const [notifOpen, setNotifOpen] = useState(false);
  const [isLive, setIsLive] = useState<boolean | null>(null);
  const [alertCount, setAlertCount] = useState(0);
  const location = useLocation();

  const titleMap: Record<string, { title: string; subtitle: string }> = {
    '/dashboard': { title: 'SOC Dashboard', subtitle: 'Unidirectional IP Traffic Threat Telemetry' },
    '/alerts': { title: 'Threat Alerts', subtitle: 'Dual-Layer Rule & NJ-ODE Anomaly Detections' },
    '/traffic': { title: 'Network Traffic', subtitle: 'Live Packet Ingestion & Channel Attribution' },
    '/threats': { title: 'Threat Intelligence', subtitle: 'DDoS, Beacons, DGA, Exfiltration & C2 Taxonomy' },
    '/analytics': { title: 'Analytics & Reports', subtitle: 'Throughput Metrics, Model Accuracy & Trends' },
    '/health': { title: 'System Health', subtitle: 'FastAPI, NJ-ODE PyTorch Model & Worker Latency' },
    '/activity': { title: 'Audit & Activity Log', subtitle: 'Engine Replays & Event Forensics' },
    '/settings': { title: 'System Settings', subtitle: 'Detection Thresholds & Rule Engine Configuration' },
  };

  const currentRoute = titleMap[location.pathname] || {
    title: 'Threatwave',
    subtitle: 'Cyber Threat Intelligence Platform',
  };

  useEffect(() => {
    let mounted = true;
    const checkHealth = async () => {
      try {
        const host = window.location.hostname || 'localhost';
        const res = await fetch(`http://${host}:8000/api/health`);
        if (mounted) setIsLive(res.ok);
      } catch {
        if (mounted) setIsLive(false);
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 6000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    alertService.list().then((res) => {
      if (Array.isArray(res)) {
        setAlertCount(res.length);
      }
    }).catch(() => {});
  }, [location.pathname]);

  return (
    <div className={`app-root${collapsed ? ' sidebar-collapsed' : ''}`}>
      <aside className="sidebar">
        <SidebarContent collapsed={collapsed} alertCount={alertCount} />
      </aside>

      <div className="main-viewport">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="btn-icon"
              onClick={() => setCollapsed((v) => !v)}
              aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >
              {collapsed ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}
            </button>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <h1 className="page-title">{currentRoute.title}</h1>
              <span style={{ fontSize: 11, color: 'var(--muted)', letterSpacing: '0.02em' }}>
                {currentRoute.subtitle}
              </span>
            </div>
          </div>

          <div className="topbar-right">
            <div
              className={`live-status-pill ${isLive === false ? 'offline' : ''}`}
              title={isLive ? 'Threatwave Engine Active' : 'Connecting to Threatwave Backend...'}
            >
              <span className="live-dot" />
              <span>{isLive ? 'ENGINE ACTIVE (8000)' : isLive === false ? 'ENGINE OFFLINE' : 'CHECKING...'}</span>
            </div>

            <div style={{ position: 'relative' }}>
              <button
                className="btn-icon"
                onClick={() => setNotifOpen((v) => !v)}
                aria-label="Toggle notifications"
                title="Notifications"
              >
                <Bell size={17} />
                {alertCount > 0 && (
                  <span
                    style={{
                      position: 'absolute',
                      top: 7,
                      right: 7,
                      width: 6,
                      height: 6,
                      borderRadius: '50%',
                      background: 'var(--sev-critical)',
                      boxShadow: '0 0 6px rgba(244, 63, 94, 0.5)',
                    }}
                  />
                )}
              </button>
              <NotificationPanel open={notifOpen} onClose={() => setNotifOpen(false)} />
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '5px 12px',
                borderRadius: 'var(--r-sm)',
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                fontSize: 12,
                color: 'var(--ink-2)',
                fontWeight: 500,
                backdropFilter: 'blur(8px)',
              }}
            >
              <ShieldCheck size={14} color="var(--accent)" />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>v1.0.0</span>
            </div>
          </div>
        </header>

        <main className="content-pane">{children}</main>
      </div>
    </div>
  );
}
