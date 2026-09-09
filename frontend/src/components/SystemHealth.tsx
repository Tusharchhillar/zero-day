import { useEffect, useState } from 'react';
import { Server, Cpu, Workflow, Database, LayoutDashboard } from 'lucide-react';
import { systemService } from '../services';
import type { HealthComponent } from '../types';
import { HealthBadge } from './Badge';

const ICONS: Record<string, any> = {
  'Traffic Monitor': Workflow,
  'Detection Engine': Cpu,
  'Alert Pipeline': Server,
  'Database': Database,
  'Dashboard': LayoutDashboard,
};

const TONES: Record<string, { bg: string; color: string }> = {
  Healthy: { bg: 'var(--sev-healthy-dim)', color: 'var(--sev-healthy)' },
  Warning: { bg: 'var(--sev-medium-dim)', color: 'var(--sev-medium)' },
  Offline: { bg: 'var(--sev-critical-dim)', color: 'var(--sev-critical)' },
};

export function SystemHealth({ compact = false }: { compact?: boolean }) {
  const [items, setItems] = useState<HealthComponent[]>([]);

  useEffect(() => {
    systemService.health().then(setItems);
  }, []);

  if (items.length === 0) return <div className="skeleton skel-card" />;

  if (compact) {
    const overall = items.some((i) => i.status === 'Offline') ? 'Offline' : items.some((i) => i.status === 'Warning') ? 'Warning' : 'Healthy';
    return <HealthBadge status={overall} />;
  }

  return (
    <div className="health-list">
      {items.map((h) => {
        const Ic = ICONS[h.name] ?? Server;
        const t = TONES[h.status] ?? { bg: 'var(--surface-2)', color: 'var(--muted)' };
        return (
          <div className="health-item" key={h.name}>
            <div className="h-ic" style={{ background: t.bg, color: t.color }}><Ic size={16} /></div>
            <div className="h-body" style={{ flex: 1, minWidth: 0 }}>
              <div className="h-name">{h.name}</div>
              <div className="h-detail">{h.detail} · <span className="mono">{h.uptime}</span></div>
            </div>
            <HealthBadge status={h.status} />
          </div>
        );
      })}
    </div>
  );
}
