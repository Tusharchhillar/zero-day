import type { StatCardData } from '../types';
import {
  Activity, GitBranch, ShieldAlert, Flame, BrainCircuit, HeartPulse,
  ArrowUpRight, ArrowDownRight, Minus,
} from 'lucide-react';

const ICONS: Record<string, any> = {
  activity: Activity,
  branch: GitBranch,
  alert: ShieldAlert,
  flame: Flame,
  brain: BrainCircuit,
  heart: HeartPulse,
};

const TONES: Record<string, { bg: string; color: string; bar: string }> = {
  critical: { bg: 'var(--sev-critical-dim)', color: 'var(--sev-critical)', bar: 'var(--sev-critical)' },
  high: { bg: 'var(--sev-high-dim)', color: 'var(--sev-high)', bar: 'var(--sev-high)' },
  medium: { bg: 'var(--sev-medium-dim)', color: 'var(--sev-medium)', bar: 'var(--sev-medium)' },
  low: { bg: 'var(--sev-low-dim)', color: 'var(--sev-low)', bar: 'var(--sev-low)' },
  healthy: { bg: 'var(--sev-healthy-dim)', color: 'var(--sev-healthy)', bar: 'var(--sev-healthy)' },
  neutral: { bg: 'var(--surface-3)', color: 'var(--accent)', bar: 'var(--accent)' },
};

export function StatCard({ data }: { data: StatCardData }) {
  const Ic = ICONS[data.icon] ?? Activity;
  const t = TONES[data.tone ?? 'neutral'] ?? TONES.neutral;
  const deltaIcon = data.deltaDirection === 'up' ? <ArrowUpRight size={14} /> : data.deltaDirection === 'down' ? <ArrowDownRight size={14} /> : <Minus size={14} />;
  const deltaColor = data.deltaTone === 'positive' ? 'var(--sev-healthy)' : data.deltaTone === 'negative' ? 'var(--sev-critical)' : data.deltaTone === 'neutral' ? 'var(--muted)' : 'var(--ink-2)';

  return (
    <div className="stat-card">
      <div className="tone-bar" style={{ background: t.bar }} />
      <div className="stat-top">
        <div className="stat-ic" style={{ background: t.bg, color: t.color }}><Ic size={20} /></div>
        {data.delta && (
          <span className="delta-pill" style={{ color: deltaColor }}>{deltaIcon}{data.delta}</span>
        )}
      </div>
      <div className="stat-value">{data.value}</div>
      <div className="stat-label">{data.label}</div>
      <div className="stat-foot">{data.support}</div>
    </div>
  );
}
