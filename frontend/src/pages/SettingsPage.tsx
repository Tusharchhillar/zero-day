import { ShieldCheck, Monitor, Laptop, Clock, Bell, Palette, User } from 'lucide-react';
import { useToast } from '../components/Toast';

function Section({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <div className="card-head" style={{ borderBottom: 'none', paddingBottom: 0 }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: 8 }}>{icon}{title}</h3>
      </div>
      <div style={{ padding: '4px 20px 20px' }}>{children}</div>
    </div>
  );
}

/** Presentational toggle — toggling state is demo-only and lives client-side. */
function Toggle({ label, enabled = false }: { label: string; enabled?: boolean }) {
  return (
    <button
      className={enabled ? 'btn btn-primary btn-sm' : 'btn btn-sm'}
      style={{ justifyContent: 'space-between', width: 220 }}
      onClick={() => undefined}
    >
      <span>{label}</span><span>{enabled ? 'On' : 'Off'}</span>
    </button>
  );
}

export function SettingsPage() {
  const toast = useToast();
  const saved = (m: string) => toast('success', `${m} saved.`);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <div className="sub">Profile, security and workspace preferences.</div>
        </div>
        <div className="page-head-actions" />
      </div>

      <Section icon={<User size={16} />} title="Profile">
        <div className="grid-2" style={{ gap: 16, alignItems: 'end' }}>
          <div className="field"><label>Display name</label><input className="input" defaultValue="SOC Analyst" /></div>
          <div className="field"><label>Email</label><input className="input" defaultValue="analyst@sih26145.local" /></div>
          <div className="field"><label>Role</label><input className="input" defaultValue="Security Analyst" /></div>
          <div style={{ alignSelf: 'end' }}><button className="btn" onClick={() => saved('Profile')}>Save changes</button></div>
        </div>
      </Section>

      <Section icon={<ShieldCheck size={16} />} title="Security">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="health-item">
            <div className="h-ic" style={{ background: 'var(--sev-healthy-dim)', color: 'var(--sev-healthy)' }}><ShieldCheck size={16} /></div>
            <div style={{ flex: 1 }}>
              <div className="h-name">Two-factor authentication</div>
              <div className="h-detail">Enabled</div>
            </div>
            <span className="status-pill health-Healthy">Enabled</span>
          </div>
          <div className="health-item">
            <div className="h-ic" style={{ background: 'var(--sev-healthy-dim)', color: 'var(--sev-healthy)' }}><Monitor size={16} /></div>
            <div style={{ flex: 1 }}>
              <div className="h-name">Session status</div>
              <div className="h-detail">Active on this device</div>
            </div>
            <span className="status-pill health-Healthy">Active</span>
          </div>
          <div className="health-item">
            <div className="h-ic" style={{ background: 'var(--info-dim)', color: 'var(--info)' }}><Clock size={16} /></div>
            <div style={{ flex: 1 }}>
              <div className="h-name">Last login</div>
              <div className="h-detail">Current session</div>
            </div>
          </div>
          <div className="health-item">
            <div className="h-ic" style={{ background: 'var(--info-dim)', color: 'var(--info)' }}><Laptop size={16} /></div>
            <div style={{ flex: 1 }}>
              <div className="h-name">Active sessions</div>
              <div className="h-detail">1 active session</div>
            </div>
            <button className="btn btn-sm btn-danger">Revoke</button>
          </div>
        </div>
      </Section>

      <Section icon={<Bell size={16} />} title="Notifications">
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <Toggle label="Critical alerts" enabled />
          <Toggle label="High alerts" enabled />
          <Toggle label="Daily digest" enabled />
          <Toggle label="Weekly report" />
        </div>
      </Section>

      <Section icon={<Palette size={16} />} title="Dashboard Preferences">
        <div className="grid-2">
          <div className="field"><label>Default time range</label><select className="select"><option>24H</option><option>7D</option><option>30D</option></select></div>
          <div className="field"><label>Default view</label><select className="select"><option>Overview</option><option>Alerts only</option><option>Traffic only</option></select></div>
        </div>
      </Section>

      <Section icon={<Palette size={16} />} title="Appearance">
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <Toggle label="Dark theme" enabled />
          <Toggle label="Reduced motion" />
        </div>
      </Section>
    </>
  );
}
