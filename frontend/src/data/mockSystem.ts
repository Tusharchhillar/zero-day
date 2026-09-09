// ---------------------------------------------------------------------------
// Mock SYSTEM HEALTH + session dataset — SIH 26145 (DEMO DATA ONLY)
// ---------------------------------------------------------------------------
import type { HealthComponent, SessionInfo, Notifications, Severity } from '../types';

export const mockSystemHealth: HealthComponent[] = [
  { name: 'Traffic Monitor', status: 'Healthy', detail: '572 flows/s', uptime: '99.98%' },
  { name: 'Detection Engine', status: 'Healthy', detail: '8 detectors, RF model loaded', uptime: '99.96%' },
  { name: 'Alert Pipeline', status: 'Warning', detail: 'Elevated alert volume', uptime: '99.91%' },
  { name: 'Database', status: 'Healthy', detail: 'SQLite • 214 MB', uptime: '100%' },
  { name: 'Dashboard', status: 'Healthy', detail: 'Rendering live', uptime: '99.99%' },
];

export const mockSession: SessionInfo = {
  authenticated: true,
  username: 'SOC Analyst',
  email: 'analyst@sih26145.local',
  role: 'Security Analyst',
  mfaEnabled: true,
  lastLogin: 'Today, 09:14 IST',
  activeSessions: [
    { device: 'Chrome • Windows', location: 'Mumbai, IN', lastActive: 'Now', current: true },
    { device: 'Firefox • macOS', location: 'Bengaluru, IN', lastActive: '2h ago' },
  ],
};

export const mockNotifications: Notifications[] = [
  { id: 'n1', severity: 'CRITICAL', title: 'New critical alert: AL-26xx', time: '2 min ago', read: false },
  { id: 'n2', severity: 'HIGH', title: 'Volumetric DDoS trend +14%', time: '9 min ago', read: false },
  { id: 'n3', severity: 'MEDIUM', title: '3 alerts acknowledged', time: '31 min ago', read: false },
  { id: 'n4', severity: 'LOW', title: 'Nightly report generated', time: '1h ago', read: true },
  { id: 'n5', severity: 'HIGH', title: 'Data exfiltration spike', time: '1h ago', read: true },
];

export const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

// Registration of demo login/2FA credentials — clearly a MOCK, not real auth.
export const DEMO_CREDENTIALS = {
  email: 'soc@demo.sih26145',
  password: 'sih26145',
  otp: '123456',
};

export const dashboardSectionOptions = {
  defaultRange: '24H',
};
