import { useState } from 'react';
import { HashRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { ToastProvider } from './components/Toast';
import { DashboardPage } from './pages/DashboardPage';
import { AlertsPage } from './pages/AlertsPage';
import { TrafficPage } from './pages/TrafficPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { SettingsPage } from './pages/SettingsPage';
import { HealthPage } from './pages/HealthPage';
import { ActivityPage } from './pages/ActivityPage';

function ShellLayout() {
  const [collapsed, setCollapsed] = useState(false);
  return (
    <AppShell collapsed={collapsed} setCollapsed={setCollapsed}>
      <Outlet />
    </AppShell>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <HashRouter>
        <Routes>
          <Route element={<ShellLayout />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/traffic" element={<TrafficPage />} />
            <Route path="/threats" element={<ThreatsPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/health" element={<HealthPage />} />
            <Route path="/activity" element={<ActivityPage />} />
          </Route>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </HashRouter>
    </ToastProvider>
  );
}
