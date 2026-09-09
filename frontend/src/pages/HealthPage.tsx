import { SystemHealth } from '../components/SystemHealth';
import { DemoTag } from '../components/DemoTag';

export function HealthPage() {
  return (
    <>
      <div className="page-head">
        <div>
          <h1>System Health</h1>
          <div className="sub">Status of each pipeline component.</div>
        </div>
        <div className="page-head-actions">
          <DemoTag />
          <div className="health-pill"><span className="pulse" />Healthy</div>
        </div>
      </div>
      <div className="card card-pad" style={{ maxWidth: 760 }}>
        <SystemHealth />
      </div>
    </>
  );
}