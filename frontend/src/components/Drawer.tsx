import { useEffect, type ReactNode } from 'react';
import { X } from 'lucide-react';

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  headRight?: ReactNode;
}

export function Drawer({ open, onClose, title, subtitle, children, footer, headRight }: DrawerProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <div className="drawer" role="dialog" aria-modal="true" aria-label={typeof title === 'string' ? title : 'Detail'}>
        <div className="drawer-head">
          <div>
            {title && <h2 style={{ fontSize: 18, marginBottom: 3 }}>{title}</h2>}
            {subtitle && <div style={{ color: 'var(--muted)', fontSize: 13 }}>{subtitle}</div>}
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {headRight}
            <button className="icon-btn" onClick={onClose} aria-label="Close">
              <X size={18} />
            </button>
          </div>
        </div>
        <div className="drawer-body">{children}</div>
        {footer && <div className="drawer-foot">{footer}</div>}
      </div>
    </>
  );
}

export function Modal({ open, onClose, title, children, width = 480 }: DrawerProps & { width?: number }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <div
        style={{
          position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
          width: width, maxWidth: '94vw', maxHeight: '86vh', overflow: 'auto',
          background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--r-lg)',
          boxShadow: 'var(--shadow-lg)', zIndex: 100, padding: 'var(--space-6)',
        }}
        role="dialog"
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <h2 style={{ fontSize: 17 }}>{title}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </div>
        {children}
      </div>
    </>
  );
}
