import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';
import { CheckCircle2, AlertTriangle, Info, XCircle, X } from 'lucide-react';

type ToastKind = 'success' | 'error' | 'warning' | 'info';
interface Toast { id: number; kind: ToastKind; message: string }

const ToastCtx = createContext<(kind: ToastKind, message: string) => void>(() => {});

export function useToast() {
  return useContext(ToastCtx);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const idRef = useRef(0);

  const push = useCallback((kind: ToastKind, message: string) => {
    const id = ++idRef.current;
    setToasts((t) => [...t, { id, kind, message }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4200);
  }, []);

  const dismiss = (id: number) => setToasts((t) => t.filter((x) => x.id !== id));

  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toast-wrap" role="status" aria-live="polite">
        {toasts.map((t) => {
          const Icon = t.kind === 'success' ? CheckCircle2 : t.kind === 'error' ? XCircle : t.kind === 'warning' ? AlertTriangle : Info;
          const color = t.kind === 'success' ? 'var(--sev-healthy)' : t.kind === 'error' ? 'var(--sev-critical)' : t.kind === 'warning' ? 'var(--sev-medium)' : 'var(--accent)';
          return (
            <div className={`toast ${t.kind}`} key={t.id}>
              <Icon size={18} color={color} style={{ flex: '0 0 auto' }} />
              <span style={{ flex: 1 }}>{t.message}</span>
              <button className="icon-btn" onClick={() => dismiss(t.id)} aria-label="Dismiss" style={{ width: 26, height: 26 }}>
                <X size={14} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastCtx.Provider>
  );
}
