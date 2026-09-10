import { createClient, SupabaseClient } from '@supabase/supabase-js';
import type { Alert } from '../types';

// Read configuration from env or runtime defaults
const SUPABASE_URL: string =
  (import.meta as any).env?.VITE_SUPABASE_URL ||
  (window as any).__SUPABASE_URL__ ||
  '';

const SUPABASE_KEY: string =
  (import.meta as any).env?.VITE_SUPABASE_ANON_KEY ||
  (import.meta as any).env?.VITE_SUPABASE_KEY ||
  (window as any).__SUPABASE_KEY__ ||
  '';

export const isSupabaseConfigured = (): boolean => {
  return Boolean(SUPABASE_URL && SUPABASE_KEY);
};

let clientInstance: SupabaseClient | null = null;

export const getSupabaseClient = (): SupabaseClient | null => {
  if (!isSupabaseConfigured()) return null;
  if (!clientInstance) {
    clientInstance = createClient(SUPABASE_URL, SUPABASE_KEY, {
      realtime: {
        params: {
          eventsPerSecond: 10,
        },
      },
    });
  }
  return clientInstance;
};

// Map Supabase DB row to React Alert Interface
export function mapSupabaseRowToAlert(row: any): Alert {
  return {
    id: row.alert_id || `alt-${Math.random().toString(36).substring(2, 8)}`,
    timestamp: row.timestamp || new Date().toISOString(),
    flowId: row.flow_id || 'flow-000',
    threatClass: row.threat_class || 'botnet_c2_beacon',
    sihCategory: row.sih_category || 'Botnet C2 Beaconing',
    severity: (row.severity as Alert['severity']) || 'HIGH',
    confidence: typeof row.confidence === 'number' ? row.confidence : 0.90,
    status: (row.status as Alert['status']) || 'New',
    source: {
      ip: row.src_ip || '0.0.0.0',
      port: row.src_port || 443,
    },
    destination: {
      ip: row.dst_ip || '0.0.0.0',
      port: row.dst_port || 443,
    },
    protocol: row.protocol || 'TCP',
    evidence: Array.isArray(row.evidence) ? row.evidence : [],
    summary: row.summary || 'Supabase event',
    detectionMethod: row.detection_method || 'Unknown',
    contributingFeatures: Array.isArray(row.contributing_features) ? row.contributing_features : [],
    detectorOutputs: Array.isArray(row.detector_outputs) ? row.detector_outputs : [],
    analystInterpretation: row.analyst_interpretation || '',
    magnitude: row.magnitude || 0,
    detectionLatencyMs: row.detection_latency_ms || 0,
  };
}

/**
 * Fetch alerts directly from Supabase
 */
export async function fetchSupabaseAlerts(limit = 100): Promise<Alert[]> {
  const client = getSupabaseClient();
  if (!client) return [];

  try {
    const { data, error } = await client
      .from('alerts')
      .select('*')
      .order('timestamp', { ascending: false })
      .limit(limit);

    if (error) {
      console.error('[Supabase] Error fetching alerts:', error);
      return [];
    }

    return (data || []).map(mapSupabaseRowToAlert);
  } catch (err) {
    console.error('[Supabase] Fetch error:', err);
    return [];
  }
}

/**
 * Update Alert Status directly in Supabase
 */
export async function updateSupabaseAlertStatus(alertId: string, status: Alert['status']): Promise<boolean> {
  const client = getSupabaseClient();
  if (!client) return false;

  try {
    const { error } = await client
      .from('alerts')
      .update({ status })
      .eq('alert_id', alertId);

    if (error) {
      console.error('[Supabase] Error updating alert status:', error);
      return false;
    }
    return true;
  } catch (err) {
    console.error('[Supabase] Status update error:', err);
    return false;
  }
}

/**
 * Insert a single alert directly into Supabase
 */
export async function insertSupabaseAlert(rawAlert: any): Promise<boolean> {
  const client = getSupabaseClient();
  if (!client) return false;

  try {
    const { error } = await client
      .from('alerts')
      .insert([rawAlert]);

    if (error) {
      console.error('[Supabase] Error inserting alert:', error);
      return false;
    }
    return true;
  } catch (err) {
    console.error('[Supabase] Insert error:', err);
    return false;
  }
}

/**
 * Subscribe to Live Realtime Alert Inserts directly from Supabase
 */
export function subscribeToSupabaseRealtime(onAlertReceived: (alert: Alert) => void) {
  const client = getSupabaseClient();
  if (!client) return () => {};

  const channel = client
    .channel('public:alerts')
    .on(
      'postgres_changes',
      { event: 'INSERT', schema: 'public', table: 'alerts' },
      (payload) => {
        if (payload.new) {
          onAlertReceived(mapSupabaseRowToAlert(payload.new));
        }
      }
    )
    .subscribe();

  return () => {
    client.removeChannel(channel);
  };
}

/**
 * Delete all alerts from Supabase
 */
export async function clearSupabaseAlerts(): Promise<boolean> {
  const client = getSupabaseClient();

  if (!client) {
    console.error('[Supabase] ❌ Client is NOT configured');
    return false;
  }

  console.log('[Supabase] 🗑️ Starting delete...');

  const { data, error } = await client
    .from('alerts')
    .delete()
    .not('alert_id', 'is', null)
    .select('alert_id');

  console.log('[Supabase] DELETE RESPONSE:', {
    data,
    error,
  });

  if (error) {
    console.error('[Supabase] ❌ DELETE FAILED');
    console.error('Message:', error.message);
    console.error('Code:', error.code);
    console.error('Details:', error.details);
    console.error('Hint:', error.hint);
    return false;
  }

  console.log(
    `[Supabase] ✅ Deleted ${data?.length ?? 0} alerts`
  );
  return true;
}
