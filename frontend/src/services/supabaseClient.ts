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
  if (!row) {
    return {
      id: `alt-${Math.random().toString(36).substring(2, 8)}`,
      timestamp: new Date().toISOString(),
      flowId: 'flow-000',
      threatClass: 'botnet_c2_beacon',
      sihCategory: 'Botnet C2 Beaconing',
      severity: 'HIGH',
      confidence: 0.90,
      status: 'New',
      source: { ip: '0.0.0.0', port: 443 },
      destination: { ip: '0.0.0.0', port: 443 },
      protocol: 'TCP',
      evidence: [],
      summary: 'Alert detected',
      detectionMethod: 'Rules + ML hybrid',
      contributingFeatures: [],
      detectorOutputs: [],
      analystInterpretation: 'Alert detected by ZERO-DAY engine.',
      magnitude: 0.90,
      detectionLatencyMs: 0,
    };
  }

  let rawEvidence = row.evidence ?? row.evidence_json ?? [];
  if (typeof rawEvidence === 'string') {
    try {
      rawEvidence = JSON.parse(rawEvidence);
    } catch {
      rawEvidence = [rawEvidence];
    }
  }
  if (!Array.isArray(rawEvidence)) {
    rawEvidence = [rawEvidence];
  }

  const evidence: string[] = rawEvidence
    .map((e: any) => {
      if (e === null || e === undefined) return '';
      if (typeof e === 'string') return e;
      if (typeof e === 'object') {
        if (e.reason) return String(e.reason);
        if (e.feature) return `${e.feature} = ${e.value ?? ''} ${e.reason ? `(${e.reason})` : ''}`.trim();
        if (e.name) return `${e.name} = ${e.value ?? ''}`;
        try { return JSON.stringify(e); } catch { return '[Forensic Record]'; }
      }
      return String(e);
    })
    .filter((s: string) => s.length > 0);

  const contributingFeatures = Array.isArray(row.contributing_features ?? row.contributingFeatures)
    ? (row.contributing_features ?? row.contributingFeatures)
    : rawEvidence
        .filter((e: any) => typeof e === 'object' && e !== null && (e.feature || e.name))
        .map((e: any) => ({ name: String(e.feature || e.name), value: String(e.value ?? '') }));

  const confidence = typeof row.confidence === 'number' && !isNaN(row.confidence) ? row.confidence : 0.90;

  const detectorOutputs = Array.isArray(row.detector_outputs ?? row.detectorOutputs)
    ? (row.detector_outputs ?? row.detectorOutputs)
    : [
        {
          detector: row.detector ?? row.detection_method ?? 'zero_day',
          score: confidence,
          triggered: true,
        },
      ];

  return {
    id: String(row.alert_id || row.id || `alt-${Math.random().toString(36).substring(2, 8)}`),
    timestamp: row.timestamp || new Date().toISOString(),
    flowId: String(row.flow_id || row.flowId || 'flow-000'),
    threatClass: row.threat_class || row.threatClass || 'botnet_c2_beacon',
    sihCategory: row.sih_category || row.sihCategory || 'Botnet C2 Beaconing',
    severity: (row.severity as Alert['severity']) || 'HIGH',
    confidence,
    status: (row.status as Alert['status']) || 'New',
    source: {
      ip: row.src_ip || row.source?.ip || '0.0.0.0',
      port: row.src_port || row.source?.port || 443,
    },
    destination: {
      ip: row.dst_ip || row.destination?.ip || '0.0.0.0',
      port: row.dst_port || row.destination?.port || 443,
    },
    protocol: row.protocol || 'TCP',
    evidence,
    summary: row.summary || `${row.sih_category || 'Threat'} detected by ZERO-DAY engine`,
    detectionMethod: row.detection_method || row.detectionMethod || 'Rules + ML hybrid',
    contributingFeatures,
    detectorOutputs,
    analystInterpretation:
      row.analyst_interpretation ||
      row.analystInterpretation ||
      `Observed ${row.sih_category || 'threat'} with confidence ${(confidence * 100).toFixed(1)}%.`,
    magnitude: typeof row.magnitude === 'number' && !isNaN(row.magnitude) ? row.magnitude : confidence,
    detectionLatencyMs:
      typeof row.detection_latency_ms === 'number'
        ? row.detection_latency_ms
        : typeof row.detectionLatencyMs === 'number'
        ? row.detectionLatencyMs
        : 0,
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
