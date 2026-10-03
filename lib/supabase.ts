/**
 * VERITAS-Vault Supabase Client & Database Helpers
 *
 * Mapped to environment variables:
 * - NEXT_PUBLIC_SUPABASE_URL / SUPABASE_URL
 * - NEXT_PUBLIC_SUPABASE_ANON_KEY / SUPABASE_KEY / SUPABASE_ANON_KEY
 */

export type VaultRole = "admin" | "operator";
export type AccessRole = "Employee" | "Customer";
export type AccessMode = "standard" | "high-value";
export type VaultVerdict = "GRANTED" | "DENIED" | "BREACH" | "WAITING" | "RESET";

export interface VerifiedParty {
  id: string;
  name: string;
  role: AccessRole;
}

export interface EnrolledUser {
  user_id: string;
  name: string;
  role: AccessRole | string;
  image_url?: string;
  synced_at?: string;
  pwa_data?: {
    id: string;
    name: string;
    role: AccessRole;
    created_at: string;
    template?: Record<string, unknown>;
    baseline?: string;
  };
}

export interface AccessAuditLog {
  id?: number;
  event_id: string;
  timestamp: string;
  mode: AccessMode | string;
  verified_parties: string;
  party_ids?: string;
  verdict: VaultVerdict;
  sha256_hash: string;
  encrypted_path?: string;
  status: "CLOUD_STORED" | "LOCAL_STORED" | string;
  pwa_data?: {
    id: string;
    timestamp: string;
    verdict: VaultVerdict;
    mode: string;
    parties: VerifiedParty[];
    reason?: string;
    evidence?: {
      path?: string;
      sha256?: string;
      shape?: number[];
      key_id?: string;
    };
    sha256_hash?: string;
    status?: string;
  };
}

export interface VaultRecord {
  id: string;
  payload: Record<string, unknown>;
  version: number;
}

export interface SupabaseConfig {
  url: string;
  key: string;
}

/**
 * Resolves Supabase credentials from Next.js / Vercel public or server environment variables.
 */
export function getSupabaseConfig(): SupabaseConfig {
  const env = (typeof process !== "undefined" && process.env) || ({} as Record<string, string | undefined>);
  const url =
    env.NEXT_PUBLIC_SUPABASE_URL ||
    env.SUPABASE_URL ||
    (typeof window !== "undefined" && (window as unknown as { __SUPABASE_URL__?: string }).__SUPABASE_URL__) ||
    "";
  const key =
    env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    env.SUPABASE_ANON_KEY ||
    env.SUPABASE_KEY ||
    (typeof window !== "undefined" && (window as unknown as { __SUPABASE_ANON_KEY__?: string }).__SUPABASE_ANON_KEY__) ||
    "";

  return { url: url.replace(/\/+$/, ""), key };
}

export function isSupabaseConfigured(): boolean {
  const { url, key } = getSupabaseConfig();
  return Boolean(url && key && url.startsWith("https://"));
}

/**
 * Lightweight HTTP client for Supabase REST API (zero external runtime dependencies).
 */
export async function supabaseRestQuery<T>(
  table: string,
  params: Record<string, string> = {},
  options: RequestInit = {}
): Promise<T[]> {
  const { url, key } = getSupabaseConfig();
  if (!url || !key) {
    throw new Error("Supabase is not configured (missing URL or API key).");
  }

  const query = new URLSearchParams(params).toString();
  const endpoint = `${url}/rest/v1/${table}${query ? `?${query}` : ""}`;

  const response = await fetch(endpoint, {
    ...options,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Supabase query failed (${response.status}): ${errorText}`);
  }

  return response.json();
}

/**
 * Fetch all enrolled personnel from the public.enrolled_users table.
 */
export async function getEnrolledPersonnel(): Promise<EnrolledUser[]> {
  return supabaseRestQuery<EnrolledUser>("enrolled_users", {
    select: "user_id,name,role,synced_at,pwa_data",
    order: "synced_at.desc",
  });
}

/**
 * Fetch recent audit logs from the public.access_audit_logs table.
 */
export async function getAccessAuditLogs(filter?: {
  verdict?: VaultVerdict;
  limit?: number;
}): Promise<AccessAuditLog[]> {
  const params: Record<string, string> = {
    select: "*",
    order: "timestamp.desc",
    limit: String(filter?.limit || 100),
  };
  if (filter?.verdict) {
    params.verdict = `eq.${filter.verdict}`;
  }
  return supabaseRestQuery<AccessAuditLog>("access_audit_logs", params);
}

/**
 * Fetch a specific vault state record by key (e.g. 'checkpoint:main').
 */
export async function getVaultRecord(recordId: string): Promise<VaultRecord | null> {
  const records = await supabaseRestQuery<VaultRecord>("vault_records", {
    id: `eq.${recordId}`,
    limit: "1",
  });
  return records[0] || null;
}
