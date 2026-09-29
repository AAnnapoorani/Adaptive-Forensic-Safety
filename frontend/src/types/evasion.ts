// Extended API service — all new evasion, polymorphic, and multi-machine endpoints

// ── Evasion / Polymorphic types ────────────────────────────────────────────

export interface DriverEntry {
  filename: string;
  device_path: string;
  base_address: string;
  is_byovd_known_vulnerable: boolean;
  byovd_risk: string | null;
  byovd_cve: string | null;
  byovd_vendor: string | null;
  byovd_technique: string | null;
  enumerated_at: string;
}

export interface MemoryRegion {
  pid: number;
  process_name: string;
  base_address: string;
  region_size_bytes: number;
  protection: string;
  type: string;
  state: string;
  injection_indicator: string;
  severity: string;
  detection_notes: string;
  scanned_at: string;
}

export interface PolymorphicResult {
  original_hash: string;
  variant_count: number;
  all_hashes_unique: boolean;
  hashes: string[];
  variants: string[];
  mutation_techniques: string[];
}

export interface EncryptResult {
  status: string;
  investigation_id: string;
  blob_hex: string;
  blob_size_bytes: number;
  payload_sha256: string;
  encryption_scheme: string;
  key_derivation: string;
}

export interface RoutingConfig {
  routing_mode: string;
  cdn_domain: string | null;
  real_host: string | null;
  proxy_configured: boolean;
  supported_modes: Record<string, string>;
  current_description: string;
}

export interface RemoteMachine {
  machine_id: string;
  hostname: string;
  ip_address: string;
  os_type: string;
  port: number;
  username: string;
  auth_method: string;
  status: string;
  tags: string[];
  registered_at: string;
}

export interface PingResult {
  machine_id: string;
  hostname: string;
  ip: string;
  port: number;
  tcp_reachable: boolean;
  ssh_connected: boolean;
  latency_ms: number | null;
}
