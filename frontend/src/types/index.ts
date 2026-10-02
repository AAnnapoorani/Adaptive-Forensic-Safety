export interface Machine {
  id: string;
  machine_id?: string;
  hostname: string;
  os_type: 'Windows' | 'Linux' | 'macOS' | string;
  os_name: string;
  os_version?: string;
  architecture?: string;
  ip_address?: string;
  mac_address?: string;
  agent_version?: string;
  status: 'ONLINE' | 'OFFLINE' | 'ACTIVE' | string;
  last_seen: string;
  first_seen?: string;
  created_at?: string;
  latest_metrics?: {
    cpu_percent: number;
    cpu_cores?: number;
    cpu_freq_mhz?: number;
    memory_total_bytes?: number;
    memory_used_bytes?: number;
    memory_available_bytes?: number;
    memory_percent: number;
    disk_total_bytes?: number;
    disk_used_bytes?: number;
    disk_free_bytes?: number;
    disk_percent: number;
    network_bytes_sent?: number;
    network_bytes_recv?: number;
    network_upload_speed: number;
    network_download_speed: number;
    active_connections: number;
    timestamp?: string;
  };
  hardware_fingerprint?: HardwareFingerprint;
  lifetime_ledger?: LifetimeLedgerEvent[];
}

export interface HardwareFingerprint {
  bios_uuid: string;
  primary_mac: string;
  os_machine_guid: string;
  hash_formula: string;
  composite_hash: string;
  stable_machine_id: string;
}

export interface LifetimeLedgerEvent {
  event_type: string;
  timestamp: string;
  user: string;
  ip_address: string;
  status: string;
  machine_id: string;
  notes: string;
}

export interface MachineTelemetryPoint {
  timestamp: string;
  cpu_percent: number;
  memory_percent: number;
  disk_percent: number;
  network_upload_speed: number;
  network_download_speed: number;
  active_connections: number;
}

export interface MachineProcess {
  pid: number;
  name: string;
  exe_path?: string;
  username: string;
  cpu_percent: number;
  memory_percent: number;
  memory_rss_bytes: number;
  status: string;
  create_time?: string;
  timestamp?: string;
  threat_level?: 'CLEAN' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL' | string;
  matched_rules?: string[];
}

export interface AgentTriageCommandItem {
  id: string;
  command: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  dispatched_at: string;
  completed_at?: string;
  exit_code?: number;
  output?: string;
  error?: string;
  signed_hash?: string;
}

export interface ForensicEventItem {
  id: string;
  event_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INFO';
  source: string;
  description: string;
  process_name?: string;
  pid?: number;
  user?: string;
  remote_ip?: string;
  metadata_json?: string;
  timestamp: string;
}

export interface InvestigationSummary {
  id: string;
  intent: string;
  status: string;
  machine_id: string;
  current_round: number;
  total_rounds: number;
  start_time: string;
  end_time?: string;
  created_at: string;
  artifact_count: number;
  correlation_count: number;
  timeline_count: number;
  escalation_triggered: boolean;
}

export interface InvestigationDetail {
  id: string;
  intent: string;
  script?: string;
  status: string;
  machine_id: string;
  current_round: number;
  total_rounds: number;
  start_time: string;
  end_time?: string;
  created_at: string;
  summary?: string;
  metrics: {
    total_artifacts: number;
    correlation_matches: number;
    timeline_events: number;
    rounds_count: number;
    escalation_triggered: boolean;
  };
}

export interface EvidenceNode {
  id: string;
  operation: string;
  label: string;
  category: string;
  required: boolean;
  status: string;
  round_number: number;
  reason: string;
  metadata?: Record<string, any>;
}

export interface EvidenceEdge {
  source: string;
  target: string;
  relationship: string;
}

export interface EvidenceGraph {
  intent: string;
  total_nodes: number;
  total_edges: number;
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
}

export interface PlannedStep {
  step_id: string;
  operation: string;
  priority: number;
  dependencies: string[];
  round_number: number;
  reason: string;
  status: string;
  start_time?: string;
  end_time?: string;
  error?: string;
}

export interface ExecutableWorkflow {
  investigation_id: string;
  round_number: number;
  total_steps: number;
  steps: PlannedStep[];
}

export interface PlanPreview {
  investigation_id?: string;
  intent: string;
  round: number;
  initial_operations?: string[];
  tokens?: any[];
  ir?: any;
  evidence_graph: EvidenceGraph;
  workflow: ExecutableWorkflow;
}

export interface ReportData {
  investigation_id: string;
  markdown: string;
  html: string;
  json?: any;
}


export interface EvidenceArtifact {
  id: string;
  name: string;
  artifact_type: string;
  collector: string;
  operation: string;
  round_number: number;
  reason: string;
  file_size_bytes: number;
  sha256: string;
  integrity_status: string;
  is_synthetic: boolean;
  collected_at: string;
}

export interface ProvenanceRecord {
  id: string;
  artifact_id: string;
  intent: string;
  collector: string;
  operation: string;
  machine_id: string;
  round_number: number;
  reason: string;
  sha256: string;
  collected_at: string;
  recorded_at: string;
  metadata?: Record<string, any>;
  // ── Integrity 2.0 Hash Chain & Ed25519 fields ──
  sequence_number?: number;
  previous_record_hash?: string;
  record_hash?: string;
  key_id?: string;
  signature?: string;
  is_legacy?: boolean;
  canonical_record?: Record<string, any>;
}

export interface ChainVerificationReport {
  investigation_id: string;
  case_id: string;
  result: 'VERIFIED' | 'TAMPERED' | 'LEGACY_FORMAT' | 'EMPTY';
  verified: boolean;
  is_legacy?: boolean;
  records_count: number;
  chain_tip?: string;
  key_id?: string;
  signature_algorithm?: string;
  diagnostics: {
    evidence_hashes: string;
    metadata_integrity: string;
    hash_chain: string;
    chain_ordering: string;
    chain_tip: string;
    ed25519_signature: string;
  };
  failure_details?: {
    record_sequence?: number;
    artifact_id?: string;
    attack_type?: string;
    reason: string;
    expected_sha256?: string;
    calculated_sha256?: string;
    expected_previous_hash?: string;
    stored_previous_hash?: string;
    stored_record_hash?: string;
    calculated_record_hash?: string;
    expected_sequence?: number;
    found_sequence?: number;
  } | null;
}

export interface ChainManifest {
  format: string;
  version: string;
  case_id: string;
  investigation_id: string;
  genesis_hash: string;
  record_count: number;
  first_timestamp?: string;
  last_timestamp?: string;
  chain_tip: string;
  signature_algorithm: string;
  key_id?: string;
  public_key_hex?: string;
  public_key_pem?: string;
  signature?: string;
  records: any[];
}


export interface CorrelationMatch {
  id: string;
  round_number: number;
  rule_name: string;
  confidence: string;
  status_label: string;
  severity?: string;
  description: string;
  matched_data?: string;
  created_at: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  event_type: string;
  description: string;
  source: string;
  machine_id: string;
  round_number: number;
  details?: Record<string, any>;
}

export interface InvestigationRound {
  id: string;
  round_number: number;
  trigger_reason: string;
  status: string;
  started_at?: string;
  completed_at?: string;
  steps_count: number;
  artifacts_count: number;
  correlation_matches_count: number;
}
