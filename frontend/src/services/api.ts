import type {
  Machine,
  MachineTelemetryPoint,
  MachineProcess,
  ForensicEventItem,
  InvestigationSummary,
  InvestigationDetail,
  PlanPreview,
  EvidenceArtifact,
  ProvenanceRecord,
  CorrelationMatch,
  TimelineEvent,
  InvestigationRound,
  ReportData,
  ChainVerificationReport,
  ChainManifest,
  AgentTriageCommandItem
} from "../types";


function normalizeApiUrl(raw?: string): string {
  if (!raw) return "/api";
  let url = raw.trim().replace(/\/$/, '');
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = `https://${url}`;
  }
  return `${url}/api`;
}

export const BASE_URL = normalizeApiUrl(import.meta.env.VITE_API_URL);

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${BASE_URL}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers || {})
    }
  });

  if (!response.ok) {
    let errorMsg = `HTTP Error ${response.status}`;
    try {
      const errData = await response.json();
      errorMsg = errData.detail || errorMsg;
    } catch {
      // ignore
    }
    throw new Error(errorMsg);
  }

  return response.json();
}

export const api = {
  // Health
  getHealth: () => request<any>("/health"),

  // Machines
  getMachines: () => request<Machine[]>("/machines"),
  getMachine: (id: string) => request<Machine>(`/machines/${id}`),
  getMachineTelemetry: (id: string, limit: number = 60) =>
    request<MachineTelemetryPoint[]>(`/machines/${id}/telemetry?limit=${limit}`),
  getMachineProcesses: (id: string) =>
    request<MachineProcess[]>(`/machines/${id}/processes`),
  getMachineEvents: (id: string, limit: number = 50) =>
    request<ForensicEventItem[]>(`/machines/${id}/events?limit=${limit}`),
  getStreamUrl: () => `${BASE_URL}/stream`,

  // Triage Commands & Remote Shell (Enhancement 3)
  dispatchTriageCommand: (machineId: string, command: string) =>
    request<AgentTriageCommandItem>(`/machines/${machineId}/commands`, {
      method: "POST",
      body: JSON.stringify({ command })
    }),
  getTriageCommands: (machineId: string) =>
    request<AgentTriageCommandItem[]>(`/machines/${machineId}/commands`),

  // Retention Guardian (Enhancement 1)
  triggerPruning: (hours?: number) =>
    request<any>(`/telemetry/prune${hours ? `?hours=${hours}` : ''}`, { method: "POST" }),

  // Court Dossier & Legal Certificate (Enhancement 4)
  getCourtDossier: (investigationId: string) =>
    request<any>(`/investigations/${investigationId}/dossier`),
  getCourtDossierHtmlUrl: (investigationId: string) =>
    `${BASE_URL}/investigations/${investigationId}/dossier/html`,

  listInvestigations: () => request<InvestigationSummary[]>("/investigations"),
  getInvestigation: (id: string) => request<InvestigationDetail>(`/investigations/${id}`),
  createInvestigation: (data: { intent?: string; script?: string; machine_id?: string }) =>
    request<{ id: string; intent: string; status: string; machine_id: string; created_at: string }>("/investigations", {
      method: "POST",
      body: JSON.stringify(data)
    }),
  previewScript: (data: { intent?: string; script?: string }) =>
    request<PlanPreview>("/investigations/preview", {
      method: "POST",
      body: JSON.stringify(data)
    }),
  previewInvestigation: (id: string) =>
    request<PlanPreview>(`/investigations/${id}/preview`, { method: "POST" }),
  executeInvestigation: (id: string, demo: boolean = false) =>
    request<{
      investigation_id: string;
      status: string;
      rounds_executed: number;
      artifacts_collected: number;
      timeline_events_count: number;
      integrity_verified: boolean;
      summary: string;
    }>(`/investigations/${id}/execute?demo=${demo}`, { method: "POST" }),

  getInvestigationPlan: (id: string) => request<any>(`/investigations/${id}/plan`),
  getInvestigationRounds: (id: string) => request<InvestigationRound[]>(`/investigations/${id}/rounds`),
  getInvestigationEvidence: (id: string) => request<EvidenceArtifact[]>(`/investigations/${id}/evidence`),
  getInvestigationProvenance: (id: string) => request<ProvenanceRecord[]>(`/investigations/${id}/provenance`),
  getInvestigationCorrelations: (id: string) => request<CorrelationMatch[]>(`/investigations/${id}/correlations`),
  getInvestigationTimeline: (id: string) => request<TimelineEvent[]>(`/investigations/${id}/timeline`),
  verifyEvidence: (id: string) =>
    request<{
      investigation_id: string;
      total_artifacts: number;
      valid_count: number;
      all_valid: boolean;
      details: any[];
    }>(`/investigations/${id}/verify`, { method: "POST" }),

  // ── Integrity 2.0 — Cryptographic Hash Chain & Ed25519 ────────────────
  getInvestigationChain: (id: string) =>
    request<{
      investigation_id: string;
      manifest: ChainManifest | null;
      records: ProvenanceRecord[];
    }>(`/investigations/${id}/chain`),

  getChainManifest: (id: string) =>
    request<ChainManifest>(`/investigations/${id}/chain/manifest`),

  verifyChain: (id: string) =>
    request<ChainVerificationReport>(`/investigations/${id}/chain/verify`, {
      method: "POST"
    }),

  signChainTip: (id: string) =>
    request<{
      status: string;
      investigation_id: string;
      chain_tip: string;
      key_id: string;
      signature_hex: string;
      algorithm: string;
    }>(`/investigations/${id}/chain/sign`, {
      method: "POST"
    }),

  getForensicPackageUrl: (id: string) =>
    `${BASE_URL}/investigations/${id}/chain/export`,

  listPublicKeys: () =>
    request<{
      active_key_id: string;
      keys: Array<{
        key_id: string;
        algorithm: string;
        public_key_hex: string;
        created_at: string;
        alias?: string;
        is_active: boolean;
      }>;
    }>('/evidence/keys'),

  rotateSigningKey: (alias?: string) =>
    request<{
      status: string;
      active_key_id: string;
      public_key_hex: string;
      algorithm: string;
    }>(`/evidence/keys/rotate${alias ? `?alias=${encodeURIComponent(alias)}` : ''}`, {
      method: 'POST'
    }),

  getInvestigationReport: (id: string) =>
    request<ReportData>(`/investigations/${id}/report`),

  getRawArtifact: (id: string) => request<any>(`/evidence/${id}/raw`),

  // ── Evasion Lab — Polymorphic Engine ──────────────────────────────────
  mutateScript: (script: string, iterations: number = 3) =>
    request<any>('/jocky/mutate', {
      method: 'POST',
      body: JSON.stringify({ script, iterations })
    }),

  encryptPayload: (payload: any, investigation_id: string) =>
    request<any>('/jocky/encrypt', {
      method: 'POST',
      body: JSON.stringify({ payload, investigation_id })
    }),

  decryptPayload: (blob_hex: string, investigation_id: string) =>
    request<any>('/jocky/decrypt', {
      method: 'POST',
      body: JSON.stringify({ blob_hex, investigation_id })
    }),

  // ── Evasion Lab — Driver & Memory Inspection ──────────────────────────
  getDrivers: () => request<any>('/jocky/drivers'),
  getMemoryAnalysis: () => request<any>('/jocky/memory'),

  // ── Evasion Lab — CDN Routing ─────────────────────────────────────────
  getRoutingConfig: () => request<any>('/jocky/routing'),
  setRoutingConfig: (config: {
    routing_mode: string;
    cdn_domain?: string;
    real_host?: string;
    proxy_url?: string;
    api_key?: string;
  }) => request<any>('/jocky/routing', {
    method: 'POST',
    body: JSON.stringify(config)
  }),

  // ── Evasion Lab — Remote Machines ─────────────────────────────────────
  getRemoteMachines: () => request<any>('/jocky/remote-machines'),
  registerRemoteMachine: (data: {
    machine_id: string; hostname: string; ip_address: string;
    os_type: string; port: number; username: string;
    auth_method: string; tags: string[];
  }) => request<any>('/jocky/remote-machines', {
    method: 'POST',
    body: JSON.stringify(data)
  }),
  pingRemoteMachines: () =>
    request<any>('/jocky/remote-machines/ping', { method: 'POST' }),
  collectRemote: (machine_ids: string[], operations: string[]) =>
    request<any>('/jocky/remote-machines/collect', {
      method: 'POST',
      body: JSON.stringify({ machine_ids, operations, credentials: {} })
    }),
};
