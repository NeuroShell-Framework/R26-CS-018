export type UserRole = 'admin' | 'operator' | 'analyst' | 'viewer'

export interface IntentContract {
  intent: string
  target: { type: string; value: string } | null
  ports: number[]
  modifiers: string[]
  cve_ids: string[]
  tool_hint: string | null
  confidence: number
  rejection_reason: string | null
  scope_warnings: string[]
}

export interface C2Output {
  status: string
  command: string
  command_sequence: string[]
  tool: string
  session_id: string
  intent_ref: string
  estimated_duration: string
  retrieval_sources: string[]
  validation_passed: boolean
  safety_flags: string[]
  latency_ms: number
}

export interface CorrectionEntry {
  attempt: number
  original_command: string
  corrected_command: string
  error_class: string
  strategy: string
  approved: boolean
  correction_source: string
}

export interface C3Output {
  status: 'success' | 'recovered' | 'failed'
  session_id: string
  command_executed: string
  stdout: string
  stderr: string
  exit_code: number
  recovery_log: unknown[]
  correction_history: CorrectionEntry[]
  failure_report: {
    attempts: number
    final_error_class: string
    strategies_tried?: string[]
    recommendation?: string
  } | null
  tool_substituted: boolean
  latency_ms: number
  integration_latency_ms?: number
}

export interface C4Finding {
  cve_id: string
  service_name?: string
  service_port?: number
  analysis_mode?: string
  exploit_probability?: number
  composite_risk_score?: number
  risk_tier?: string
  top_features?: Record<string, unknown>
}

export interface C4Output {
  status?: string
  session_id: string
  parse_result?: {
    hosts: string[]
    services: unknown[]
    raw_cve_ids: string[]
    paths_found: string[]
  }
  enriched_count?: number
  enriched_vulnerabilities?: unknown[]
  predictions?: C4Finding[]
  ranked_findings?: C4Finding[]
  false_positive_reduction_rate?: number
  latency_ms?: number
  integration_latency_ms?: number
}

export interface FlowResponse {
  status: string
  detail?: string
  flow: {
    step_1_user_input: {
      command: string
      session_id: string
      role: string
    }
    step_2_component_1: {
      status: string
      output: {
        version1: { intent_contract: IntentContract; session_id: string }
        version2: Record<string, unknown>
      }
    }
    step_3_component_2: {
      status: string
      latency_ms?: number
      reason?: string
      output: C2Output | null
    }
    step_4_component_3: {
      status: string
      latency_ms?: number
      output: C3Output | null
    }
    step_5_component_4: {
      status: string
      latency_ms?: number
      output: C4Output | null
    }
  }
}

export interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  flow?: FlowResponse
  error?: string
  ts: number
}

export interface ChatSession {
  id: string
  title: string
  createdAt: number
  updatedAt: number
  messages: ChatMessage[]
}

export const ROLES: UserRole[] = ['admin', 'operator', 'analyst', 'viewer']