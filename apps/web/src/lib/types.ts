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