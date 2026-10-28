import { config } from './config'
import type { FlowResponse, UserRole } from './types'

export interface ChainInput {
  command: string
  sessionId: string
  role: UserRole
  signal?: AbortSignal
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export async function executeChain(input: ChainInput): Promise<FlowResponse> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (config.c1ApiKey) headers['X-API-Key'] = config.c1ApiKey

  let resp: Response
  try {
    resp = await fetch(`${config.c1Url}/execute`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        command: input.command,
        session_id: input.sessionId,
        role: input.role,
      }),
      signal: input.signal,
    })
  } catch (e) {
    if (input.signal?.aborted) throw new ApiError(0, 'Aborted')
    throw new ApiError(0, config.c1Url)
  }

  let data: unknown
  try {
    data = await resp.json()
  } catch {
    data = null
  }

  if (!resp.ok) {
    const detail =
      data && typeof data === 'object' && 'detail' in data
        ? String((data as { detail: unknown }).detail)
        : `HTTP ${resp.status}`
    throw new ApiError(resp.status, detail)
  }

  return data as FlowResponse
}

export interface HealthInfo {
  ok: boolean
  label: string
}

export async function checkHealth(url: string, label: string): Promise<HealthInfo> {
  try {
    const controller = new AbortController()
    const t = setTimeout(() => controller.abort(), 4000)
    const resp = await fetch(`${url}/health`, { signal: controller.signal })
    clearTimeout(t)
    return { ok: resp.status === 200, label }
  } catch {
    return { ok: false, label }
  }
}