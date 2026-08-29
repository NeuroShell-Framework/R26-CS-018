import { createClient } from '@supabase/supabase-js'
import { config, supabaseConfigured } from './config'

let client = null as ReturnType<typeof createClient> | null

export function getSupabase() {
  if (!supabaseConfigured) return null
  if (!client) {
    client = createClient(config.supabaseUrl, config.supabaseAnonKey)
  }
  return client
}

export type UserProfile = {
  id: string
  email: string
  name: string
  role: string
}

export function profileFromUser(user: {
  id: string
  email?: string
  user_metadata?: Record<string, unknown> | null
}): UserProfile {
  const meta = (user.user_metadata ?? {}) as Record<string, string>
  return {
    id: user.id,
    email: user.email ?? '',
    name: meta.name ?? user.email?.split('@')[0] ?? 'User',
    role: meta.role ?? 'analyst',
  }
}