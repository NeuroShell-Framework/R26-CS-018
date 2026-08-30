const env = (key: string, fallback = '') => {
  const v = import.meta.env[key]
  return typeof v === 'string' && v.trim() ? v : fallback
}

export const config = {
  c1Url: env('VITE_C1_URL', 'http://127.0.0.1:8001'),
  c2Url: env('VITE_C2_URL', 'http://127.0.0.1:8002'),
  c3Url: env('VITE_C3_URL', 'http://127.0.0.1:8003'),
  c4Url: env('VITE_C4_URL', 'http://127.0.0.1:8004'),
  c1ApiKey: env('VITE_C1_API_KEY', ''),
  supabaseUrl: env('VITE_SUPABASE_URL', ''),
  supabaseAnonKey: env('VITE_SUPABASE_ANON_KEY', ''),
}

export const supabaseConfigured = Boolean(
  config.supabaseUrl && config.supabaseAnonKey,
)