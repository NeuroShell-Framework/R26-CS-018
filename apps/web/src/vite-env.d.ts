/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SUPABASE_URL?: string
  readonly VITE_SUPABASE_ANON_KEY?: string
  readonly VITE_C1_URL?: string
  readonly VITE_C2_URL?: string
  readonly VITE_C1_API_KEY?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}