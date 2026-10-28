import { type FormEvent, type ReactNode, useEffect, useState } from 'react'
import { getSupabase, profileFromUser } from '../lib/supabase'
import { supabaseConfigured } from '../lib/config'
import type { UserProfile } from '../lib/supabase'
import { ROLES, type UserRole } from '../lib/types'

interface Props {
  onAuthenticated: (profile: UserProfile) => void
}

type Mode = 'signin' | 'signup'

const inputCls =
  'w-full rounded-lg border border-surface-600 bg-surface-850 px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-500 outline-none transition focus:border-accent-500 focus:ring-2 focus:ring-accent-500/30'

export default function AuthScreen({ onAuthenticated }: Props) {
  const [mode, setMode] = useState<Mode>('signin')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<UserRole>('admin')
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const sb = getSupabase()
    if (!sb) return
    const { data: sub } = sb.auth.onAuthStateChange((_event, session) => {
      if (session?.user) {
        onAuthenticated(profileFromUser(session.user))
      }
    })
    return () => {
      sub.subscription.unsubscribe()
    }
  }, [onAuthenticated])

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setInfo('')
    setBusy(true)
    const sb = getSupabase()
    if (!sb) {
      setBusy(false)
      return
    }
    try {
      if (mode === 'signin') {
        const { data, error: err } = await sb.auth.signInWithPassword({
          email,
          password,
        })
        if (err) throw err
        if (data.user) onAuthenticated(profileFromUser(data.user))
      } else {
        if (!name.trim()) throw new Error('Please enter your name')
        const { data, error: err } = await sb.auth.signUp({
          email,
          password,
          options: {
            data: { name: name.trim(), role },
          },
        })
        if (err) throw err
        if (!data.session) {
          setInfo(
            'Account created — check your inbox for a confirmation link, then sign in.',
          )
        } else if (data.user) {
          onAuthenticated(profileFromUser(data.user))
        }
      }
    } catch (c: unknown) {
      setError(
        c instanceof Error
          ? c.message
          : 'Authentication failed. Check your credentials.',
      )
    } finally {
      setBusy(false)
    }
  }

  if (!supabaseConfigured) {
    return (
      <Shell>
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-5 py-4 text-sm text-amber-300">
          Supabase is not configured.
          <br />
          <br />
          Copy <code className="font-mono">.env.example</code> to{' '}
          <code className="font-mono">.env</code> and set{' '}
          <code className="font-mono">VITE_SUPABASE_URL</code> and{' '}
          <code className="font-mono">VITE_SUPABASE_ANON_KEY</code> from your
          Supabase project.
        </div>
      </Shell>
    )
  }

  return (
    <Shell>
      <div className="flex flex-col gap-6">
        <div className="flex flex-col gap-1.5 text-center">
          <div className="text-2xl font-semibold tracking-tight text-gray-100">
            {mode === 'signin' ? 'Welcome back' : 'Create your account'}
          </div>
          <div className="text-sm text-gray-400">
            {mode === 'signin'
              ? 'Sign in to continue to NeuroShell Console'
              : 'Set up your identity for the engagement console'}
          </div>
        </div>

        <form onSubmit={submit} className="flex flex-col gap-4">
          {mode === 'signup' && (
            <div className="flex flex-col gap-4">
              <input
                className={inputCls}
                placeholder="Full name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="name"
              />
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-gray-400">
                  RBAC role
                </label>
                <div className="grid grid-cols-4 gap-2">
                  {ROLES.map((r) => (
                    <button
                      key={r}
                      type="button"
                      onClick={() => setRole(r)}
                      className={`rounded-lg border px-2 py-1.5 text-xs font-medium capitalize transition ${
                        role === r
                          ? 'border-accent-500 bg-accent-500/15 text-accent-500'
                          : 'border-surface-600 bg-surface-850 text-gray-400 hover:border-surface-600 hover:text-gray-200'
                      }`}
                    >
                      {r}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          <input
            className={inputCls}
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            required
          />
          <input
            className={inputCls}
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === 'signin' ? 'current-password' : 'new-password'}
            required
            minLength={6}
          />

          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
              {error}
            </div>
          )}
          {info && (
            <div className="rounded-lg border border-accent-500/30 bg-accent-500/10 px-3 py-2 text-sm text-emerald-300">
              {info}
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="mt-1 w-full rounded-lg bg-accent-600 px-4 py-2.5 text-sm font-semibold text-gray-950 transition hover:bg-accent-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy
              ? 'Please wait…'
              : mode === 'signin'
                ? 'Sign in'
                : 'Create account'}
          </button>
        </form>

        <div className="text-center text-sm text-gray-400">
          {mode === 'signin' ? (
            <>
              Don&apos;t have an account?{' '}
              <button
                className="font-medium text-accent-500 hover:underline"
                onClick={() => {
                  setMode('signup')
                  setError('')
                  setInfo('')
                }}
              >
                Sign up
              </button>
            </>
          ) : (
            <>
              Already registered?{' '}
              <button
                className="font-medium text-accent-500 hover:underline"
                onClick={() => {
                  setMode('signin')
                  setError('')
                  setInfo('')
                }}
              >
                Sign in
              </button>
            </>
          )}
        </div>
      </div>
    </Shell>
  )
}

function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-full items-center justify-center bg-surface-950 px-4">
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center gap-3">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-accent-600 to-accent-700 text-xl font-bold text-gray-950 shadow-lg shadow-accent-600/20">
            N
          </div>
          <div className="text-lg font-semibold tracking-tight text-gray-100">
            NeuroShell Console
          </div>
          <div className="text-xs text-gray-500">
            AI-driven offensive security workflow
          </div>
        </div>
        <div className="rounded-2xl border border-surface-700 bg-surface-900 p-6 shadow-2xl shadow-black/40">
          {children}
        </div>
      </div>
    </div>
  )
}