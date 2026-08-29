import { useCallback, useEffect, useState } from 'react'
import { getSupabase, profileFromUser, type UserProfile } from './lib/supabase'
import AuthScreen from './components/AuthScreen'
import PanelLayout from './components/PanelLayout'

export default function App() {
  const [profile, setProfile] = useState<UserProfile | null>(null)
  const [checking, setChecking] = useState(true)

  useEffect(() => {
    const sb = getSupabase()
    if (!sb) {
      setChecking(false)
      return
    }
    let mounted = true
    sb.auth.getSession().then(({ data }) => {
      if (!mounted) return
      if (data.session?.user) {
        setProfile(profileFromUser(data.session.user))
      }
      setChecking(false)
    })
    const { data: sub } = sb.auth.onAuthStateChange((_event, session) => {
      if (!mounted) return
      if (session?.user) {
        setProfile(profileFromUser(session.user))
      } else {
        setProfile(null)
      }
    })
    return () => {
      mounted = false
      sub.subscription.unsubscribe()
    }
  }, [])

  const onAuthenticated = useCallback((u: UserProfile) => {
    setProfile(u)
  }, [])

  const onSignOut = useCallback(async () => {
    const sb = getSupabase()
    if (sb) await sb.auth.signOut()
    setProfile(null)
  }, [])

  if (checking) {
    return (
      <div className="flex h-full items-center justify-center bg-surface-950">
        <div className="flex items-center gap-3 text-sm text-gray-500">
          <span className="h-2 w-2 animate-pulse rounded-full bg-accent-500" />
          Loading session…
        </div>
      </div>
    )
  }

  return profile ? (
    <PanelLayout key={profile.id} profile={profile} onSignOut={onSignOut} />
  ) : (
    <AuthScreen onAuthenticated={onAuthenticated} />
  )
}