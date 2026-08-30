import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Menu, ShieldCheck } from 'lucide-react'
import type { ChatSession, UserRole } from '../lib/types'
import type { UserProfile } from '../lib/supabase'
import { createStore } from '../lib/store'
import { executeChain } from '../lib/api'
import { checkHealth } from '../lib/api'
import { config } from '../lib/config'
import Sidebar from './Sidebar'
import ChatArea from './ChatArea'
import Composer from './Composer'

interface Props {
  profile: UserProfile
  onSignOut: () => void
}

export default function PanelLayout({ profile, onSignOut }: Props) {
  const store = useMemo(() => createStore(), [])
  const [sessions, setSessions] = useState<ChatSession[]>(() =>
    store.sessions,
  )
  const [activeId, setActiveId] = useState<string | null>(store.activeId)
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [role, setRole] = useState<UserRole>(
    (profile.role as UserRole) || 'analyst',
  )
  const [busy, setBusy] = useState(false)
  const [c1Ok, setC1Ok] = useState(false)
  const [c2Ok, setC2Ok] = useState(false)
  const [c3Ok, setC3Ok] = useState(false)
  const [c4Ok, setC4Ok] = useState(false)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  const active = sessions.find((s) => s.id === activeId) ?? null

  useEffect(() => {
    let cancelled = false
    async function tick() {
      const [a, b, c, d] = await Promise.all([
        checkHealth(config.c1Url, 'C1'),
        checkHealth(config.c2Url, 'C2'),
        checkHealth(config.c3Url, 'C3'),
        checkHealth(config.c4Url, 'C4'),
      ])
      if (cancelled) return
      setC1Ok(a.ok)
      setC2Ok(b.ok)
      setC3Ok(c.ok)
      setC4Ok(d.ok)
    }
    tick()
    const t = setInterval(tick, 10000)
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [])

  function handleNew() {
    const { session } = store.createAndSelect()
    setSessions(store.sessions)
    setActiveId(session.id)
  }

  function handleSelect(id: string) {
    store.select(id)
    setActiveId(id)
  }

  function handleDelete(id: string) {
    store.delete(id)
    setSessions(store.sessions)
    setActiveId(store.activeId)
  }

  const send = useCallback(
    async (command: string) => {
      if (busy) return
      let sessionId = activeId
      if (!sessionId) {
        const { session } = store.createAndSelect()
        setSessions(store.sessions)
        setActiveId(session.id)
        sessionId = session.id
      }
      let assistantId = ''
      try {
        const res = store.appendUserMessage(sessionId, command)
        setSessions(res.sessions)
        const asst = store.appendAssistantMessage(sessionId)
        setSessions(asst.sessions)
        assistantId = asst.message.id
      } catch {
        return
      }
      setBusy(true)
      const controller = new AbortController()
      try {
        const flow = await executeChain({
          command,
          sessionId,
          role,
          signal: controller.signal,
        })
        setSessions(store.resolveAssistantMessage(sessionId, assistantId, flow))
      } catch (e) {
        const msg =
          e instanceof Error
            ? e.message === 'Aborted'
              ? 'Request stopped.'
              : `Could not reach Component 01 at ${config.c1Url} — is the backend running? (${e.message})`
            : 'Unexpected error'
        setSessions(
          store.resolveAssistantMessage(sessionId, assistantId, undefined, msg),
        )
      } finally {
        setBusy(false)
      }
    },
    [activeId, busy, role, store],
  )

  function handleSuggestion(c: string) {
    send(c)
    inputRef.current?.focus()
  }

  return (
    <div className="flex h-full overflow-hidden">
      {sidebarOpen && (
        <Sidebar
          sessions={sessions}
          activeId={activeId}
          profile={profile}
          c1Ok={c1Ok}
          c2Ok={c2Ok}
          c3Ok={c3Ok}
          c4Ok={c4Ok}
          onNew={handleNew}
          onSelect={handleSelect}
          onDelete={handleDelete}
          onSignOut={onSignOut}
        />
      )}

      <main className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-surface-800 bg-surface-900 px-4">
          <button
            onClick={() => setSidebarOpen((o) => !o)}
            className="rounded-lg p-1.5 text-gray-400 transition hover:bg-surface-800 hover:text-gray-200"
            title="Toggle sidebar"
          >
            <Menu className="h-5 w-5" />
          </button>
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-medium text-gray-100">
              {active ? active.title : 'NeuroShell Console'}
            </div>
            <div className="text-[11px] text-gray-500">
              {active ? `${active.messages.filter((m) => m.role === 'user').length} messages` : 'Start a new engagement'}
            </div>
          </div>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-surface-700 bg-surface-850 px-2.5 py-1 text-[11px] font-medium capitalize text-gray-300">
            <ShieldCheck className="h-3.5 w-3.5 text-accent-500" />
            {role}
          </span>
        </header>

        <ChatArea
          messages={active?.messages ?? []}
          title={active?.title ?? ''}
          busy={busy}
          onEmptyPick={handleSuggestion}
        />

        <Composer
          busy={busy}
          role={role}
          onRoleChange={setRole}
          onSend={send}
          forwardRef={inputRef}
        />
      </main>
    </div>
  )
}