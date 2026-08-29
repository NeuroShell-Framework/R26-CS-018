import { useState } from 'react'
import { LogOut, Plus, Search, Trash2 } from 'lucide-react'
import type { ChatSession } from '../lib/types'
import type { UserProfile } from '../lib/supabase'

interface Props {
  sessions: ChatSession[]
  activeId: string | null
  profile: UserProfile
  c1Ok: boolean
  c2Ok: boolean
  onNew: () => void
  onSelect: (id: string) => void
  onDelete: (id: string) => void
  onSignOut: () => void
}

function groupSessions(sessions: ChatSession[]) {
  const now = Date.now()
  const day = 86_400_000
  const today: ChatSession[] = []
  const week: ChatSession[] = []
  const older: ChatSession[] = []
  for (const s of sessions) {
    const age = now - s.updatedAt
    if (age < day) today.push(s)
    else if (age < 7 * day) week.push(s)
    else older.push(s)
  }
  const groups: Array<{ label: string; items: ChatSession[] }> = []
  if (today.length) groups.push({ label: 'Today', items: today })
  if (week.length)
    groups.push({ label: 'Previous 7 days', items: week })
  if (older.length) groups.push({ label: 'Older', items: older })
  return groups
}

export default function Sidebar({
  sessions,
  activeId,
  profile,
  c1Ok,
  c2Ok,
  onNew,
  onSelect,
  onDelete,
  onSignOut,
}: Props) {
  const [query, setQuery] = useState('')
  const q = query.trim().toLowerCase()
  const filtered = q
    ? sessions.filter(
        (s) =>
          s.title.toLowerCase().includes(q) ||
          s.messages.some((m) => m.content.toLowerCase().includes(q)),
      )
    : sessions
  const groups = groupSessions(filtered)

  return (
    <aside className="flex h-full w-72 shrink-0 flex-col border-r border-surface-800 bg-surface-900">
      <div className="p-3">
        <button
          onClick={onNew}
          className="flex w-full items-center justify-center gap-2 rounded-xl border border-surface-600 bg-surface-800 px-3 py-2.5 text-sm font-medium text-gray-200 transition hover:border-accent-500/60 hover:bg-surface-700"
        >
          <Plus className="h-4 w-4" />
          New chat
        </button>
        <div className="relative mt-3">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search sessions…"
            className="w-full rounded-lg border border-surface-700 bg-surface-850 py-2 pl-9 pr-3 text-sm text-gray-200 placeholder-gray-600 outline-none focus:border-accent-500/50"
          />
        </div>
      </div>

      <nav className="flex-1 space-y-4 overflow-y-auto px-3 pb-3">
        {groups.length === 0 && (
          <div className="px-2 py-6 text-center text-xs text-gray-600">
            {q ? 'No matching sessions' : 'No sessions yet'}
          </div>
        )}
        {groups.map((g) => (
          <div key={g.label}>
            <div className="mb-1 px-2 text-[11px] font-medium uppercase tracking-wider text-gray-500">
              {g.label}
            </div>
            <div className="flex flex-col gap-0.5">
              {g.items.map((s) => (
                <div
                  key={s.id}
                  onClick={() => onSelect(s.id)}
                  className={`group flex cursor-pointer items-center gap-2 rounded-lg px-2 py-2 text-[13px] transition ${
                    s.id === activeId
                      ? 'bg-surface-700 text-gray-100'
                      : 'text-gray-400 hover:bg-surface-800 hover:text-gray-200'
                  }`}
                >
                  <span className="flex-1 truncate">{s.title}</span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      onDelete(s.id)
                    }}
                    title="Delete session"
                    className="rounded p-0.5 text-gray-500 opacity-0 transition hover:text-red-300 group-hover:opacity-100"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="border-t border-surface-800 p-3">
        <div className="flex items-center justify-between rounded-lg border border-surface-700 bg-surface-850 px-3 py-2">
          <div className="flex gap-3 text-[11px]">
            <span className="flex items-center gap-1.5">
              <span
                className={`h-2 w-2 rounded-full ${c1Ok ? 'bg-accent-500' : 'bg-red-500'}`}
              />
              <span className="text-gray-400">C1</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span
                className={`h-2 w-2 rounded-full ${c2Ok ? 'bg-accent-500' : 'bg-red-500'}`}
              />
              <span className="text-gray-400">C2</span>
            </span>
          </div>
          <span className="font-mono text-[10px] text-gray-600">8001/8002</span>
        </div>
        <div className="mt-3 flex items-center gap-2.5">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-accent-600 text-sm font-bold text-gray-950">
            {profile.name.charAt(0).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <div className="truncate text-[13px] font-medium text-gray-200">
              {profile.name}
            </div>
            <div className="truncate text-[11px] text-gray-500">
              {profile.email}
            </div>
          </div>
          <button
            onClick={onSignOut}
            title="Sign out"
            className="rounded-lg p-1.5 text-gray-500 transition hover:bg-surface-800 hover:text-gray-200"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </aside>
  )
}