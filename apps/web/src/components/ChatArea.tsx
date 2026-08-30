import { useEffect, useRef } from 'react'
import { Bot, TerminalSquare, User } from 'lucide-react'
import type { ChatMessage } from '../lib/types'
import ChainCard from './ChainCard'

const SUGGESTIONS = [
  'Scan host 192.168.10.14 for open ports 80 and 443 using nmap',
  'Run a vulnerability audit on http://192.168.10.14 with nikto',
  'Enumerate the services running on host 192.168.10.14',
  'Bruteforce directories on http://192.168.10.14 using gobuster with default wordlist',
]

function TypingDots() {
  return (
    <div className="flex items-center gap-1 py-1">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="h-1.5 w-1.5 animate-bounce rounded-full bg-gray-500"
          style={{ animationDelay: `${i * 150}ms` }}
        />
      ))}
    </div>
  )
}

function EmptyState({ onPick }: { onPick: (c: string) => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-6 px-6">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-accent-600 to-accent-700 text-xl font-bold text-gray-950 shadow-lg shadow-accent-600/20">
        N
      </div>
      <div className="text-center">
        <div className="text-xl font-semibold tracking-tight text-gray-100">
          How can I help you with your engagement?
        </div>
        <div className="mt-1 text-sm text-gray-500">
          Natural language → validated intent → ready-to-run Kali command
        </div>
      </div>
      <div className="grid w-full max-w-2xl grid-cols-1 gap-2 sm:grid-cols-2">
        {SUGGESTIONS.map((s) => (
          <button
            key={s}
            onClick={() => onPick(s)}
            className="rounded-xl border border-surface-700 bg-surface-850 px-3 py-2.5 text-left text-[13px] text-gray-300 transition hover:border-accent-500/50 hover:text-gray-100"
          >
            {s}
          </button>
        ))}
      </div>
    </div>
  )
}

export default function ChatArea({
  messages,
  title,
  busy,
  onEmptyPick,
}: {
  messages: ChatMessage[]
  title: string
  busy: boolean
  onEmptyPick: (c: string) => void
}) {
  const bottomRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, busy])

  if (messages.length === 0) {
    return (
      <div className="flex-1 overflow-y-auto">
        <EmptyState onPick={onEmptyPick} />
      </div>
    )
  }

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="mx-auto flex min-h-full max-w-4xl flex-col gap-6 px-4 py-6">
        {messages.map((m) => (
          <div key={m.id} className="flex gap-3">
            <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg">
              {m.role === 'user' ? (
                <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-surface-700 text-gray-300">
                  <User className="h-4 w-4" />
                </span>
              ) : (
                <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-accent-600/20 text-accent-500">
                  <Bot className="h-4 w-4" />
                </span>
              )}
            </div>
            <div className="min-w-0 flex-1">
              {m.role === 'user' ? (
                <p className="whitespace-pre-wrap break-words pt-1 text-[15px] leading-relaxed text-gray-100">
                  {m.content}
                </p>
              ) : m.flow ? (
                <ChainCard flow={m.flow} />
              ) : m.error ? (
                <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
                  {m.error}
                </div>
              ) : (
                <div className="flex items-center gap-2 pt-1 text-sm text-gray-400">
                  <TerminalSquare className="h-4 w-4" />
                  {busy ? (
                    <TypingDots />
                  ) : (
                    <span>Planning…</span>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
      <div className="sr-only" aria-live="polite">
        {title}
      </div>
    </div>
  )
}