import { type RefObject, useEffect, useRef, useState } from 'react'
import { ArrowUp, Settings2 } from 'lucide-react'
import { ROLES, type UserRole } from '../lib/types'

interface Props {
  busy: boolean
  role: UserRole
  onRoleChange: (r: UserRole) => void
  onSend: (command: string) => void
  forwardRef: RefObject<HTMLTextAreaElement>
}

export default function Composer({
  busy,
  role,
  onRoleChange,
  onSend,
  forwardRef: inputRef,
}: Props) {
  const [text, setText] = useState('')
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  function autoResize() {
    const el = inputRef.current ?? textareaRef.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = `${Math.min(el.scrollHeight, 200)}px`
  }

  useEffect(() => {
    autoResize()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text])

  function submit() {
    const command = text.trim()
    if (!command || busy) return
    setText('')
    onSend(command)
    requestAnimationFrame(() => inputRef.current?.focus())
  }

  return (
    <div className="border-t border-surface-800 bg-surface-900 px-4 py-3">
      <div className="mx-auto max-w-4xl">
        <div className="relative rounded-2xl border border-surface-600 bg-surface-850 shadow-lg shadow-black/20 focus-within:border-accent-500/60">
          <textarea
            ref={inputRef}
            rows={1}
            value={text}
            onChange={(e) => {
              setText(e.target.value)
              autoResize()
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                submit()
              }
            }}
            placeholder="Describe what you want to do…  (e.g. scan host 192.168.10.14 for ports 80 and 443 using nmap)"
            className="block max-h-50 w-full resize-none bg-transparent px-4 py-3 pr-14 text-[15px] leading-relaxed text-gray-100 placeholder-gray-600 outline-none"
          />
          <button
            onClick={submit}
            disabled={busy || !text.trim()}
            title="Send"
            className="absolute bottom-2.5 right-2.5 flex h-8 w-8 items-center justify-center rounded-lg bg-accent-600 text-gray-950 transition hover:bg-accent-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ArrowUp className="h-4 w-4" />
          </button>
        </div>
        <div className="mt-2 flex items-center justify-between px-1">
          <div className="flex items-center gap-1.5 text-[11px] text-gray-500">
            <Settings2 className="h-3.5 w-3.5" />
            <span>
              Enter to send · Shift+Enter for a new line · chain runs through
              C1 → C2
            </span>
          </div>
          <div className="flex items-center gap-1">
            {ROLES.map((r) => (
              <button
                key={r}
                onClick={() => onRoleChange(r)}
                className={`rounded-full px-2.5 py-1 text-[11px] font-medium capitalize transition ${
                  role === r
                    ? 'bg-accent-600/15 text-accent-500'
                    : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}