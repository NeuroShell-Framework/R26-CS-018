import { type ReactNode, useState } from 'react'
import {
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  ShieldAlert,
  Terminal,
} from 'lucide-react'
import type { FlowResponse } from '../lib/types'
import JsonBlock from './JsonBlock'

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <button
      onClick={copy}
      title="Copy to clipboard"
      className="rounded-lg border border-surface-600 p-1.5 text-gray-400 transition hover:border-surface-500 hover:text-gray-100"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-accent-500" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  )
}

function Badge({
  tone,
  children,
}: {
  tone: 'green' | 'red' | 'amber' | 'slate'
  children: ReactNode
}) {
  const map = {
    green: 'border-accent-500/30 bg-accent-500/10 text-accent-500',
    red: 'border-red-500/30 bg-red-500/10 text-red-300',
    amber: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
    slate: 'border-surface-600 bg-surface-800 text-gray-300',
  }
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${map[tone]}`}
    >
      {children}
    </span>
  )
}

function Collapsible({
  title,
  subtitle,
  data,
  defaultOpen = false,
}: {
  title: string
  subtitle?: string
  data: unknown
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="overflow-hidden rounded-lg border border-surface-700 bg-surface-850">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left transition hover:bg-surface-800"
      >
        {open ? (
          <ChevronDown className="h-4 w-4 text-gray-500" />
        ) : (
          <ChevronRight className="h-4 w-4 text-gray-500" />
        )}
        <span className="text-[13px] font-medium text-gray-200">{title}</span>
        {subtitle && (
          <span className="ml-auto font-mono text-[11px] text-gray-500">
            {subtitle}
          </span>
        )}
      </button>
      {open && <div className="border-t border-surface-700 p-3">{<JsonBlock data={data} />}</div>}
    </div>
  )
}

export default function ChainCard({ flow }: { flow: FlowResponse }) {
  const c1 = flow.flow?.step_2_component_1
  const c2 = flow.flow?.step_3_component_2
  const c2Output = c2?.output ?? null
  const c1Latency =
    (c1?.output?.version2?.latency_ms as number | undefined) ?? null
  const version1 = c1?.output?.version1
  const errorDetail = flow.detail

  const c2Tone =
    !c2 || c2.status === 'skipped'
      ? 'slate'
      : c2.status === 'success'
        ? 'green'
        : c2.status === 'rejected'
          ? 'amber'
          : 'red'

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={c1?.status === 'success' ? 'green' : 'red'}>
          <span className="font-mono text-[10px]">C1</span> parse{' '}
          {c1?.status ?? 'error'}
        </Badge>
        <Badge tone={c2Tone}>
          <span className="font-mono text-[10px]">C2</span> planner{' '}
          {c2?.status ?? 'skipped'}
        </Badge>
        {c1Latency != null && (
          <Badge tone="slate">
            <span className="font-mono">⏱ {c1Latency}ms</span>
          </Badge>
        )}
        {c2?.latency_ms != null && (
          <Badge tone="slate">
            <span className="font-mono">⏱ {c2.latency_ms}ms</span>
          </Badge>
        )}
        {version1?.intent_contract?.tool_hint && (
          <Badge tone="green">
            <Terminal className="h-3 w-3" />
            {version1.intent_contract.tool_hint}
          </Badge>
        )}
      </div>

      {errorDetail && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
          {errorDetail}
        </div>
      )}

      {c2Output?.command && (
        <div className="overflow-hidden rounded-xl border border-surface-700 bg-surface-850">
          <div className="flex items-center gap-2 border-b border-surface-700 px-3 py-2">
            <Terminal className="h-4 w-4 text-accent-500" />
            <span className="text-[13px] font-medium text-gray-200">
              Validated command
            </span>
            <span className="ml-auto">
              <CopyButton text={c2Output.command} />
            </span>
          </div>
          <div className="px-3 py-3">
            <code className="block overflow-x-auto whitespace-pre-wrap break-all font-mono text-[13px] leading-relaxed text-emerald-300">
              {c2Output.command}
            </code>
            {c2Output.command_sequence && c2Output.command_sequence.length > 1 && (
              <div className="mt-2 flex flex-col gap-1">
                {c2Output.command_sequence.map((c, i) => (
                  <code
                    key={i}
                    className="font-mono text-[12px] text-gray-400"
                  >
                    {i + 1}. {c}
                  </code>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {c2?.reason && (
        <div className="rounded-lg border border-surface-700 bg-surface-850 px-3 py-2 text-sm text-gray-400">
          {c2.reason}
        </div>
      )}

      {c2Output && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {c2Output.tool && (
            <span className="text-gray-400">
              tool: <span className="font-mono text-gray-200">{c2Output.tool}</span>
            </span>
          )}
          {c2Output.estimated_duration && (
            <span className="text-gray-400">
              duration: <span className="text-gray-200">{c2Output.estimated_duration}</span>
            </span>
          )}
          {typeof c2Output.validation_passed === 'boolean' && (
            <span className="text-gray-400">
              validation:{' '}
              <span
                className={
                  c2Output.validation_passed
                    ? 'font-medium text-accent-500'
                    : 'font-medium text-red-300'
                }
              >
                {String(c2Output.validation_passed)}
              </span>
            </span>
          )}
          {c2Output.safety_flags && c2Output.safety_flags.length > 0 && (
            <span className="inline-flex items-center gap-1 text-amber-300">
              <ShieldAlert className="h-3 w-3" />
              {c2Output.safety_flags.join(', ')}
            </span>
          )}
        </div>
      )}

      <div className="flex flex-col gap-2">
        <Collapsible
          title="Component 02 · Planner output"
          subtitle={c2?.status ?? 'n/a'}
          data={c2Output ?? c2 ?? null}
        />
        {c1 && (
          <>
            <Collapsible
              title="Component 01 · version1 contract (C1 → C2 payload)"
              subtitle={version1?.session_id}
              data={version1 ?? null}
            />
            <Collapsible
              title="Component 01 · version2 (extended)"
              data={c1.output?.version2 ?? null}
            />
          </>
        )}
      </div>
    </div>
  )
}