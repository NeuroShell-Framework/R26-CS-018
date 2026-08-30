import { type ReactNode, useState } from 'react'
import {
  Bug,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  ShieldAlert,
  ShieldCheck,
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
  const c3 = flow.flow?.step_4_component_3
  const c4 = flow.flow?.step_5_component_4
  const c2Output = c2?.output ?? null
  const c3Output = c3?.output ?? null
  const c4Output = c4?.output ?? null
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

  const c3Tone =
    !c3 || c3.status === 'skipped'
      ? 'slate'
      : c3.status === 'success'
        ? 'green'
        : c3.status === 'recovered'
          ? 'amber'
          : c3.status === 'failed'
            ? 'amber'
            : 'red'

  const c4Tone =
    !c4 || c4.status !== 'success'
      ? 'slate'
      : (c4Output?.ranked_findings?.length ?? 0) > 0
        ? 'red'
        : 'green'

  const c4topTier = c4Output?.ranked_findings?.reduce<string | undefined>(
    (acc, f) => {
      if (!f.risk_tier) return acc
      if (f.risk_tier === 'CRITICAL') return 'CRITICAL'
      if (f.risk_tier === 'HIGH' && acc !== 'CRITICAL') return 'HIGH'
      if (f.risk_tier === 'MEDIUM' && !acc) return 'MEDIUM'
      if (f.risk_tier === 'LOW' && !acc) return 'LOW'
      return acc
    },
    undefined,
  )

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
        <Badge tone={c3Tone}>
          <span className="font-mono text-[10px]">C3</span> executor{' '}
          {c3?.status ?? 'skipped'}
        </Badge>
        <Badge tone={c4Tone}>
          <span className="font-mono text-[10px]">C4</span> analysis{' '}
          {c4?.status ?? 'skipped'}
        </Badge>
        {c4topTier && (
          <Badge tone={c4topTier === 'CRITICAL' || c4topTier === 'HIGH' ? 'red' : 'amber'}>
            <ShieldAlert className="h-3 w-3" />
            {c4topTier}
          </Badge>
        )}
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
        {c3?.latency_ms != null && (
          <Badge tone="slate">
            <span className="font-mono">⏱ {c3.latency_ms}ms</span>
          </Badge>
        )}
        {c4?.latency_ms != null && (
          <Badge tone="slate">
            <span className="font-mono">⏱ {c4.latency_ms}ms</span>
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

      {c3Output && c3Output.stdout && (
        <div className="overflow-hidden rounded-xl border border-surface-700 bg-surface-850">
          <div className="flex items-center gap-2 border-b border-surface-700 px-3 py-2">
            <Bug className="h-4 w-4 text-accent-500" />
            <span className="text-[13px] font-medium text-gray-200">
              Component 03 · Execution result
            </span>
            <span className="ml-auto flex items-center gap-2">
              <span
                className={`font-mono text-[11px] ${
                  c3Output.exit_code === 0
                    ? 'text-emerald-400'
                    : 'text-red-300'
                }`}
              >
                exit {c3Output.exit_code}
              </span>
              <CopyButton text={c3Output.stdout} />
            </span>
          </div>
          <div className="px-3 py-3">
            <code className="block overflow-x-auto whitespace-pre-wrap break-all font-mono text-[13px] leading-relaxed text-gray-300">
              {c3Output.stdout}
            </code>
            {c3Output.status === 'recovered' && (
              <div className="mt-2 flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-300">
                <ShieldAlert className="h-3 w-3" />
                Recovered after {c3Output.recovery_log?.length ?? 0} recovery
                attempt(s)
              </div>
            )}
            {c3Output.status === 'failed' && (
              <div className="mt-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
                <div className="font-medium">
                  {c3Output.failure_report?.final_error_class ?? 'FAILED'}
                </div>
                {c3Output.stderr && (
                  <pre className="mt-1 whitespace-pre-wrap font-mono text-[11px]">
                    {c3Output.stderr}
                  </pre>
                )}
                {c3Output.failure_report?.recommendation && (
                  <div className="mt-1 text-amber-300">
                    ↳ {c3Output.failure_report.recommendation}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {c4Output && (
        <div className="overflow-hidden rounded-xl border border-surface-700 bg-surface-850">
          <div className="flex items-center gap-2 border-b border-surface-700 px-3 py-2">
            <ShieldCheck className="h-4 w-4 text-accent-500" />
            <span className="text-[13px] font-medium text-gray-200">
              Component 04 · Vulnerability analysis
            </span>
            <span className="ml-auto font-mono text-[11px] text-gray-500">
              {c4Output.ranked_findings?.length ?? 0} finding(s){' '}
              {c4Output.false_positive_reduction_rate
                ? `· FP↓ ${c4Output.false_positive_reduction_rate.toFixed(0)}%`
                : ''}
            </span>
          </div>
          <div className="px-3 py-3">
            {(c4Output.ranked_findings?.length ?? 0) === 0 ? (
              <div className="flex items-center gap-2 text-sm text-gray-400">
                <Check className="h-4 w-4 text-emerald-400" />
                No exploitable vulnerabilities identified in this output.
              </div>
            ) : (
              <div className="flex flex-col gap-2">
                {c4Output.ranked_findings?.map((f, i) => (
                  <div
                    key={i}
                    className="rounded-lg border border-surface-700 bg-surface-800 px-3 py-2"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[12px] font-medium text-gray-200">
                        {f.cve_id}
                      </span>
                      {f.risk_tier && (
                        <Badge
                          tone={
                            f.risk_tier === 'CRITICAL' || f.risk_tier === 'HIGH'
                              ? 'red'
                              : 'amber'
                          }
                        >
                          {f.risk_tier}
                        </Badge>
                      )}
                      {typeof f.composite_risk_score === 'number' && (
                        <span className="ml-auto font-mono text-[11px] text-gray-400">
                          risk {f.composite_risk_score.toFixed(2)}
                        </span>
                      )}
                    </div>
                    {f.service_name && (
                      <div className="mt-1 text-xs text-gray-400">
                        {f.service_name}
                        {f.service_port ? ` · :${f.service_port}` : ''}
                      </div>
                    )}
                    {f.analysis_mode && (
                      <div className="mt-1 font-mono text-[10px] text-gray-500">
                        {f.analysis_mode}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="flex flex-col gap-2">
        <Collapsible
          title="Component 02 · Planner output"
          subtitle={c2?.status ?? 'n/a'}
          data={c2Output ?? c2 ?? null}
        />
        {c3 && (
          <Collapsible
            title="Component 03 · AEERE execution result"
            subtitle={c3?.status ?? 'n/a'}
            data={c3Output ?? c3 ?? null}
          />
        )}
        {c4 && (
          <Collapsible
            title="Component 04 · AVAE analysis output"
            subtitle={c4?.status ?? 'n/a'}
            data={c4Output ?? c4 ?? null}
          />
        )}
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