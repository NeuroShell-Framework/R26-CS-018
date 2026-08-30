import { Fragment } from 'react'

const TOKEN =
  /("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*")\s*(:)?|(\b(?:true|false)\b)|(\bnull\b)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g

function highlight(line: string, lineNo: number) {
  const parts: Array<{
    text: string
    cls: string
  }> = []
  let last = 0
  let m: RegExpExecArray | null
  TOKEN.lastIndex = 0
  while ((m = TOKEN.exec(line)) !== null) {
    if (m.index > last) parts.push({ text: line.slice(last, m.index), cls: '' })
    let cls = 'text-slate-300'
    if (m[1]) cls = m[2] ? 'text-emerald-300' : 'text-amber-200'
    else if (m[3]) cls = 'text-sky-300'
    else if (m[4]) cls = 'text-rose-300'
    else if (m[5]) cls = 'text-violet-300'
    parts.push({ text: m[0], cls })
    last = m.index + m[0].length
  }
  if (last < line.length) parts.push({ text: line.slice(last), cls: '' })

  return (
    <div key={lineNo} className="flex">
      <span className="mr-4 w-6 shrink-0 select-none text-right text-gray-600">
        {lineNo}
      </span>
      <span className="whitespace-pre">
        {parts.map((p, i) =>
          p.cls ? (
            <span key={i} className={p.cls}>
              {p.text}
            </span>
          ) : (
            <Fragment key={i}>{p.text}</Fragment>
          ),
        )}
      </span>
    </div>
  )
}

export default function JsonBlock({ data }: { data: unknown }) {
  const text =
    typeof data === 'string'
      ? data
      : JSON.stringify(data, null, 2) ?? 'null'
  const lines = text.split('\n')
  return (
    <pre className="overflow-x-auto rounded-lg bg-black/40 p-3 font-mono text-[12.5px] leading-relaxed">
      {lines.map((line, i) => highlight(line, i + 1))}
    </pre>
  )
}