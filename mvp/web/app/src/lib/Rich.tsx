// Rich chat answers: Cyanide's text as Markdown, then the tables, charts and figures the core attached as `blocks`.
// Everything here only shows data; a button that changes something is a SuggestionCard, which goes through the usual
// decision endpoints. Table cells and chart labels are plain text (they can hold attacker-chosen strings), and the
// Markdown renderer never runs HTML.
import { useId, useState } from 'react'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { AlertTriangle, Check, CheckCircle2, Copy, OctagonAlert, Table2, TrendingUp } from 'lucide-react'

export type Block =
  | { type: 'table'; title?: string; columns: string[]; rows: string[][]; link?: string }
  | { type: 'chart'; kind: 'bar' | 'line'; title?: string; labels: string[]; series: { name: string; values: number[] }[]; unit?: string }
  | { type: 'stats'; items: { label: string; value: string; tone?: string }[] }

/** Copies text and shows a tick for a moment. */
export function CopyButton({ text, label = 'Copy', className = '' }: { text: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false)
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500) } catch { /* no clipboard */ }
  }
  return (
    <button type="button" className={'rich-tool ' + className} onClick={() => void copy()} title={label} aria-label={label}>
      {done ? <Check size={14} aria-hidden /> : <Copy size={14} aria-hidden />}
      <span className="sr-only" role="status">{done ? 'Copied' : ''}</span>
    </button>
  )
}

export function Text({ md }: { md: string }) {
  return (
    <div className="rich-md leading-relaxed">
      <Markdown remarkPlugins={[remarkGfm]} components={{
        table: ({ children }) => <div className="rich-frame my-2 overflow-x-auto" tabIndex={0}><table className="rich-table">{children}</table></div>,
        a: ({ children, href }) => (href && /^https?:\/\//.test(href)
          ? <a href={href} target="_blank" rel="noreferrer noopener" className="underline">{children}</a>
          : <span className="underline">{children}</span>),
        code: ({ children, className }) => (className
          ? <code className="block overflow-x-auto rounded-md bg-surface-3 p-3 font-mono text-xs">{children}</code>
          : <code className="rounded bg-surface-3 px-1 font-mono text-[0.85em]">{children}</code>),
      }}>{md}</Markdown>
    </div>
  )
}

const TONE: Record<string, { cls: string; icon: typeof CheckCircle2; word: string }> = {
  green: { cls: 'text-ok', icon: CheckCircle2, word: 'fine' },
  amber: { cls: 'text-warn', icon: AlertTriangle, word: 'watch' },
  red: { cls: 'text-bad', icon: OctagonAlert, word: 'needs action' },
  critical: { cls: 'text-bad', icon: OctagonAlert, word: 'urgent' },
}

function Stats({ items }: { items: { label: string; value: string; tone?: string }[] }) {
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      {items.map((s) => {
        const t = TONE[s.tone ?? '']
        const Icon = t?.icon
        return (
          <div key={s.label} className="rich-frame p-3">
            <p className="text-xs text-muted">{s.label}</p>
            <p className="mt-0.5 flex items-center gap-1.5 text-xl font-semibold tabular-nums">
              {Icon && <Icon size={16} className={t.cls} aria-hidden />}{s.value}
              {t && <span className="sr-only">({t.word})</span>}
            </p>
          </div>)
      })}
    </div>
  )
}

const tsv = (cols: string[], rows: string[][]) => [cols, ...rows].map((r) => r.join('\t')).join('\n')

function Table({ b, onOpen }: { b: Extract<Block, { type: 'table' }>; onOpen?: (id: string) => void }) {
  return (
    <figure className="rich-frame overflow-hidden">
      <figcaption className="flex items-center gap-2 border-b border-line px-3 py-2 text-sm font-medium">
        <Table2 size={14} className="text-muted" aria-hidden />{b.title || 'Table'}
        <span className="text-xs font-normal text-muted">{b.rows.length} row{b.rows.length === 1 ? '' : 's'}</span>
        <CopyButton text={tsv(b.columns, b.rows)} label="Copy table (paste into a spreadsheet)" className="ml-auto" />
      </figcaption>
      <div className="max-h-96 overflow-auto" tabIndex={0}>
        <table className="rich-table">
          <thead><tr>{b.columns.map((c) => <th key={c} scope="col">{c}</th>)}</tr></thead>
          <tbody>
            {b.rows.map((r, i) => (
              <tr key={i}>{r.map((cell, j) => (
                <td key={j}>{j === 0 && b.link === 'incident' && onOpen
                  ? <button type="button" className="font-mono text-xs underline decoration-dotted underline-offset-2 hover:text-ink" title="Ask about this incident" onClick={() => onOpen(cell)}>{cell}</button>
                  : cell}</td>))}</tr>))}
          </tbody>
        </table>
      </div>
    </figure>
  )
}

// Categorical slots in fixed order (validated palette, dark and light steps); never cycled past three.
const SERIES = ['var(--series-1)', 'var(--series-2)', 'var(--series-3)']

function Chart({ b }: { b: Extract<Block, { type: 'chart' }> }) {
  const id = useId()
  const [hover, setHover] = useState<number | null>(null)
  const [asTable, setAsTable] = useState(false)
  const W = 640, H = 220, L = 36, R = 12, T = 12, B = 28
  const n = b.labels.length
  const max = Math.max(1, ...b.series.flatMap((s) => s.values))
  const nice = (() => { const p = 10 ** Math.floor(Math.log10(max)); const m = max / p; return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p })()
  const y = (v: number) => T + (H - T - B) * (1 - v / nice)
  const band = (W - L - R) / Math.max(1, n)
  const x = (i: number) => L + band * i + band / 2
  const whole = b.series.every((s) => s.values.every((v) => Number.isInteger(v)))
  const ticks = whole && !Number.isInteger(nice / 2) ? [0, nice] : [0, nice / 2, nice]
  const every = Math.ceil(n / 8)
  const fmt = (v: number) => (Number.isInteger(v) ? String(v) : v.toFixed(1))
  const rows = b.labels.map((l, i) => [l, ...b.series.map((s) => fmt(s.values[i] ?? 0))])
  const cols = ['', ...b.series.map((s) => s.name)]
  const barW = Math.max(2, Math.min(28, band / b.series.length - 2))
  return (
    <figure className="rich-frame overflow-hidden" aria-labelledby={id}>
      <figcaption id={id} className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2 text-sm font-medium">
        <TrendingUp size={14} className="text-muted" aria-hidden />{b.title || 'Chart'}
        {b.unit && <span className="text-xs font-normal text-muted">{b.unit}</span>}
        {b.series.length > 1 && (
          <span className="flex gap-3 text-xs font-normal text-soft">
            {b.series.map((s, k) => <span key={s.name} className="flex items-center gap-1"><i className="inline-block h-2 w-2 rounded-full" style={{ background: SERIES[k] }} />{s.name}</span>)}
          </span>)}
        <button type="button" className="rich-tool ml-auto text-xs" onClick={() => setAsTable((v) => !v)} aria-pressed={asTable}>{asTable ? 'Chart' : 'Table'}</button>
        <CopyButton text={tsv(cols, rows)} label="Copy the numbers" />
      </figcaption>
      {asTable ? (
        <div className="max-h-80 overflow-auto" tabIndex={0}>
          <table className="rich-table"><thead><tr>{cols.map((c, i) => <th key={i} scope="col">{c || 'When'}</th>)}</tr></thead>
            <tbody>{rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j} className={j ? 'tabular-nums' : ''}>{c}</td>)}</tr>)}</tbody></table>
        </div>
      ) : (
        <div className="relative px-1 pb-1">
          <svg viewBox={`0 0 ${W} ${H}`} className="block h-auto w-full" role="img" aria-label={`${b.title}: ${b.series.map((s) => `${s.name} from ${fmt(s.values[0] ?? 0)} to ${fmt(s.values[s.values.length - 1] ?? 0)}, highest ${fmt(Math.max(...s.values))}`).join('; ')}`}
            onMouseLeave={() => setHover(null)}>
            {ticks.map((t) => (
              <g key={t}>
                <line x1={L} x2={W - R} y1={y(t)} y2={y(t)} className={t === 0 ? 'rich-axis' : 'rich-grid'} />
                <text x={L - 6} y={y(t) + 4} textAnchor="end" className="rich-tick">{fmt(t)}</text>
              </g>))}
            {b.labels.map((l, i) => (i % every === 0 || i === n - 1) && l !== b.labels[i - every] && (
              <text key={i} x={x(i)} y={H - 8} textAnchor="middle" className="rich-tick">{l}</text>))}
            {hover !== null && b.kind === 'line' && <line x1={x(hover)} x2={x(hover)} y1={T} y2={H - B} className="rich-axis" />}
            {b.kind === 'bar'
              ? b.series.map((s, k) => s.values.map((v, i) => {
                const h = Math.max(0, y(0) - y(v)), bx = x(i) - (barW + 2) * b.series.length / 2 + k * (barW + 2) + 1
                const r = Math.min(4, h, barW / 2)
                return <path key={`${k}-${i}`} d={h < 0.5 ? '' : `M${bx},${y(0)} v${-(h - r)} q0,${-r} ${r},${-r} h${barW - 2 * r} q${r},0 ${r},${r} v${h - r} z`}
                  fill={SERIES[k]} opacity={hover === null || hover === i ? 1 : 0.45} />
              }))
              : b.series.map((s, k) => (
                <g key={k}>
                  <polyline fill="none" stroke={SERIES[k]} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round"
                    points={s.values.map((v, i) => `${x(i)},${y(v)}`).join(' ')} />
                  {hover !== null && <circle cx={x(hover)} cy={y(s.values[hover] ?? 0)} r={4} fill={SERIES[k]} stroke="var(--surface)" strokeWidth={2} />}
                </g>))}
            {b.labels.map((_, i) => (
              <rect key={i} x={x(i) - band / 2} y={T} width={band} height={H - T - B} fill="transparent" onMouseEnter={() => setHover(i)} />))}
          </svg>
          {hover !== null && (
            <div className="rich-tip" style={{ left: `${(x(hover) / W) * 100}%` }} role="status">
              <b className="block text-xs">{b.labels[hover]}</b>
              {b.series.map((s, k) => (
                <span key={k} className="flex items-center gap-1.5 text-xs">
                  <i className="inline-block h-2 w-2 rounded-full" style={{ background: SERIES[k] }} />{s.name}: <b className="tabular-nums">{fmt(s.values[hover] ?? 0)}</b>
                </span>))}
            </div>)}
        </div>)}
    </figure>
  )
}

/** The blocks under an answer. `onOpen` asks about an incident when its id is clicked in a table. */
export function Blocks({ blocks, onOpen }: { blocks?: Block[]; onOpen?: (id: string) => void }) {
  if (!blocks?.length) return null
  return (
    <div className="space-y-3">
      {blocks.map((b, i) => b.type === 'table' ? <Table key={i} b={b} onOpen={onOpen} />
        : b.type === 'chart' ? <Chart key={i} b={b} />
        : b.type === 'stats' ? <Stats key={i} items={b.items} /> : null)}
    </div>
  )
}
