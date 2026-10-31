/** A number card for the top of a page: label, big figure, one line of context. `hot` marks something that needs a look
 *  with a dot and a word for screen readers as well as the colour (meaning is never colour-only). */
export default function Stat({ label, value, note, hot, tone = 'warn' }: {
  label: string; value: string | number; note: string; hot?: boolean; tone?: 'warn' | 'bad'
}) {
  return (
    <div className="stat rounded-xl border border-line bg-surface p-4">
      <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-muted">
        {label}
        {hot && <><span className={'stat-dot ml-auto ' + (tone === 'bad' ? 'bg-bad' : 'bg-warn')} aria-hidden /><span className="sr-only">needs a look</span></>}
      </p>
      <p className={'mt-1 text-2xl font-semibold tabular-nums ' + (hot ? (tone === 'bad' ? 'text-bad' : 'text-warn') : '')}>{value}</p>
      <p className="mt-0.5 text-xs text-muted">{note}</p>
    </div>
  )
}
