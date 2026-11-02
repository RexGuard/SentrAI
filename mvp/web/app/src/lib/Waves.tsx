// The glowing ribbons behind the console (from Erick's reference picture): each ribbon is a bundle of thin light
// lines with a soft blurred copy under it. Purely decorative, fixed behind everything, never takes clicks.
import { memo } from 'react'

type Ribbon = { id: string; d: (k: number) => string; from: string; to: string; lines: number; width: number }

// Each path is drawn `lines` times with k from 0 to 1, so the curves fan out a little, like a light ribbon.
const RIBBONS: Ribbon[] = [
  { id: 'tl', from: 'var(--ribbon-1)', to: 'var(--ribbon-2)', lines: 16, width: 1.1,
    d: (k) => `M -60 ${150 + k * 30} C 120 ${170 + k * 20}, 220 ${90 - k * 40}, 330 ${-20 - k * 30}` },
  { id: 'tr', from: 'var(--ribbon-1)', to: 'var(--ribbon-2)', lines: 22, width: 1.2,
    d: (k) => `M 760 ${150 + k * 30} C 940 ${70 - k * 50}, 1060 ${200 + k * 40}, 1180 ${150 - k * 10} S 1290 ${60 - k * 30}, 1360 ${20 - k * 50}` },
  { id: 'bl', from: 'var(--ribbon-1)', to: 'var(--ribbon-2)', lines: 24, width: 1.3,
    d: (k) => `M -80 ${600 + k * 40} C 140 ${560 - k * 30}, 360 ${640 + k * 30}, 560 ${690 + k * 10} S 900 ${700 - k * 20}, 1360 ${640 + k * 50}` },
  { id: 'br', from: 'var(--ribbon-2)', to: 'var(--ribbon-1)', lines: 14, width: 1,
    d: (k) => `M 700 ${760} C 900 ${680 - k * 30}, 1100 ${690 + k * 20}, 1360 ${600 - k * 40}` },
]

function Waves() {
  return (
    <svg className="console-waves" viewBox="0 0 1280 720" preserveAspectRatio="none" aria-hidden focusable="false">
      <defs>
        {RIBBONS.map((r) => (
          <linearGradient key={r.id} id={`rb-${r.id}`} x1="0" x2="1" y1="0" y2="0">
            <stop offset="0" style={{ stopColor: r.from, stopOpacity: 0 }} />
            <stop offset=".35" style={{ stopColor: r.from }} />
            <stop offset=".75" style={{ stopColor: r.to }} />
            <stop offset="1" style={{ stopColor: r.to, stopOpacity: 0.2 }} />
          </linearGradient>))}
        <filter id="rb-glow" x="-10%" y="-30%" width="120%" height="160%"><feGaussianBlur stdDeviation="14" /></filter>
      </defs>
      {RIBBONS.map((r) => {
        const ks = Array.from({ length: r.lines }, (_, i) => i / (r.lines - 1))
        return (
          <g key={r.id} fill="none" stroke={`url(#rb-${r.id})`}>
            <path d={r.d(0.5)} strokeWidth={60} filter="url(#rb-glow)" className="console-wave-glow" />
            {ks.map((k) => <path key={k} d={r.d(k)} strokeWidth={r.width} className="console-wave-line" />)}
          </g>)
      })}
    </svg>
  )
}

export default memo(Waves)
