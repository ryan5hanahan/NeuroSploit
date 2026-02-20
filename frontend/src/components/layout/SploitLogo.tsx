import { useThemeStore } from '../../store/theme'

export default function SploitLogo({ className = '' }: { className?: string }) {
  const theme = useThemeStore((s) => s.theme)

  if (theme === 'terminal') {
    return (
      <svg viewBox="0 0 520 140" className={className} xmlns="http://www.w3.org/2000/svg">
        <rect
          x="10" y="10" width="500" height="120" rx="6"
          className="stroke-primary-500" strokeWidth="2" fill="none" opacity={0.4}
        />
        {/* Glitch layers */}
        <text x="58" y="82" fontFamily="'Courier New', monospace" fontSize={54}
              fill="#FF0040" opacity={0.6}>sploit.ai</text>
        <text x="62" y="78" fontFamily="'Courier New', monospace" fontSize={54}
              className="fill-primary-400" opacity={0.6}>sploit.ai</text>
        {/* Main text */}
        <text x="60" y="80" fontFamily="'Courier New', monospace" fontSize={54}
              className="fill-primary-500">sploit.ai</text>
        {/* Cursor */}
        <rect x="365" y="90" width="18" height="6" className="fill-primary-500">
          <animate attributeName="opacity" values="1;0;1" dur="1.2s" repeatCount="indefinite" />
        </rect>
      </svg>
    )
  }

  // Midnight + Cyber: shield mark + circuit + wordmark
  return (
    <svg viewBox="0 0 520 140" className={className} xmlns="http://www.w3.org/2000/svg">
      {/* Shield mark */}
      <polygon
        className="stroke-primary-500"
        strokeWidth={2} fill="none" opacity={0.8}
        points="40,25 80,25 95,45 95,75 60,110 25,75 25,45"
      />
      {/* Circuit line */}
      <line x1={95} y1={65} x2={130} y2={65} className="stroke-primary-500" strokeWidth={2} />
      <circle cx={130} cy={65} r={4} className="fill-primary-500" />
      {/* Wordmark */}
      <text x={150} y={82} fontFamily="'Courier New', monospace" fontSize={52}
            letterSpacing={1} className="fill-white">
        sploit<tspan className="fill-primary-500">.ai</tspan>
      </text>
    </svg>
  )
}
