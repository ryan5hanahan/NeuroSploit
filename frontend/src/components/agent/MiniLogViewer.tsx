import { useState, useEffect, useRef } from 'react'
import { ChevronDown, ChevronUp, Terminal } from 'lucide-react'
import { useOperationStore } from '../../store'

const LOG_LEVEL_STYLES: Record<string, string> = {
  info: 'text-blue-400',
  tool: 'text-cyan-400',
  finding: 'text-green-400',
  error: 'text-red-400',
  warn: 'text-yellow-400',
  reasoning: 'text-purple-400',
}

const LOG_LEVELS = ['all', 'tool', 'finding', 'reasoning', 'error'] as const

interface Props {
  operationId: string
  maxLines?: number
}

export default function MiniLogViewer({ operationId, maxLines = 20 }: Props) {
  const [collapsed, setCollapsed] = useState(true)
  const [levelFilter, setLevelFilter] = useState<string>('all')
  const bottomRef = useRef<HTMLDivElement>(null)
  const { steps } = useOperationStore()

  // Derive log lines from steps
  const logLines = steps
    .filter((s) => s.operation_id === operationId || !s.operation_id)
    .slice(-50)
    .map((step) => {
      if (step.is_error) {
        return { level: 'error', text: `Step ${step.step}: ${step.tool} failed (${step.duration_ms}ms)` }
      }
      if (step.findings_count > 0) {
        return { level: 'finding', text: `Step ${step.step}: ${step.tool} — ${step.findings_count} finding(s) (${step.duration_ms}ms)` }
      }
      return { level: 'tool', text: `Step ${step.step}: ${step.tool} (${step.duration_ms}ms)` }
    })

  const filtered = levelFilter === 'all'
    ? logLines.slice(-maxLines)
    : logLines.filter((l) => l.level === levelFilter).slice(-maxLines)

  // Auto-scroll
  useEffect(() => {
    if (!collapsed && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [filtered.length, collapsed])

  return (
    <div className="border border-dark-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="w-full flex items-center justify-between px-3 py-2 bg-dark-900/50 hover:bg-dark-900 transition-colors"
      >
        <span className="flex items-center gap-2 text-xs font-medium text-dark-400">
          <Terminal className="w-3.5 h-3.5" />
          Live Logs
          <span className="text-dark-600">({logLines.length})</span>
        </span>
        {collapsed ? (
          <ChevronDown className="w-3.5 h-3.5 text-dark-500" />
        ) : (
          <ChevronUp className="w-3.5 h-3.5 text-dark-500" />
        )}
      </button>

      {!collapsed && (
        <>
          {/* Level Filter */}
          <div className="flex gap-1 px-3 py-1.5 border-t border-dark-700 bg-dark-900/30">
            {LOG_LEVELS.map((lvl) => (
              <button
                key={lvl}
                onClick={() => setLevelFilter(lvl)}
                className={`text-xs px-2 py-0.5 rounded transition-colors ${
                  levelFilter === lvl
                    ? 'bg-purple-500/20 text-purple-400'
                    : 'text-dark-500 hover:text-dark-300'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>

          {/* Log Content */}
          <div className="max-h-48 overflow-auto px-3 py-2 font-mono text-xs space-y-0.5 bg-dark-950">
            {filtered.length === 0 ? (
              <p className="text-dark-600 text-center py-2">No log entries</p>
            ) : (
              filtered.map((line, i) => (
                <div key={i} className="flex gap-2">
                  <span className={`flex-shrink-0 w-16 ${LOG_LEVEL_STYLES[line.level] || 'text-dark-500'}`}>
                    [{line.level}]
                  </span>
                  <span className="text-dark-300 break-all">{line.text}</span>
                </div>
              ))
            )}
            <div ref={bottomRef} />
          </div>
        </>
      )}
    </div>
  )
}
