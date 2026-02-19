import { CheckCircle, Circle, Loader2, Slash } from 'lucide-react'
import type { AgentV2PlanPhase } from '../../types'

interface PlanTimelineProps {
  planText: string | null
  planPhases: AgentV2PlanPhase[] | null
  confidence: number
}

const STATUS_ICONS: Record<string, React.ReactNode> = {
  pending: <Circle className="w-4 h-4 text-dark-500" />,
  active: <Loader2 className="w-4 h-4 text-primary-400 animate-spin" />,
  in_progress: <Loader2 className="w-4 h-4 text-primary-400 animate-spin" />,
  completed: <CheckCircle className="w-4 h-4 text-green-400" />,
  skipped: <Slash className="w-4 h-4 text-dark-500" />,
}

function ConfidenceBadge({ value }: { value: number }) {
  const color =
    value >= 70
      ? 'bg-green-500/20 text-green-400 border-green-500/30'
      : value >= 40
      ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
      : 'bg-red-500/20 text-red-400 border-red-500/30'

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${color}`}
    >
      Confidence: {value}
    </span>
  )
}

export default function PlanTimeline({
  planText,
  planPhases,
  confidence,
}: PlanTimelineProps) {
  // Structured phases view
  if (planPhases && planPhases.length > 0) {
    return (
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <p className="text-sm font-medium text-dark-300">Operation Plan</p>
          <ConfidenceBadge value={confidence} />
        </div>

        <div className="relative ml-2">
          {/* Vertical line */}
          <div className="absolute left-[7px] top-2 bottom-2 w-0.5 bg-dark-700" />

          <div className="space-y-3">
            {planPhases.map((phase, idx) => {
              const isActive =
                phase.status === 'active' || phase.status === 'in_progress'
              return (
                <div
                  key={idx}
                  className={`relative pl-7 ${
                    isActive ? 'border-l-2 border-primary-500 ml-[6px] pl-5' : ''
                  }`}
                >
                  {/* Status icon */}
                  <div className="absolute left-0 top-0.5">
                    {STATUS_ICONS[phase.status] || STATUS_ICONS.pending}
                  </div>

                  <div>
                    <p
                      className={`text-sm font-medium ${
                        isActive
                          ? 'text-primary-400'
                          : phase.status === 'completed'
                          ? 'text-green-400'
                          : 'text-dark-300'
                      }`}
                    >
                      {phase.name}
                    </p>

                    {/* Objectives checklist */}
                    {phase.objectives && phase.objectives.length > 0 && (
                      <ul className="mt-1 space-y-0.5">
                        {phase.objectives.map((obj, oi) => {
                          const done = (
                            phase.completed_objectives || []
                          ).includes(obj)
                          return (
                            <li
                              key={oi}
                              className={`text-xs flex items-start gap-1.5 ${
                                done ? 'text-dark-500 line-through' : 'text-dark-400'
                              }`}
                            >
                              <span className="mt-0.5">
                                {done ? (
                                  <CheckCircle className="w-3 h-3 text-green-500" />
                                ) : (
                                  <Circle className="w-3 h-3 text-dark-600" />
                                )}
                              </span>
                              {obj}
                            </li>
                          )
                        })}
                      </ul>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    )
  }

  // Fallback: plain text
  if (planText) {
    return (
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <p className="text-sm font-medium text-dark-300">Plan Snapshot</p>
          <ConfidenceBadge value={confidence} />
        </div>
        <pre className="text-xs text-dark-400 bg-dark-900 rounded-lg p-3 overflow-auto max-h-48 whitespace-pre-wrap font-mono">
          {planText}
        </pre>
      </div>
    )
  }

  return (
    <div className="text-center py-6 text-dark-400 text-sm">
      No plan data yet
    </div>
  )
}
