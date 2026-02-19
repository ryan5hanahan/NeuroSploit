import {
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'
import type { AgentV2QualityEvaluation } from '../../types'

interface QualityScorecardProps {
  evaluation: AgentV2QualityEvaluation | null
}

const DIMENSION_LABELS: Record<string, string> = {
  coverage: 'Coverage',
  efficiency: 'Efficiency',
  evidence_quality: 'Evidence',
  methodology: 'Methodology',
  reporting: 'Reporting',
}

function ScoreBadge({ score }: { score: number }) {
  const color =
    score >= 70
      ? 'bg-green-500/20 text-green-400 border-green-500/30'
      : score >= 40
      ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
      : 'bg-red-500/20 text-red-400 border-red-500/30'

  return (
    <div className="text-center">
      <span
        className={`inline-flex items-center justify-center w-16 h-16 rounded-full text-2xl font-bold border-2 ${color}`}
      >
        {Math.round(score)}
      </span>
      <p className="text-xs text-dark-400 mt-1">Overall Score</p>
    </div>
  )
}

export default function QualityScorecard({ evaluation }: QualityScorecardProps) {
  if (!evaluation) {
    return (
      <div className="text-center py-6 text-dark-400 text-sm">
        Available after completion
      </div>
    )
  }

  const radarData = Object.entries(evaluation.dimensions).map(
    ([key, value]) => ({
      dimension: DIMENSION_LABELS[key] || key,
      score: value,
      fullMark: 100,
    })
  )

  return (
    <div className="space-y-4">
      {/* Overall score */}
      <ScoreBadge score={evaluation.overall_score} />

      {/* Radar chart */}
      <div className="w-full h-52">
        <ResponsiveContainer width="100%" height="100%">
          <RadarChart data={radarData} cx="50%" cy="50%" outerRadius="70%">
            <PolarGrid stroke="#334155" />
            <PolarAngleAxis
              dataKey="dimension"
              tick={{ fill: '#94a3b8', fontSize: 11 }}
            />
            <PolarRadiusAxis
              angle={90}
              domain={[0, 100]}
              tick={{ fill: '#64748b', fontSize: 10 }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                borderRadius: '8px',
                color: '#e2e8f0',
                fontSize: 12,
              }}
              formatter={(value: number) => [`${value.toFixed(1)}`, 'Score']}
            />
            <Radar
              dataKey="score"
              stroke="#8b5cf6"
              fill="#8b5cf6"
              fillOpacity={0.25}
              strokeWidth={2}
            />
          </RadarChart>
        </ResponsiveContainer>
      </div>

      {/* Dimension bars */}
      <div className="space-y-2">
        {Object.entries(evaluation.dimensions).map(([key, value]) => {
          const barColor =
            value >= 70
              ? 'bg-green-500'
              : value >= 40
              ? 'bg-yellow-500'
              : 'bg-red-500'
          return (
            <div key={key}>
              <div className="flex items-center justify-between text-xs mb-0.5">
                <span className="text-dark-400">
                  {DIMENSION_LABELS[key] || key}
                </span>
                <span className="text-dark-300 font-medium">
                  {value.toFixed(1)}
                </span>
              </div>
              <div className="h-1.5 bg-dark-900 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${barColor}`}
                  style={{ width: `${Math.min(value, 100)}%` }}
                />
              </div>
            </div>
          )
        })}
      </div>

      {/* Notes */}
      {evaluation.notes && evaluation.notes.length > 0 && (
        <div>
          <p className="text-xs font-medium text-dark-400 mb-1">Notes</p>
          <ul className="space-y-0.5">
            {evaluation.notes.map((note, i) => (
              <li key={i} className="text-xs text-dark-500 flex items-start gap-1">
                <span className="mt-0.5 text-dark-600">&bull;</span>
                {note}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
