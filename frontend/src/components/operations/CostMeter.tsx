import type { AgentV2CostReport } from '../../types'

interface CostMeterProps {
  cost: AgentV2CostReport | null
}

const TIER_COLORS: Record<string, string> = {
  fast: 'bg-green-500',
  balanced: 'bg-blue-500',
  deep: 'bg-purple-500',
}

const TIER_LABELS: Record<string, string> = {
  fast: 'Fast',
  balanced: 'Balanced',
  deep: 'Deep',
}

export default function CostMeter({ cost }: CostMeterProps) {
  if (!cost) {
    return (
      <div className="text-center py-6 text-dark-400 text-sm">
        No cost data yet
      </div>
    )
  }

  const pct = Math.min(cost.budget_pct_used, 100)
  const barColor =
    pct >= 80 ? 'bg-red-500' : pct >= 50 ? 'bg-yellow-500' : 'bg-green-500'

  // Tier segments
  const tierEntries = Object.entries(cost.tiers || {}).filter(
    ([, t]) => t.calls > 0
  )
  const totalCalls = tierEntries.reduce((sum, [, t]) => sum + t.calls, 0)

  return (
    <div className="space-y-3">
      {/* Budget progress */}
      <div>
        <div className="flex items-center justify-between text-sm mb-1">
          <span className="text-dark-300">Budget Used</span>
          <span className="text-white font-medium">
            ${cost.total_cost_usd.toFixed(4)} / ${cost.budget_usd.toFixed(2)}
          </span>
        </div>
        <div className="h-2.5 bg-dark-900 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-300 ${barColor}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        <p className="text-xs text-dark-500 mt-1">{pct.toFixed(1)}% used</p>
      </div>

      {/* Tier breakdown */}
      {tierEntries.length > 0 && (
        <div>
          <p className="text-xs text-dark-400 mb-1.5">Tier Breakdown</p>
          <div className="h-2 bg-dark-900 rounded-full overflow-hidden flex">
            {tierEntries.map(([tier, data]) => (
              <div
                key={tier}
                className={`h-full ${TIER_COLORS[tier] || 'bg-dark-600'}`}
                style={{ width: `${(data.calls / totalCalls) * 100}%` }}
                title={`${TIER_LABELS[tier] || tier}: ${data.calls} calls`}
              />
            ))}
          </div>
          <div className="flex flex-wrap gap-3 mt-2">
            {tierEntries.map(([tier, data]) => (
              <div key={tier} className="flex items-center gap-1.5 text-xs">
                <span
                  className={`w-2 h-2 rounded-full ${
                    TIER_COLORS[tier] || 'bg-dark-600'
                  }`}
                />
                <span className="text-dark-400">
                  {TIER_LABELS[tier] || tier}
                </span>
                <span className="text-dark-300">{data.calls} calls</span>
                <span className="text-dark-500">
                  ${data.cost_usd.toFixed(4)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Token counts */}
      <div className="flex gap-4 text-xs text-dark-500">
        <span>
          Input: {(cost.total_input_tokens / 1000).toFixed(1)}k tokens
        </span>
        <span>
          Output: {(cost.total_output_tokens / 1000).toFixed(1)}k tokens
        </span>
      </div>
    </div>
  )
}
