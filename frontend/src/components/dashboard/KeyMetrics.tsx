import { Activity, AlertTriangle, DollarSign, TrendingUp } from 'lucide-react'
import Card from '../common/Card'
import type { DashboardStatsExtended } from '../../types'

function Sparkline({ data }: { data: number[] }) {
  const max = Math.max(...data, 1)
  const barWidth = 100 / data.length
  return (
    <svg viewBox="0 0 100 24" className="w-full h-6" preserveAspectRatio="none">
      {data.map((value, i) => {
        const height = (value / max) * 20
        return (
          <rect
            key={i}
            x={i * barWidth + barWidth * 0.15}
            y={24 - height}
            width={barWidth * 0.7}
            height={Math.max(height, 1)}
            rx={1}
            className="fill-primary-500/60"
          />
        )
      })}
    </svg>
  )
}

interface KeyMetricsProps {
  stats: DashboardStatsExtended | null
}

export default function KeyMetrics({ stats }: KeyMetricsProps) {
  if (!stats) return null

  const opsRunning = (stats.operations?.running || 0) + (stats.scans.running || 0)
  const opsCompleted = (stats.operations?.completed || 0) + (stats.scans.completed || 0)
  const opsStopped = (stats.operations?.stopped || 0) + (stats.scans.stopped || 0) + (stats.scans.failed || 0)

  const severities = [
    { label: 'Crit', count: stats.vulnerabilities.critical, color: 'bg-red-500', text: 'text-red-400' },
    { label: 'High', count: stats.vulnerabilities.high, color: 'bg-orange-500', text: 'text-orange-400' },
    { label: 'Med', count: stats.vulnerabilities.medium, color: 'bg-yellow-500', text: 'text-yellow-400' },
    { label: 'Low', count: stats.vulnerabilities.low, color: 'bg-blue-500', text: 'text-blue-400' },
    { label: 'Info', count: stats.vulnerabilities.info, color: 'bg-gray-500', text: 'text-gray-400' },
  ]

  return (
    <Card title="Key Metrics">
      <div className="space-y-5">
        {/* Operations summary */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Activity className="w-4 h-4 text-dark-400" />
            <span className="text-xs text-dark-400 uppercase font-medium">Operations</span>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-center">
              <p className="text-lg font-bold text-green-400">{opsRunning}</p>
              <p className="text-[10px] text-dark-500">Running</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-bold text-emerald-400">{opsCompleted}</p>
              <p className="text-[10px] text-dark-500">Complete</p>
            </div>
            <div className="text-center">
              <p className="text-lg font-bold text-dark-400">{opsStopped}</p>
              <p className="text-[10px] text-dark-500">Stopped</p>
            </div>
          </div>
        </div>

        {/* Findings summary */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-dark-400" />
            <span className="text-xs text-dark-400 uppercase font-medium">
              Findings
              <span className="text-white ml-1">{stats.vulnerabilities.total}</span>
            </span>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {severities.filter(s => s.count > 0).map(s => (
              <span key={s.label} className={`flex items-center gap-1 text-xs ${s.text}`}>
                <span className={`w-2 h-2 rounded-full ${s.color}`} />
                {s.count} {s.label}
              </span>
            ))}
            {stats.vulnerabilities.total === 0 && (
              <span className="text-xs text-dark-500">No findings yet</span>
            )}
          </div>
        </div>

        {/* 7-day sparkline */}
        {stats.trend && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <TrendingUp className="w-4 h-4 text-dark-400" />
              <span className="text-xs text-dark-400 uppercase font-medium">
                7-Day Trend
                <span className="text-white ml-1">+{stats.trend.net_new_findings}</span>
              </span>
            </div>
            <Sparkline data={stats.trend.findings_by_day} />
          </div>
        )}

        {/* Cost */}
        {stats.trend && stats.trend.total_cost_usd > 0 && (
          <div>
            <div className="flex items-center gap-2">
              <DollarSign className="w-4 h-4 text-dark-400" />
              <span className="text-xs text-dark-400 uppercase font-medium">Total Cost</span>
              <span className="text-sm text-white font-medium ml-auto">${stats.trend.total_cost_usd.toFixed(2)}</span>
            </div>
          </div>
        )}
      </div>
    </Card>
  )
}
