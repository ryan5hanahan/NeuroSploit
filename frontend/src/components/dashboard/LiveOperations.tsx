import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, RefreshCw, BrainCircuit, Clock, Plus } from 'lucide-react'
import Card from '../common/Card'
import { dashboardApi } from '../../services/api'
import type { LiveOperation } from '../../types'

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
}

function StatusDot({ status }: { status: string }) {
  if (status === 'running') {
    return <span className="relative flex h-2.5 w-2.5">
      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
      <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500" />
    </span>
  }
  if (status === 'completed') return <span className="inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
  if (status === 'error' || status === 'failed') return <span className="inline-flex rounded-full h-2.5 w-2.5 bg-red-500" />
  if (status === 'stopped') return <span className="inline-flex rounded-full h-2.5 w-2.5 bg-yellow-500" />
  return <span className="inline-flex rounded-full h-2.5 w-2.5 bg-dark-500" />
}

function SeverityDots({ breakdown }: { breakdown: LiveOperation['severity_breakdown'] }) {
  const dots: { color: string; count: number; label: string }[] = [
    { color: 'bg-red-500', count: breakdown.critical, label: 'C' },
    { color: 'bg-orange-500', count: breakdown.high, label: 'H' },
    { color: 'bg-yellow-500', count: breakdown.medium, label: 'M' },
    { color: 'bg-blue-500', count: breakdown.low, label: 'L' },
  ]
  const visible = dots.filter(d => d.count > 0)
  if (visible.length === 0) return null
  return (
    <div className="flex items-center gap-1">
      {visible.map(d => (
        <span key={d.label} className={`${d.color} text-white text-[10px] font-bold rounded-full w-5 h-5 flex items-center justify-center`}>
          {d.count}
        </span>
      ))}
    </div>
  )
}

export default function LiveOperations() {
  const [operations, setOperations] = useState<LiveOperation[]>([])
  const [loading, setLoading] = useState(true)

  const fetchData = useCallback(async () => {
    try {
      const data = await dashboardApi.getLiveOperations(5)
      setOperations(data.operations)
    } catch (err) {
      console.error('Failed to fetch live operations:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const hasRunning = operations.some(op => op.status === 'running')
    const interval = setInterval(fetchData, hasRunning ? 5000 : 30000)
    return () => clearInterval(interval)
  }, [fetchData, operations])

  return (
    <Card
      title="Live Operations"
      action={
        <Link to="/agent" className="text-sm text-primary-500 hover:text-primary-400 flex items-center gap-1">
          View All <ArrowRight className="w-4 h-4" />
        </Link>
      }
    >
      {loading ? (
        <div className="flex items-center justify-center py-8">
          <RefreshCw className="w-5 h-5 animate-spin text-dark-400" />
        </div>
      ) : operations.length === 0 ? (
        <div className="text-center py-8">
          <BrainCircuit className="w-8 h-8 text-dark-500 mx-auto mb-2" />
          <p className="text-dark-400 text-sm">No recent operations</p>
          <Link to="/agent" className="inline-flex items-center gap-1 text-sm text-primary-500 hover:text-primary-400 mt-2">
            <Plus className="w-4 h-4" /> Start an operation
          </Link>
        </div>
      ) : (
        <div className="space-y-2">
          {operations.map((op) => (
            <Link
              key={`${op.type}-${op.id}`}
              to={op.type === 'agent' ? `/agent/${op.id}` : `/scan/${op.id}`}
              className="block p-3 bg-dark-900/50 rounded-lg hover:bg-dark-900 transition-colors"
            >
              <div className="flex items-center gap-3">
                <StatusDot status={op.status} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-white truncate">{op.target}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium uppercase ${
                      op.type === 'agent' ? 'bg-purple-500/20 text-purple-400' : 'bg-blue-500/20 text-blue-400'
                    }`}>
                      {op.type}
                    </span>
                  </div>
                  <p className="text-xs text-dark-400 truncate">{op.objective}</p>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <SeverityDots breakdown={op.severity_breakdown} />
                  {op.findings_count > 0 && (
                    <span className="text-xs text-dark-300">{op.findings_count} findings</span>
                  )}
                  <span className="text-xs text-dark-500 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {formatDuration(op.duration_seconds)}
                  </span>
                </div>
              </div>
              {/* Progress bar */}
              {op.status === 'running' && (
                <div className="mt-2 h-1 bg-dark-700 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary-500 rounded-full transition-all duration-500"
                    style={{ width: `${op.progress}%` }}
                  />
                </div>
              )}
            </Link>
          ))}
        </div>
      )}
    </Card>
  )
}
