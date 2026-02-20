import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ChevronRight, RefreshCw, StopCircle, CheckCircle, XCircle,
  DollarSign, AlertTriangle, Clock, Footprints, ExternalLink,
  Pause, Play, Square,
} from 'lucide-react'
import Button from '../common/Button'
import MiniLogViewer from './MiniLogViewer'
import { agentV2Api } from '../../services/api'
import type { AgentV2OperationSummary } from '../../types'

const STATUS_STYLES: Record<string, string> = {
  running: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  paused: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  completed: 'bg-green-500/20 text-green-400 border-green-500/30',
  error: 'bg-red-500/20 text-red-400 border-red-500/30',
  cancelled: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  stopping: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  budget_exhausted: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
}

const PROGRESS_COLORS: Record<string, string> = {
  running: 'bg-blue-500',
  paused: 'bg-yellow-500',
  completed: 'bg-green-500',
  error: 'bg-red-500',
  cancelled: 'bg-orange-500',
  stopping: 'bg-orange-500',
  budget_exhausted: 'bg-yellow-500',
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-blue-500/20 text-blue-400',
  info: 'bg-dark-600/50 text-dark-300',
}

function getStatusIcon(status: string) {
  switch (status) {
    case 'running':
      return <RefreshCw className="w-4 h-4 animate-spin text-blue-400" />
    case 'paused':
      return <Pause className="w-4 h-4 text-yellow-400" />
    case 'completed':
      return <CheckCircle className="w-4 h-4 text-green-400" />
    case 'error':
      return <XCircle className="w-4 h-4 text-red-400" />
    case 'cancelled':
    case 'stopping':
      return <StopCircle className="w-4 h-4 text-orange-400" />
    case 'budget_exhausted':
      return <DollarSign className="w-4 h-4 text-yellow-400" />
    default:
      return <AlertTriangle className="w-4 h-4 text-dark-400" />
  }
}

function formatDuration(seconds?: number): string {
  if (!seconds) return '--'
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
}

function formatTimeAgo(dateStr?: string): string {
  if (!dateStr) return ''
  const diff = (Date.now() - new Date(dateStr).getTime()) / 1000
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

interface Props {
  operation: AgentV2OperationSummary
  isActive?: boolean
  onRefresh?: () => void
}

export default function OperationCard({ operation: op, isActive, onRefresh }: Props) {
  const navigate = useNavigate()
  const [expanded, setExpanded] = useState(false)
  const [actionLoading, setActionLoading] = useState('')

  const progressPct = op.max_steps > 0
    ? Math.min((op.steps_used / op.max_steps) * 100, 100)
    : 0

  const handleAction = async (action: 'stop' | 'pause' | 'resume') => {
    setActionLoading(action)
    try {
      if (action === 'stop') await agentV2Api.stop(op.operation_id)
      else if (action === 'pause') await agentV2Api.pause(op.operation_id)
      else if (action === 'resume') await agentV2Api.resume(op.operation_id)
      onRefresh?.()
    } catch (err) {
      console.error(`Failed to ${action}:`, err)
    } finally {
      setActionLoading('')
    }
  }

  return (
    <div className="bg-dark-900/50 rounded-lg border border-dark-700 hover:border-dark-600 transition-colors overflow-hidden">
      {/* Header Row — always visible */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-dark-900 transition-colors"
      >
        <ChevronRight
          className={`w-4 h-4 text-dark-500 flex-shrink-0 transition-transform duration-200 ${
            expanded ? 'rotate-90' : ''
          }`}
        />
        <div className="flex-shrink-0">{getStatusIcon(op.status)}</div>

        <div className="flex-1 min-w-0">
          <p className="text-white font-medium truncate text-sm">{op.target}</p>
        </div>

        <span
          className={`text-xs px-2.5 py-1 rounded-full font-medium border flex-shrink-0 ${
            STATUS_STYLES[op.status] || 'bg-dark-700 text-dark-300 border-dark-600'
          }`}
        >
          {op.status}
        </span>

        {op.findings_count > 0 && (
          <span className="text-xs px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-400 border border-purple-500/30 flex-shrink-0">
            {op.findings_count} finding{op.findings_count !== 1 ? 's' : ''}
          </span>
        )}
      </button>

      {/* Meta Row */}
      <div className="flex items-center gap-4 px-4 pb-2 text-xs text-dark-500">
        {op.started_at && (
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            {isActive ? formatTimeAgo(op.started_at) : formatDuration(op.duration_seconds)}
          </span>
        )}
        <span className="flex items-center gap-1">
          <Footprints className="w-3 h-3" />
          {op.steps_used}/{op.max_steps}
        </span>
        {op.cost_usd !== undefined && op.cost_usd > 0 && (
          <span className="flex items-center gap-1">
            <DollarSign className="w-3 h-3" />
            ${op.cost_usd.toFixed(2)}
          </span>
        )}
      </div>

      {/* Progress Bar */}
      {isActive && (
        <div className="px-4 pb-3">
          <div className="h-1.5 bg-dark-800 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                PROGRESS_COLORS[op.status] || 'bg-primary-500'
              } ${op.status === 'running' ? 'animate-pulse' : ''}`}
              style={{ width: `${progressPct}%` }}
            />
          </div>
        </div>
      )}

      {/* Expanded Section */}
      {expanded && (
        <div className="px-4 pb-4 pt-1 border-t border-dark-700 space-y-3">
          {/* Objective */}
          {op.objective && (
            <p className="text-sm text-dark-300">{op.objective}</p>
          )}

          {/* Severity Pills */}
          {op.severity_breakdown && Object.keys(op.severity_breakdown).length > 0 && (
            <div className="flex gap-2 flex-wrap">
              {Object.entries(op.severity_breakdown).map(([sev, count]) =>
                count > 0 ? (
                  <span
                    key={sev}
                    className={`text-xs px-2 py-0.5 rounded-full ${SEVERITY_STYLES[sev] || 'bg-dark-600 text-dark-300'}`}
                  >
                    {count} {sev}
                  </span>
                ) : null
              )}
            </div>
          )}

          {/* Mini Logs (active only) */}
          {isActive && <MiniLogViewer operationId={op.operation_id} />}

          {/* Actions */}
          <div className="flex gap-2 pt-1">
            <Button
              size="sm"
              variant="secondary"
              onClick={() => navigate(`/agent/${op.operation_id}`)}
            >
              <ExternalLink className="w-3.5 h-3.5 mr-1.5" />
              View Details
            </Button>

            {isActive && op.status === 'running' && (
              <>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => handleAction('pause')}
                  isLoading={actionLoading === 'pause'}
                >
                  <Pause className="w-3.5 h-3.5 mr-1.5" />
                  Pause
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => handleAction('stop')}
                  isLoading={actionLoading === 'stop'}
                  className="text-red-400 hover:text-red-300"
                >
                  <Square className="w-3.5 h-3.5 mr-1.5" />
                  Stop
                </Button>
              </>
            )}

            {isActive && op.status === 'paused' && (
              <Button
                size="sm"
                variant="secondary"
                onClick={() => handleAction('resume')}
                isLoading={actionLoading === 'resume'}
              >
                <Play className="w-3.5 h-3.5 mr-1.5" />
                Resume
              </Button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
