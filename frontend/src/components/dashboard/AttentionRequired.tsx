import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { CheckCircle, X, Clock } from 'lucide-react'
import Card from '../common/Card'
import { SeverityBadge } from '../common/Badge'
import { dashboardApi } from '../../services/api'
import type { AttentionFinding } from '../../types'

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

export default function AttentionRequired() {
  const [findings, setFindings] = useState<AttentionFinding[]>([])
  const [totalUnreviewed, setTotalUnreviewed] = useState(0)
  const [loading, setLoading] = useState(true)
  const [dismissing, setDismissing] = useState<string | null>(null)

  const fetchData = useCallback(async () => {
    try {
      const data = await dashboardApi.getAttention(10)
      setFindings(data.findings)
      setTotalUnreviewed(data.total_unreviewed)
    } catch (err) {
      console.error('Failed to fetch attention items:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const handleDismiss = async (vulnId: string) => {
    setDismissing(vulnId)
    try {
      await dashboardApi.dismissFinding(vulnId)
      setFindings(prev => prev.filter(f => f.id !== vulnId))
      setTotalUnreviewed(prev => Math.max(0, prev - 1))
    } catch (err) {
      console.error('Failed to dismiss finding:', err)
    } finally {
      setDismissing(null)
    }
  }

  if (loading) return null

  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          Attention Required
          {totalUnreviewed > 0 && (
            <span className="bg-red-500/20 text-red-400 text-xs px-2 py-0.5 rounded-full font-medium">
              {totalUnreviewed}
            </span>
          )}
        </span>
      }
    >
      {findings.length === 0 ? (
        <div className="text-center py-6">
          <CheckCircle className="w-8 h-8 text-green-500 mx-auto mb-2" />
          <p className="text-green-400 text-sm font-medium">All findings reviewed</p>
          <p className="text-dark-500 text-xs mt-1">No critical or high findings need attention</p>
        </div>
      ) : (
        <div className="space-y-1">
          {findings.map((finding) => (
            <div
              key={finding.id}
              className="flex items-center gap-3 p-2.5 bg-dark-900/50 rounded-lg hover:bg-dark-900 transition-colors group"
            >
              <SeverityBadge severity={finding.severity} />
              <div className="flex-1 min-w-0">
                <Link
                  to={`/scan/${finding.scan_id}`}
                  className="font-medium text-white text-sm truncate block hover:text-primary-400"
                >
                  {finding.title}
                </Link>
                <p className="text-xs text-dark-500 truncate">
                  {finding.target || finding.endpoint}
                </p>
              </div>
              <span className="text-xs text-dark-500 flex items-center gap-1 flex-shrink-0">
                <Clock className="w-3 h-3" />
                {timeAgo(finding.created_at)}
              </span>
              <button
                onClick={(e) => { e.preventDefault(); handleDismiss(finding.id) }}
                disabled={dismissing === finding.id}
                className="opacity-0 group-hover:opacity-100 p-1 rounded text-dark-500 hover:text-white hover:bg-dark-700 transition-all disabled:opacity-50"
                title="Dismiss"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
