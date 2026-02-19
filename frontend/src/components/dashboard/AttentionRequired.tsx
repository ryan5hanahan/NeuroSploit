import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { CheckCircle, Check, ChevronDown, ChevronUp } from 'lucide-react'
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
  const [expanded, setExpanded] = useState(false)

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

  // Show 3 collapsed, all when expanded
  const visible = expanded ? findings : findings.slice(0, 3)
  const hasMore = findings.length > 3

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
        <div className="text-center py-4">
          <CheckCircle className="w-6 h-6 text-green-500 mx-auto mb-1" />
          <p className="text-green-400 text-sm font-medium">All clear</p>
        </div>
      ) : (
        <>
          <div className="space-y-1">
            {visible.map((finding) => (
              <div
                key={finding.id}
                className="flex items-center gap-2 py-1.5 px-2 bg-dark-900/50 rounded-lg hover:bg-dark-900 transition-colors"
              >
                <SeverityBadge severity={finding.severity} />
                <Link
                  to={`/scan/${finding.scan_id}`}
                  className="flex-1 min-w-0 text-sm text-white truncate hover:text-primary-400"
                >
                  {finding.title}
                </Link>
                <span className="text-[10px] text-dark-500 flex-shrink-0">
                  {timeAgo(finding.created_at)}
                </span>
                <button
                  onClick={() => handleDismiss(finding.id)}
                  disabled={dismissing === finding.id}
                  className="flex-shrink-0 px-2 py-0.5 rounded text-xs text-dark-400 hover:text-green-400 hover:bg-green-500/10 border border-dark-700 hover:border-green-500/30 transition-colors disabled:opacity-50"
                >
                  <Check className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
          {hasMore && (
            <button
              onClick={() => setExpanded(!expanded)}
              className="flex items-center justify-center gap-1 w-full mt-2 py-1 text-xs text-dark-400 hover:text-white transition-colors"
            >
              {expanded ? (
                <>Show less <ChevronUp className="w-3 h-3" /></>
              ) : (
                <>{findings.length - 3} more <ChevronDown className="w-3 h-3" /></>
              )}
            </button>
          )}
        </>
      )}
    </Card>
  )
}
