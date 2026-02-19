import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { Bot, Bug, FileText, Shield } from 'lucide-react'
import Card from '../common/Card'
import { SeverityBadge } from '../common/Badge'
import { dashboardApi } from '../../services/api'
import type { ActivityFeedItem } from '../../types'

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

const typeIcon: Record<string, typeof Bot> = {
  agent_task: Bot,
  vulnerability: Bug,
  report: FileText,
  scan: Shield,
}

const typeColor: Record<string, string> = {
  agent_task: 'text-purple-400',
  vulnerability: 'text-red-400',
  report: 'text-green-400',
  scan: 'text-blue-400',
}

export default function Timeline() {
  const [activities, setActivities] = useState<ActivityFeedItem[]>([])
  const [limit, setLimit] = useState(15)
  const [loading, setLoading] = useState(true)
  const [total, setTotal] = useState(0)

  const fetchData = useCallback(async () => {
    try {
      const data = await dashboardApi.getActivityFeed(limit)
      setActivities(data.activities)
      setTotal(data.total)
    } catch (err) {
      console.error('Failed to fetch timeline:', err)
    } finally {
      setLoading(false)
    }
  }, [limit])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 30000)
    return () => clearInterval(interval)
  }, [fetchData])

  if (loading && activities.length === 0) return null

  return (
    <Card title="Timeline">
      {activities.length === 0 ? (
        <p className="text-dark-400 text-center py-4 text-sm">No recent activity</p>
      ) : (
        <div className="space-y-1">
          {activities.map((activity, idx) => {
            const Icon = typeIcon[activity.type] || Shield
            const color = typeColor[activity.type] || 'text-dark-400'
            return (
              <Link
                key={`${activity.type}-${activity.timestamp}-${idx}`}
                to={activity.link}
                className="flex items-center gap-3 py-2 px-2 rounded-lg hover:bg-dark-900/50 transition-colors"
              >
                <Icon className={`w-4 h-4 flex-shrink-0 ${color}`} />
                <span className="text-sm text-white truncate flex-1">{activity.title}</span>
                {activity.severity && <SeverityBadge severity={activity.severity} />}
                {activity.status && !activity.severity && (
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                    activity.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                    activity.status === 'running' ? 'bg-blue-500/20 text-blue-400' :
                    activity.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                    'bg-dark-700 text-dark-300'
                  }`}>
                    {activity.status}
                  </span>
                )}
                <span className="text-xs text-dark-500 flex-shrink-0">{timeAgo(activity.timestamp)}</span>
              </Link>
            )
          })}
        </div>
      )}
      {total > activities.length && (
        <button
          onClick={() => setLimit(prev => prev + 15)}
          className="w-full mt-3 py-2 text-sm text-primary-500 hover:text-primary-400 transition-colors"
        >
          Load more
        </button>
      )}
    </Card>
  )
}
