import { useEffect, useCallback } from 'react'
import { dashboardApi } from '../services/api'
import { useDashboardStore } from '../store'
import type { DashboardStatsExtended } from '../types'
import CommandBar from '../components/dashboard/CommandBar'
import LiveOperations from '../components/dashboard/LiveOperations'
import KeyMetrics from '../components/dashboard/KeyMetrics'
import AttentionRequired from '../components/dashboard/AttentionRequired'
import Timeline from '../components/dashboard/Timeline'

export default function HomePage() {
  const { stats, setStats, setLoading } = useDashboardStore()

  const fetchStats = useCallback(async () => {
    try {
      const data = await dashboardApi.getStatsExtended()
      setStats(data)
    } catch (error) {
      console.error('Failed to fetch dashboard stats:', error)
    }
  }, [setStats])

  useEffect(() => {
    setLoading(true)
    fetchStats().finally(() => setLoading(false))

    const interval = setInterval(fetchStats, 30000)
    return () => clearInterval(interval)
  }, [fetchStats, setLoading])

  return (
    <div className="space-y-6 animate-fadeIn">
      <CommandBar />

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <div className="lg:col-span-3">
          <LiveOperations />
        </div>
        <div className="lg:col-span-2">
          <KeyMetrics stats={stats as DashboardStatsExtended} />
        </div>
      </div>

      <AttentionRequired />

      <Timeline />
    </div>
  )
}
