import { useEffect, useState, useCallback, useMemo } from 'react'
import {
  Bot, Activity, CheckCircle, AlertTriangle, DollarSign,
  RefreshCw, Plus,
} from 'lucide-react'
import OperationCard from '../components/agent/OperationCard'
import OperationFilters from '../components/agent/OperationFilters'
import NewOperationForm from '../components/agent/NewOperationForm'
import { agentV2Api } from '../services/api'
import { useOperationStore } from '../store'
import type { AgentV2OperationSummary } from '../types'

type TabId = 'active' | 'history' | 'new'

const ACTIVE_STATUSES = new Set(['running', 'paused', 'stopping'])
const TERMINAL_STATUSES = new Set(['completed', 'error', 'cancelled', 'budget_exhausted', 'stopped'])

export default function AgentPage() {
  const { operations, setOperations } = useOperationStore()
  const [isLoading, setIsLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<TabId>('active')

  // History filters
  const [statusFilter, setStatusFilter] = useState('all')
  const [sortBy, setSortBy] = useState('newest')
  const [searchQuery, setSearchQuery] = useState('')
  const [historyLimit, setHistoryLimit] = useState(20)

  const fetchOperations = useCallback(async () => {
    try {
      const data = await agentV2Api.listOperations()
      setOperations(data.operations)
      // Auto-switch to 'new' tab if no operations exist
      if (data.operations.length === 0) setActiveTab('new')
    } catch (err) {
      console.error('Failed to fetch operations:', err)
    } finally {
      setIsLoading(false)
    }
  }, [setOperations])

  useEffect(() => {
    fetchOperations()
    const hasRunning = operations.some((op) => ACTIVE_STATUSES.has(op.status))
    const interval = setInterval(fetchOperations, hasRunning ? 3000 : 30000)
    return () => clearInterval(interval)
  }, [fetchOperations, operations.length])

  // Split operations
  const activeOps = useMemo(
    () => operations.filter((op) => ACTIVE_STATUSES.has(op.status)),
    [operations]
  )

  const historyOps = useMemo(() => {
    let ops = operations.filter((op) => TERMINAL_STATUSES.has(op.status))

    // Status filter
    if (statusFilter !== 'all') {
      ops = ops.filter((op) => op.status === statusFilter)
    }

    // Search filter
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      ops = ops.filter((op) => op.target.toLowerCase().includes(q) || op.objective?.toLowerCase().includes(q))
    }

    // Sort
    ops.sort((a, b) => {
      if (sortBy === 'newest') return (b.started_at || '').localeCompare(a.started_at || '')
      if (sortBy === 'oldest') return (a.started_at || '').localeCompare(b.started_at || '')
      if (sortBy === 'findings') return (b.findings_count || 0) - (a.findings_count || 0)
      return 0
    })

    return ops
  }, [operations, statusFilter, searchQuery, sortBy])

  // Stats
  const runningCount = activeOps.filter((op) => op.status === 'running').length
  const pausedCount = activeOps.filter((op) => op.status === 'paused').length
  const totalFindingsToday = operations.reduce((sum, op) => sum + (op.findings_count || 0), 0)
  const activeCost = activeOps.reduce((sum, op) => sum + (op.cost_usd || 0), 0)

  const tabs: { id: TabId; label: string; count?: number }[] = [
    { id: 'active', label: 'Active', count: activeOps.length },
    { id: 'history', label: 'History', count: historyOps.length },
    { id: 'new', label: 'New Operation' },
  ]

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-purple-500/20 rounded-xl flex items-center justify-center">
            <Bot className="w-6 h-6 text-purple-400" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white">Agent Operations</h2>
            <p className="text-dark-400 text-sm mt-0.5">
              Autonomous LLM-driven security assessments
            </p>
          </div>
        </div>

        <button
          onClick={() => setActiveTab('new')}
          className="flex items-center gap-2 px-4 py-2.5 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded-lg hover:bg-purple-500/30 transition-colors font-medium text-sm"
        >
          <Plus className="w-4 h-4" />
          New Operation
        </button>
      </div>

      {/* Tab Bar */}
      <div className="flex gap-2">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border transition-colors ${
              activeTab === tab.id
                ? 'bg-purple-500/20 text-purple-400 border-purple-500/30'
                : 'bg-dark-800 text-dark-400 border-dark-700 hover:text-white hover:border-dark-600'
            }`}
          >
            {tab.label}
            {tab.count !== undefined && (
              <span className={`text-xs px-1.5 py-0.5 rounded-full ${
                activeTab === tab.id ? 'bg-purple-500/30 text-purple-300' : 'bg-dark-700 text-dark-500'
              }`}>
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Active Tab */}
      {activeTab === 'active' && (
        <div className="space-y-4">
          {/* Stats Row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-dark-800 rounded-xl border border-dark-700 p-4 flex items-center gap-3">
              <div className="w-9 h-9 bg-blue-500/20 rounded-lg flex items-center justify-center">
                <Activity className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{runningCount}</p>
                <p className="text-xs text-dark-500">Running</p>
              </div>
            </div>

            <div className="bg-dark-800 rounded-xl border border-dark-700 p-4 flex items-center gap-3">
              <div className="w-9 h-9 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-yellow-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{pausedCount}</p>
                <p className="text-xs text-dark-500">Paused</p>
              </div>
            </div>

            <div className="bg-dark-800 rounded-xl border border-dark-700 p-4 flex items-center gap-3">
              <div className="w-9 h-9 bg-green-500/20 rounded-lg flex items-center justify-center">
                <CheckCircle className="w-5 h-5 text-green-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{totalFindingsToday}</p>
                <p className="text-xs text-dark-500">Findings</p>
              </div>
            </div>

            <div className="bg-dark-800 rounded-xl border border-dark-700 p-4 flex items-center gap-3">
              <div className="w-9 h-9 bg-orange-500/20 rounded-lg flex items-center justify-center">
                <DollarSign className="w-5 h-5 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">${activeCost.toFixed(2)}</p>
                <p className="text-xs text-dark-500">Active Cost</p>
              </div>
            </div>
          </div>

          {/* Active Operations */}
          {isLoading ? (
            <div className="flex justify-center py-12">
              <RefreshCw className="w-6 h-6 animate-spin text-purple-400" />
            </div>
          ) : activeOps.length === 0 ? (
            <div className="text-center py-12 bg-dark-800 rounded-xl border border-dark-700">
              <Bot className="w-10 h-10 text-dark-600 mx-auto mb-3" />
              <p className="text-dark-400 font-medium">No active operations</p>
              <p className="text-dark-500 text-sm mt-1">
                Start a new operation to begin an autonomous security assessment
              </p>
              <button
                onClick={() => setActiveTab('new')}
                className="mt-4 text-purple-400 text-sm hover:text-purple-300 transition-colors"
              >
                Start New Operation &rarr;
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              {activeOps.map((op: AgentV2OperationSummary) => (
                <OperationCard
                  key={op.operation_id}
                  operation={op}
                  isActive
                  onRefresh={fetchOperations}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          <OperationFilters
            statusFilter={statusFilter}
            onStatusChange={setStatusFilter}
            sortBy={sortBy}
            onSortChange={setSortBy}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
          />

          {isLoading ? (
            <div className="flex justify-center py-12">
              <RefreshCw className="w-6 h-6 animate-spin text-purple-400" />
            </div>
          ) : historyOps.length === 0 ? (
            <div className="text-center py-12 bg-dark-800 rounded-xl border border-dark-700">
              <Bot className="w-10 h-10 text-dark-600 mx-auto mb-3" />
              <p className="text-dark-400 font-medium">
                {statusFilter !== 'all' || searchQuery ? 'No matching operations' : 'No completed operations'}
              </p>
            </div>
          ) : (
            <>
              <div className="space-y-2">
                {historyOps.slice(0, historyLimit).map((op: AgentV2OperationSummary) => (
                  <OperationCard
                    key={op.operation_id}
                    operation={op}
                    onRefresh={fetchOperations}
                  />
                ))}
              </div>

              {historyOps.length > historyLimit && (
                <div className="text-center">
                  <button
                    onClick={() => setHistoryLimit((prev) => prev + 20)}
                    className="text-purple-400 text-sm hover:text-purple-300 transition-colors py-2"
                  >
                    Load More ({historyOps.length - historyLimit} remaining)
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* New Operation Tab */}
      {activeTab === 'new' && <NewOperationForm />}
    </div>
  )
}
