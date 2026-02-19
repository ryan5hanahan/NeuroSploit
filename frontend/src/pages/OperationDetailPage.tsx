import { useEffect, useState, useCallback, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  BrainCircuit, StopCircle, RefreshCw, AlertTriangle, Clock,
  Footprints, Shield, DollarSign, ChevronDown, ChevronRight,
  ArrowDown, Pause, CheckCircle, FileText, Download,
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { SeverityBadge } from '../components/common/Badge'
import CostMeter from '../components/operations/CostMeter'
import PlanTimeline from '../components/operations/PlanTimeline'
import ToolUsageChart from '../components/operations/ToolUsageChart'
import QualityScorecard from '../components/operations/QualityScorecard'
import { agentV2Api } from '../services/api'
import { wsService } from '../services/websocket'
import { useOperationStore } from '../store'
import type { AgentV2Finding, AgentV2WSStep, WSMessage } from '../types'

const STATUS_STYLES: Record<string, string> = {
  running: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  completed: 'bg-green-500/20 text-green-400 border-green-500/30',
  error: 'bg-red-500/20 text-red-400 border-red-500/30',
  cancelled: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  stopping: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  budget_exhausted: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
}

const TERMINAL_STATUSES = new Set(['completed', 'error', 'cancelled', 'budget_exhausted'])

const TOOL_CATEGORY_COLORS: Record<string, string> = {
  shell_execute: 'text-blue-400',
  http_request: 'text-green-400',
  browser_navigate: 'text-purple-400',
  browser_extract_links: 'text-purple-400',
  browser_extract_forms: 'text-purple-400',
  browser_execute_js: 'text-purple-400',
  browser_screenshot: 'text-purple-400',
  memory_store: 'text-cyan-400',
  memory_search: 'text-cyan-400',
  save_artifact: 'text-orange-400',
  report_finding: 'text-orange-400',
  update_plan: 'text-yellow-400',
  stop: 'text-red-400',
}

function formatDuration(seconds: number | null | undefined): string {
  if (!seconds) return '--'
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
}

export default function OperationDetailPage() {
  const { operationId } = useParams<{ operationId: string }>()
  const navigate = useNavigate()
  const {
    currentOperation, currentFindings, steps,
    setCurrentOperation, setCurrentFindings, updateFromStep, addStep,
  } = useOperationStore()

  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'steps'>('overview')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set())
  const [autoScroll, setAutoScroll] = useState(true)
  const [showExportMenu, setShowExportMenu] = useState(false)
  const [isExporting, setIsExporting] = useState(false)
  const stepsEndRef = useRef<HTMLDivElement>(null)

  // Use a ref for status so the polling callback always sees the latest value
  const statusRef = useRef<string | undefined>(undefined)
  statusRef.current = currentOperation?.status

  const fetchStatus = useCallback(async () => {
    if (!operationId) return
    try {
      const status = await agentV2Api.getStatus(operationId)
      setCurrentOperation(status)
      return status
    } catch (err: any) {
      // Only set error on initial load, not on polls
      throw err
    }
  }, [operationId, setCurrentOperation])

  const fetchFindings = useCallback(async () => {
    if (!operationId) return
    try {
      const data = await agentV2Api.getFindings(operationId)
      setCurrentFindings(data.findings || [])
    } catch {
      // Findings may not be available yet
    }
  }, [operationId, setCurrentFindings])

  // Initial fetch
  useEffect(() => {
    if (!operationId) return

    let cancelled = false
    const initialFetch = async () => {
      setIsLoading(true)
      setError(null)
      try {
        await Promise.all([fetchStatus(), fetchFindings()])
      } catch (err: any) {
        if (!cancelled) {
          setError(err?.response?.data?.detail || 'Failed to load operation')
        }
      } finally {
        if (!cancelled) setIsLoading(false)
      }
    }
    initialFetch()

    return () => { cancelled = true }
  }, [operationId, fetchStatus, fetchFindings])

  // Polling — only while non-terminal, stops once completed
  useEffect(() => {
    if (!operationId || isLoading) return

    const poll = async () => {
      const status = statusRef.current
      // Don't poll if terminal
      if (status && TERMINAL_STATUSES.has(status)) return
      try {
        await Promise.all([fetchStatus(), fetchFindings()])
      } catch {
        // Silently ignore poll errors
      }
    }

    const pollInterval = setInterval(poll, 5000)
    return () => clearInterval(pollInterval)
  }, [operationId, isLoading, fetchStatus, fetchFindings])

  // One-time re-fetch when transitioning to terminal status
  const prevStatusRef = useRef<string | undefined>(undefined)
  useEffect(() => {
    const prev = prevStatusRef.current
    const curr = currentOperation?.status
    prevStatusRef.current = curr

    if (prev && !TERMINAL_STATUSES.has(prev) && curr && TERMINAL_STATUSES.has(curr)) {
      // Just became terminal — final fetch for cost_report + quality_evaluation
      fetchStatus()
      fetchFindings()
    }
  }, [currentOperation?.status, fetchStatus, fetchFindings])

  // WebSocket connection
  useEffect(() => {
    if (!operationId) return

    wsService.connect(operationId)

    const unsubStep = wsService.subscribe('agent_v2_agent_step', (msg: WSMessage) => {
      const step: AgentV2WSStep = {
        type: msg.type,
        operation_id: msg.operation_id as string,
        step: (msg.step as number) || 0,
        max_steps: (msg.max_steps as number) || 0,
        tool: (msg.tool as string) || '',
        is_error: (msg.is_error as boolean) || false,
        duration_ms: (msg.duration_ms as number) || 0,
        findings_count: (msg.findings_count as number) || 0,
      }
      updateFromStep(step)
      addStep(step)
    })

    const unsubComplete = wsService.subscribe('agent_v2_agent_completed', () => {
      // Final fetch for cost_report, quality_evaluation
      fetchStatus()
      fetchFindings()
    })

    return () => {
      unsubStep()
      unsubComplete()
      wsService.disconnect()
    }
  }, [operationId, updateFromStep, addStep, fetchStatus, fetchFindings])

  // Auto-scroll steps log
  useEffect(() => {
    if (autoScroll && stepsEndRef.current) {
      stepsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [steps.length, autoScroll])

  const handleStop = async () => {
    if (!operationId) return
    try {
      await agentV2Api.stop(operationId)
      setCurrentOperation(
        currentOperation ? { ...currentOperation, status: 'stopping' } : null
      )
    } catch (err) {
      console.error('Failed to stop:', err)
    }
  }

  const handleExport = async (format: 'html' | 'json') => {
    if (!operationId) return
    setIsExporting(true)
    setShowExportMenu(false)
    try {
      await agentV2Api.generateReport(operationId, format)
      window.open(agentV2Api.getReportDownloadUrl(operationId, format), '_blank')
    } catch (err) {
      console.error('Export failed:', err)
    } finally {
      setIsExporting(false)
    }
  }

  const toggleFinding = (idx: number) => {
    const next = new Set(expandedFindings)
    if (next.has(idx)) next.delete(idx)
    else next.add(idx)
    setExpandedFindings(next)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-primary-500" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-64">
        <AlertTriangle className="w-12 h-12 text-red-500 mb-4" />
        <p className="text-xl text-white mb-2">Failed to load operation</p>
        <p className="text-dark-400 mb-4">{error}</p>
        <Button onClick={() => navigate('/operations')}>Back to Operations</Button>
      </div>
    )
  }

  if (!currentOperation) {
    return (
      <div className="flex flex-col items-center justify-center h-64">
        <AlertTriangle className="w-12 h-12 text-yellow-500 mb-4" />
        <p className="text-xl text-white mb-2">Operation not found</p>
        <Button onClick={() => navigate('/operations')}>Back to Operations</Button>
      </div>
    )
  }

  const isRunning = currentOperation.status === 'running' || currentOperation.status === 'stopping'
  const progressPct =
    currentOperation.max_steps > 0
      ? Math.min(
          (currentOperation.steps_used / currentOperation.max_steps) * 100,
          100
        )
      : 0

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <BrainCircuit className="w-6 h-6 text-primary-500" />
            <h2 className="text-2xl font-bold text-white truncate max-w-lg">
              {currentOperation.target}
            </h2>
            <span
              className={`text-xs px-2.5 py-1 rounded-full font-medium border ${
                STATUS_STYLES[currentOperation.status] ||
                'bg-dark-700 text-dark-300 border-dark-600'
              }`}
            >
              {currentOperation.status}
            </span>
          </div>
          <p className="text-dark-400 text-sm mt-1 max-w-lg truncate">
            {currentOperation.objective}
          </p>
          {currentOperation.duration_seconds != null && currentOperation.duration_seconds > 0 && (
            <p className="text-dark-500 text-xs mt-1">
              Duration: {formatDuration(currentOperation.duration_seconds)}
            </p>
          )}
        </div>
        <div className="flex gap-2">
          {currentOperation.status === 'running' && (
            <Button variant="danger" onClick={handleStop}>
              <StopCircle className="w-4 h-4 mr-2" />
              Stop
            </Button>
          )}
          {TERMINAL_STATUSES.has(currentOperation.status) && (
            <div className="relative">
              <Button
                variant="ghost"
                onClick={() => setShowExportMenu(!showExportMenu)}
                disabled={isExporting}
              >
                <Download className="w-4 h-4 mr-2" />
                {isExporting ? 'Exporting...' : 'Export Report'}
              </Button>
              {showExportMenu && (
                <div className="absolute right-0 mt-1 w-36 bg-dark-800 border border-dark-700 rounded-lg shadow-lg z-10 overflow-hidden">
                  <button
                    onClick={() => handleExport('html')}
                    className="w-full px-4 py-2 text-sm text-left text-white hover:bg-dark-700 transition-colors"
                  >
                    HTML Report
                  </button>
                  <button
                    onClick={() => handleExport('json')}
                    className="w-full px-4 py-2 text-sm text-left text-white hover:bg-dark-700 transition-colors"
                  >
                    JSON Report
                  </button>
                </div>
              )}
            </div>
          )}
          <Button variant="ghost" onClick={() => navigate('/operations')}>
            Back
          </Button>
        </div>
      </div>

      {/* Progress bar */}
      <div>
        <div className="flex items-center justify-between text-sm mb-1">
          <span className="text-dark-300">
            Step {currentOperation.steps_used} / {currentOperation.max_steps}
          </span>
          <span className="text-white font-medium">{progressPct.toFixed(0)}%</span>
        </div>
        <div className="h-2 bg-dark-900 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-300 ${
              isRunning ? 'bg-primary-500' : 'bg-green-500'
            }`}
            style={{ width: `${progressPct}%` }}
          />
        </div>
      </div>

      {/* Stop reason */}
      {currentOperation.stop_reason && (
        <div className="bg-dark-900/50 border border-dark-700 rounded-lg p-3 text-sm text-dark-300">
          <span className="text-dark-500 font-medium">Stop reason: </span>
          {currentOperation.stop_reason}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-2 border-b border-dark-700 pb-2">
        {(['overview', 'findings', 'steps'] as const).map((tab) => (
          <Button
            key={tab}
            variant={activeTab === tab ? 'primary' : 'ghost'}
            onClick={() => setActiveTab(tab)}
          >
            {tab === 'overview' && 'Overview'}
            {tab === 'findings' && `Findings (${currentOperation.findings_count})`}
            {tab === 'steps' && `Steps (${steps.length})`}
          </Button>
        ))}
      </div>

      {/* Tab: Overview */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Stat cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card>
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-lg bg-blue-500/10">
                  <Footprints className="w-5 h-5 text-blue-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">
                    {currentOperation.steps_used}
                  </p>
                  <p className="text-xs text-dark-400">Steps Used</p>
                </div>
              </div>
            </Card>
            <Card>
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-lg bg-red-500/10">
                  <Shield className="w-5 h-5 text-red-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">
                    {currentOperation.findings_count}
                  </p>
                  <p className="text-xs text-dark-400">Findings</p>
                </div>
              </div>
            </Card>
            <Card>
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-lg bg-green-500/10">
                  <Clock className="w-5 h-5 text-green-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">
                    {formatDuration(currentOperation.duration_seconds)}
                  </p>
                  <p className="text-xs text-dark-400">Duration</p>
                </div>
              </div>
            </Card>
            <Card>
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-lg bg-purple-500/10">
                  <DollarSign className="w-5 h-5 text-purple-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">
                    $
                    {currentOperation.cost_report
                      ? currentOperation.cost_report.total_cost_usd.toFixed(4)
                      : '--'}
                  </p>
                  <p className="text-xs text-dark-400">Cost</p>
                </div>
              </div>
            </Card>
          </div>

          {/* 2-column grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left column */}
            <div className="space-y-6">
              <Card title="Plan">
                <PlanTimeline
                  planText={currentOperation.plan_snapshot || null}
                  planPhases={currentOperation.plan_phases || null}
                  confidence={currentOperation.confidence ?? 0}
                />
              </Card>
              <Card title="Cost Breakdown">
                <CostMeter cost={currentOperation.cost_report || null} />
              </Card>
            </div>

            {/* Right column */}
            <div className="space-y-6">
              <Card title="Tool Usage">
                <ToolUsageChart toolUsage={currentOperation.tool_usage || null} />
              </Card>
              {(!isRunning || currentOperation.quality_evaluation) && (
                <Card title="Quality Assessment">
                  <QualityScorecard
                    evaluation={currentOperation.quality_evaluation || null}
                  />
                </Card>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab: Findings */}
      {activeTab === 'findings' && (
        <div className="space-y-3">
          {currentFindings.length === 0 ? (
            <Card>
              <p className="text-dark-400 text-center py-8">
                {isRunning
                  ? 'Scanning for vulnerabilities...'
                  : 'No findings reported'}
              </p>
            </Card>
          ) : (
            currentFindings.map((finding: AgentV2Finding, idx: number) => (
              <div
                key={idx}
                className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden"
              >
                {/* Finding header */}
                <div
                  className="p-4 cursor-pointer hover:bg-dark-750 transition-colors"
                  onClick={() => toggleFinding(idx)}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-2 flex-1">
                      {expandedFindings.has(idx) ? (
                        <ChevronDown className="w-4 h-4 mt-1 text-dark-400" />
                      ) : (
                        <ChevronRight className="w-4 h-4 mt-1 text-dark-400" />
                      )}
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-white">{finding.title}</p>
                        <p className="text-sm text-dark-400 truncate mt-1">
                          {finding.endpoint}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={finding.severity} />
                      {finding.vuln_type && (
                        <span className="text-xs bg-dark-700 px-2 py-0.5 rounded text-dark-300">
                          {finding.vuln_type}
                        </span>
                      )}
                      {finding.validation_status === 'verified' && (
                        <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-1">
                          <CheckCircle className="w-3 h-3" /> Verified
                        </span>
                      )}
                      {finding.step_number != null && (
                        <span className="text-xs text-dark-500">
                          Step #{finding.step_number}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Finding details */}
                {expandedFindings.has(idx) && (
                  <div className="p-4 pt-0 space-y-3 border-t border-dark-700">
                    {finding.description && (
                      <div>
                        <p className="text-sm font-medium text-dark-300 mb-1">
                          Description
                        </p>
                        <p className="text-sm text-dark-400 whitespace-pre-wrap">
                          {finding.description}
                        </p>
                      </div>
                    )}

                    {finding.evidence && (
                      <div>
                        <p className="text-sm font-medium text-dark-300 mb-1">
                          Evidence
                        </p>
                        <pre className="text-xs bg-dark-900 p-3 rounded overflow-x-auto text-dark-300 font-mono max-h-48 whitespace-pre-wrap">
                          {finding.evidence}
                        </pre>
                      </div>
                    )}

                    {finding.reproduction_steps && (
                      <div>
                        <p className="text-sm font-medium text-dark-300 mb-1">
                          Reproduction Steps
                        </p>
                        <p className="text-sm text-dark-400 whitespace-pre-wrap">
                          {finding.reproduction_steps}
                        </p>
                      </div>
                    )}

                    {finding.remediation && (
                      <div>
                        <p className="text-sm font-medium text-green-400 mb-1">
                          Remediation
                        </p>
                        <p className="text-sm text-dark-400 whitespace-pre-wrap">
                          {finding.remediation}
                        </p>
                      </div>
                    )}

                    {/* Artifacts */}
                    {finding.artifact_paths && finding.artifact_paths.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-dark-300 mb-1">
                          Artifacts
                        </p>
                        <div className="space-y-1">
                          {finding.artifact_paths.map((path, pi) => (
                            <div
                              key={pi}
                              className="flex items-center gap-2 text-xs text-dark-400 bg-dark-900/50 rounded px-2 py-1"
                            >
                              <FileText className="w-3 h-3 text-dark-500 flex-shrink-0" />
                              <span className="font-mono truncate">{path}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab: Steps Log */}
      {activeTab === 'steps' && (
        <Card
          title="Steps Log"
          action={
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setAutoScroll(!autoScroll)}
            >
              {autoScroll ? (
                <>
                  <Pause className="w-3 h-3 mr-1" /> Pause scroll
                </>
              ) : (
                <>
                  <ArrowDown className="w-3 h-3 mr-1" /> Auto scroll
                </>
              )}
            </Button>
          }
        >
          <div className="max-h-[500px] overflow-auto space-y-1 font-mono text-xs">
            {steps.length === 0 ? (
              <p className="text-dark-400 text-center py-8">
                {isRunning
                  ? 'Waiting for agent steps...'
                  : 'No steps recorded via WebSocket. Steps are available during live operations.'}
              </p>
            ) : (
              steps.map((step, idx) => (
                <div
                  key={idx}
                  className={`flex items-center gap-3 px-3 py-1.5 rounded ${
                    step.is_error
                      ? 'bg-red-500/10'
                      : idx % 2 === 0
                      ? 'bg-dark-900/30'
                      : ''
                  }`}
                >
                  <span className="text-dark-500 w-8 text-right">
                    #{step.step}
                  </span>
                  <span
                    className={`w-36 truncate ${
                      TOOL_CATEGORY_COLORS[step.tool] || 'text-dark-300'
                    }`}
                  >
                    {step.tool.replace(/_/g, ' ')}
                  </span>
                  <span className="text-dark-500 w-16 text-right">
                    {step.duration_ms}ms
                  </span>
                  {step.is_error && (
                    <span className="w-2 h-2 rounded-full bg-red-500 flex-shrink-0" />
                  )}
                  {step.findings_count > 0 && (
                    <span className="text-dark-500">
                      {step.findings_count} finding{step.findings_count !== 1 ? 's' : ''}
                    </span>
                  )}
                </div>
              ))
            )}
            <div ref={stepsEndRef} />
          </div>
        </Card>
      )}
    </div>
  )
}
