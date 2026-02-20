import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Bot, Plus, ChevronUp, ChevronDown, Target, AlertTriangle,
  RefreshCw, StopCircle, CheckCircle, XCircle, DollarSign, Globe,
  BookOpen,
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import Input from '../components/common/Input'
import Textarea from '../components/common/Textarea'
import AuthInputSection, { AuthState } from '../components/AuthInputSection'
import CredentialSetsPanel, { CredentialSetEntry } from '../components/CredentialSetsPanel'
import { agentV2Api } from '../services/api'
import { useOperationStore } from '../store'
import type { AgentV2OperationSummary, AgentTask } from '../types'

const STATUS_STYLES: Record<string, string> = {
  running: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  paused: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  completed: 'bg-green-500/20 text-green-400 border-green-500/30',
  error: 'bg-red-500/20 text-red-400 border-red-500/30',
  cancelled: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  stopping: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  budget_exhausted: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
}

const SCOPE_OPTIONS = [
  { value: 'full_auto', label: 'Full Auto' },
  { value: 'vuln_lab', label: 'Vuln Lab' },
  { value: 'ctf', label: 'CTF' },
  { value: 'recon_only', label: 'Recon Only' },
]

const TASK_CATEGORIES = [
  { id: '', name: 'All' },
  { id: 'reconnaissance', name: 'Recon' },
  { id: 'vulnerability_scanning', name: 'Vuln Scan' },
  { id: 'exploitation', name: 'Exploit' },
  { id: 'web_application', name: 'Web App' },
  { id: 'api_testing', name: 'API' },
  { id: 'authentication', name: 'Auth' },
  { id: 'custom', name: 'Custom' },
]

export default function AgentPage() {
  const navigate = useNavigate()
  const { operations, setOperations } = useOperationStore()
  const [showForm, setShowForm] = useState(false)
  const [isStarting, setIsStarting] = useState(false)
  const [isLoading, setIsLoading] = useState(true)

  // Form state
  const [target, setTarget] = useState('')
  const [objective, setObjective] = useState('')
  const [maxSteps, setMaxSteps] = useState(100)
  const [scopeProfile, setScopeProfile] = useState('full_auto')
  const [multiTarget, setMultiTarget] = useState(false)
  const [additionalTargets, setAdditionalTargets] = useState('')
  const [subdomainDiscovery, setSubdomainDiscovery] = useState(false)

  // Auth state (matches VulnLab style)
  const [auth, setAuth] = useState<AuthState>({ authType: 'none', authValue: '', username: '', password: '' })
  const [credentialSets, setCredentialSets] = useState<CredentialSetEntry[]>([])

  // Task library state
  const [showTaskLibrary, setShowTaskLibrary] = useState(false)
  const [tasks, setTasks] = useState<AgentTask[]>([])
  const [loadingTasks, setLoadingTasks] = useState(false)
  const [taskCategory, setTaskCategory] = useState('')
  const [selectedTask, setSelectedTask] = useState<AgentTask | null>(null)

  const fetchOperations = useCallback(async () => {
    try {
      const data = await agentV2Api.listOperations()
      setOperations(data.operations)
      if (data.operations.length === 0) setShowForm(true)
    } catch (err) {
      console.error('Failed to fetch operations:', err)
    } finally {
      setIsLoading(false)
    }
  }, [setOperations])

  const fetchTasks = useCallback(async (category?: string) => {
    setLoadingTasks(true)
    try {
      const data = await agentV2Api.tasks.list(category || undefined)
      setTasks(data)
    } catch (err) {
      console.error('Failed to fetch tasks:', err)
    } finally {
      setLoadingTasks(false)
    }
  }, [])

  useEffect(() => {
    fetchOperations()
    const hasRunning = operations.some((op) => op.status === 'running')
    const interval = setInterval(fetchOperations, hasRunning ? 10000 : 30000)
    return () => clearInterval(interval)
  }, [fetchOperations, operations.length])

  useEffect(() => {
    if (showTaskLibrary) fetchTasks(taskCategory)
  }, [showTaskLibrary, taskCategory, fetchTasks])

  const handleCategoryChange = (cat: string) => {
    setTaskCategory(cat)
  }

  const handleTaskSelect = (task: AgentTask) => {
    setSelectedTask(task)
    setObjective(task.prompt)
  }

  const handleStart = async () => {
    if (!target.trim()) return
    setIsStarting(true)
    try {
      // Build auth_type + auth_credentials from AuthInputSection state
      const effectiveAuthType = auth.authType && auth.authType !== 'none' ? auth.authType : undefined
      let auth_credentials: Record<string, string> | undefined
      if (effectiveAuthType === 'cookie' && auth.authValue) {
        auth_credentials = { cookie: auth.authValue }
      } else if (effectiveAuthType === 'bearer' && auth.authValue) {
        auth_credentials = { token: auth.authValue }
      } else if ((effectiveAuthType === 'basic' || effectiveAuthType === 'login') && auth.username) {
        auth_credentials = { username: auth.username, password: auth.password || '' }
      } else if (effectiveAuthType === 'header' && auth.authValue) {
        const colonIdx = auth.authValue.indexOf(':')
        if (colonIdx > 0) {
          auth_credentials = { header_name: auth.authValue.slice(0, colonIdx).trim(), header_value: auth.authValue.slice(colonIdx + 1).trim() }
        }
      }

      // Build credential_sets from CredentialSetsPanel
      const validCreds = credentialSets.filter(cs => cs.label.trim() && cs.auth_type)
      const credential_sets = validCreds.length > 0 ? validCreds.map(cs => ({
        label: cs.label,
        role: cs.role,
        auth_type: cs.auth_type as any,
        cookie: cs.cookie,
        token: cs.bearer_token,
        username: cs.username,
        password: cs.password,
        header_name: cs.header_name,
        header_value: cs.header_value,
      })) : undefined

      const resp = await agentV2Api.start({
        target: target.trim(),
        additional_targets: multiTarget
          ? additionalTargets.split('\n').map(t => t.trim()).filter(Boolean)
          : undefined,
        subdomain_discovery: subdomainDiscovery || undefined,
        objective: objective.trim() || undefined,
        max_steps: maxSteps,
        scope_profile: scopeProfile,
        auth_type: effectiveAuthType as any,
        auth_credentials,
        credential_sets,
        task_id: selectedTask?.id,
      })
      navigate(`/agent/${resp.operation_id}`)
    } catch (err: any) {
      console.error('Failed to start agent:', err)
      alert(err?.response?.data?.detail || 'Failed to start agent')
    } finally {
      setIsStarting(false)
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <RefreshCw className="w-4 h-4 animate-spin text-blue-400" />
      case 'paused':
        return <StopCircle className="w-4 h-4 text-yellow-400" />
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

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bot className="w-7 h-7 text-primary-500" />
          <div>
            <h2 className="text-2xl font-bold text-white">Agent</h2>
            <p className="text-dark-400 text-sm mt-0.5">
              Autonomous LLM-driven security assessments
            </p>
          </div>
        </div>
        <Button onClick={() => setShowForm(!showForm)}>
          {showForm ? (
            <>
              <ChevronUp className="w-4 h-4 mr-2" />
              Hide Form
            </>
          ) : (
            <>
              <Plus className="w-4 h-4 mr-2" />
              New Operation
            </>
          )}
        </Button>
      </div>

      {/* Start Form */}
      {showForm && (
        <Card title="Start New Operation">
          <div className="space-y-4">
            <Input
              label="Target URL"
              placeholder="https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />

            {/* Subdomain Discovery & Multi-Target toggles */}
            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={subdomainDiscovery}
                  onChange={(e) => setSubdomainDiscovery(e.target.checked)}
                  className="w-4 h-4 rounded bg-dark-900 border-dark-600 text-primary-500 focus:ring-primary-500"
                />
                <Globe className="w-4 h-4 text-dark-400" />
                <span className="text-sm text-dark-200">Subdomain Discovery</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={multiTarget}
                  onChange={(e) => setMultiTarget(e.target.checked)}
                  className="w-4 h-4 rounded bg-dark-900 border-dark-600 text-primary-500 focus:ring-primary-500"
                />
                <Target className="w-4 h-4 text-dark-400" />
                <span className="text-sm text-dark-200">Multiple Targets</span>
              </label>
            </div>

            {/* Multi-target textarea */}
            {multiTarget && (
              <Textarea
                label="Additional Targets (one per line)"
                placeholder={"https://api.example.com\nhttps://admin.example.com"}
                value={additionalTargets}
                onChange={(e) => setAdditionalTargets(e.target.value)}
                rows={3}
              />
            )}

            <Textarea
              label="Objective"
              placeholder="Perform a comprehensive security assessment"
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              rows={2}
            />

            {/* Task Library Picker */}
            <div className="border border-dark-700 rounded-lg overflow-hidden">
              <button
                type="button"
                onClick={() => setShowTaskLibrary(!showTaskLibrary)}
                className="w-full flex items-center justify-between px-4 py-3 bg-dark-900/50 hover:bg-dark-900 transition-colors text-left"
              >
                <span className="flex items-center gap-2 text-sm font-medium text-dark-200">
                  <BookOpen className="w-4 h-4" />
                  Task Library
                  {selectedTask && (
                    <span className="text-xs bg-primary-500/20 text-primary-400 px-2 py-0.5 rounded-full">
                      {selectedTask.name}
                    </span>
                  )}
                </span>
                {showTaskLibrary ? (
                  <ChevronUp className="w-4 h-4 text-dark-400" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-dark-400" />
                )}
              </button>

              {showTaskLibrary && (
                <div className="p-4 space-y-3 border-t border-dark-700">
                  {/* Category Filter */}
                  <div className="flex gap-2 flex-wrap">
                    {TASK_CATEGORIES.map((cat) => (
                      <Button
                        key={cat.id}
                        variant={taskCategory === cat.id ? 'primary' : 'secondary'}
                        size="sm"
                        onClick={() => handleCategoryChange(cat.id)}
                      >
                        {cat.name}
                      </Button>
                    ))}
                  </div>

                  {/* Tasks Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-64 overflow-auto">
                    {loadingTasks ? (
                      <p className="text-dark-400 col-span-2 text-center py-4">Loading tasks...</p>
                    ) : tasks.length === 0 ? (
                      <p className="text-dark-400 col-span-2 text-center py-4">No tasks found</p>
                    ) : (
                      tasks.map((task) => (
                        <div
                          key={task.id}
                          onClick={() => handleTaskSelect(task)}
                          className={`p-3 rounded-lg border cursor-pointer transition-all ${
                            selectedTask?.id === task.id
                              ? 'border-primary-500 bg-primary-500/10'
                              : 'border-dark-700 hover:border-dark-500 bg-dark-900/50'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-medium text-white text-sm">{task.name}</span>
                            {task.is_preset && (
                              <span className="text-xs bg-primary-500/20 text-primary-400 px-2 py-0.5 rounded">Preset</span>
                            )}
                          </div>
                          <p className="text-xs text-dark-400 line-clamp-2">{task.description}</p>
                          {task.tags?.length > 0 && (
                            <div className="flex gap-1 mt-2 flex-wrap">
                              {task.tags.slice(0, 3).map((tag) => (
                                <span key={tag} className="text-xs bg-dark-700 text-dark-300 px-1.5 py-0.5 rounded">
                                  {tag}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))
                    )}
                  </div>

                  {/* Selected Task Preview */}
                  {selectedTask && (
                    <div className="p-3 bg-dark-800 rounded-lg border border-dark-700">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-medium text-white text-sm">Selected: {selectedTask.name}</span>
                        <Button variant="ghost" size="sm" onClick={() => { setSelectedTask(null); setObjective('') }}>
                          Clear
                        </Button>
                      </div>
                      <p className="text-xs text-dark-400 whitespace-pre-wrap line-clamp-3">
                        {selectedTask.prompt}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-dark-200 mb-1.5">
                  Max Steps
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="range"
                    min={10}
                    max={500}
                    step={10}
                    value={maxSteps}
                    onChange={(e) => setMaxSteps(Number(e.target.value))}
                    className="flex-1 accent-primary-500"
                  />
                  <span className="text-white font-medium w-12 text-right">
                    {maxSteps}
                  </span>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-dark-200 mb-1.5">
                  Scope Profile
                </label>
                <select
                  value={scopeProfile}
                  onChange={(e) => setScopeProfile(e.target.value)}
                  className="w-full px-4 py-2.5 bg-dark-900 border border-dark-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
                >
                  {SCOPE_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Authentication */}
            <AuthInputSection value={auth} onChange={setAuth} />

            {/* Multi-Credential Differential Testing */}
            <CredentialSetsPanel credentialSets={credentialSets} onChange={setCredentialSets} />

            <div className="flex justify-end">
              <Button
                onClick={handleStart}
                isLoading={isStarting}
                disabled={!target.trim()}
                size="lg"
              >
                <Target className="w-5 h-5 mr-2" />
                Start Operation
              </Button>
            </div>
          </div>
        </Card>
      )}

      {/* Operations List */}
      <Card
        title="Operations"
        subtitle={`${operations.length} operation${operations.length !== 1 ? 's' : ''}`}
      >
        {isLoading ? (
          <div className="flex justify-center py-8">
            <RefreshCw className="w-6 h-6 animate-spin text-primary-500" />
          </div>
        ) : operations.length === 0 ? (
          <div className="text-center py-8">
            <Bot className="w-10 h-10 text-dark-600 mx-auto mb-3" />
            <p className="text-dark-400">No operations yet</p>
            <p className="text-dark-500 text-sm mt-1">
              Start a new operation to begin an autonomous security assessment
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {operations.map((op: AgentV2OperationSummary) => (
              <button
                key={op.operation_id}
                onClick={() => navigate(`/agent/${op.operation_id}`)}
                className="w-full flex items-center gap-4 p-4 bg-dark-900/50 rounded-lg hover:bg-dark-900 transition-colors text-left"
              >
                <div className="flex-shrink-0">{getStatusIcon(op.status)}</div>

                <div className="flex-1 min-w-0">
                  <p className="text-white font-medium truncate">{op.target}</p>
                  <p className="text-xs text-dark-400 truncate mt-0.5">
                    {op.objective}
                  </p>
                </div>

                <span
                  className={`text-xs px-2.5 py-1 rounded-full font-medium border ${
                    STATUS_STYLES[op.status] || 'bg-dark-700 text-dark-300 border-dark-600'
                  }`}
                >
                  {op.status}
                </span>

                <div className="flex-shrink-0 w-24">
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-dark-400">Steps</span>
                    <span className="text-dark-300">
                      {op.steps_used}/{op.max_steps}
                    </span>
                  </div>
                  <div className="h-1.5 bg-dark-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary-500 rounded-full transition-all"
                      style={{
                        width: `${
                          op.max_steps > 0
                            ? Math.min((op.steps_used / op.max_steps) * 100, 100)
                            : 0
                        }%`,
                      }}
                    />
                  </div>
                </div>

                <div className="flex-shrink-0 text-right w-16">
                  <p className="text-white font-bold">{op.findings_count}</p>
                  <p className="text-xs text-dark-500">findings</p>
                </div>
              </button>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
