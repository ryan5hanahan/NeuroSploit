import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BrainCircuit, Plus, ChevronUp, ChevronDown, Target, AlertTriangle,
  RefreshCw, StopCircle, CheckCircle, XCircle, DollarSign, Lock, Globe
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import Input from '../components/common/Input'
import Textarea from '../components/common/Textarea'
import { agentV2Api } from '../services/api'
import { useOperationStore } from '../store'
import type { AgentV2OperationSummary } from '../types'

const STATUS_STYLES: Record<string, string> = {
  running: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
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

export default function OperationsPage() {
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

  // Auth form state
  const [showAuth, setShowAuth] = useState(false)
  const [authType, setAuthType] = useState<string>('')
  const [authCookie, setAuthCookie] = useState('')
  const [authToken, setAuthToken] = useState('')
  const [authUsername, setAuthUsername] = useState('')
  const [authPassword, setAuthPassword] = useState('')
  const [authHeaderName, setAuthHeaderName] = useState('')
  const [authHeaderValue, setAuthHeaderValue] = useState('')

  const fetchOperations = useCallback(async () => {
    try {
      const data = await agentV2Api.listOperations()
      setOperations(data.operations)
      // Auto-show form when no operations exist
      if (data.operations.length === 0) setShowForm(true)
    } catch (err) {
      console.error('Failed to fetch operations:', err)
    } finally {
      setIsLoading(false)
    }
  }, [setOperations])

  useEffect(() => {
    fetchOperations()

    const hasRunning = operations.some((op) => op.status === 'running')
    const interval = setInterval(fetchOperations, hasRunning ? 10000 : 30000)
    return () => clearInterval(interval)
  }, [fetchOperations, operations.length])

  const handleStart = async () => {
    if (!target.trim()) return
    setIsStarting(true)
    try {
      // Build auth credentials from type-specific fields
      let auth_credentials: Record<string, string> | undefined
      const selectedAuthType = authType || undefined

      if (authType === 'cookie' && authCookie) {
        auth_credentials = { cookie: authCookie }
      } else if (authType === 'bearer' && authToken) {
        auth_credentials = { token: authToken }
      } else if (authType === 'basic' && authUsername) {
        auth_credentials = { username: authUsername, password: authPassword }
      } else if (authType === 'header' && authHeaderName) {
        auth_credentials = { header_name: authHeaderName, header_value: authHeaderValue }
      }

      const resp = await agentV2Api.start({
        target: target.trim(),
        additional_targets: multiTarget
          ? additionalTargets.split('\n').map(t => t.trim()).filter(Boolean)
          : undefined,
        subdomain_discovery: subdomainDiscovery || undefined,
        objective: objective.trim() || undefined,
        max_steps: maxSteps,
        scope_profile: scopeProfile,
        auth_type: selectedAuthType as any,
        auth_credentials,
      })
      navigate(`/operations/${resp.operation_id}`)
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
          <BrainCircuit className="w-7 h-7 text-primary-500" />
          <div>
            <h2 className="text-2xl font-bold text-white">LLM Agent</h2>
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
              label="Objective (optional)"
              placeholder="Perform a comprehensive security assessment"
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              rows={2}
            />

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

            {/* Authentication section */}
            <div className="border border-dark-700 rounded-lg overflow-hidden">
              <button
                type="button"
                onClick={() => setShowAuth(!showAuth)}
                className="w-full flex items-center justify-between px-4 py-3 bg-dark-900/50 hover:bg-dark-900 transition-colors text-left"
              >
                <span className="flex items-center gap-2 text-sm font-medium text-dark-200">
                  <Lock className="w-4 h-4" />
                  Authentication
                  {authType && (
                    <span className="text-xs bg-primary-500/20 text-primary-400 px-2 py-0.5 rounded-full">
                      {authType}
                    </span>
                  )}
                </span>
                {showAuth ? (
                  <ChevronUp className="w-4 h-4 text-dark-400" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-dark-400" />
                )}
              </button>

              {showAuth && (
                <div className="p-4 space-y-3 border-t border-dark-700">
                  <div>
                    <label className="block text-sm font-medium text-dark-200 mb-1.5">
                      Auth Type
                    </label>
                    <select
                      value={authType}
                      onChange={(e) => setAuthType(e.target.value)}
                      className="w-full px-4 py-2.5 bg-dark-900 border border-dark-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
                    >
                      <option value="">None</option>
                      <option value="cookie">Cookie</option>
                      <option value="bearer">Bearer Token</option>
                      <option value="basic">Basic Auth</option>
                      <option value="header">Custom Header</option>
                    </select>
                  </div>

                  {authType === 'cookie' && (
                    <Input
                      label="Cookie Value"
                      placeholder="session=abc123; token=xyz"
                      value={authCookie}
                      onChange={(e) => setAuthCookie(e.target.value)}
                    />
                  )}

                  {authType === 'bearer' && (
                    <Input
                      label="Bearer Token"
                      placeholder="eyJhbGciOiJIUzI1NiIs..."
                      value={authToken}
                      onChange={(e) => setAuthToken(e.target.value)}
                    />
                  )}

                  {authType === 'basic' && (
                    <div className="grid grid-cols-2 gap-3">
                      <Input
                        label="Username"
                        placeholder="admin"
                        value={authUsername}
                        onChange={(e) => setAuthUsername(e.target.value)}
                      />
                      <Input
                        label="Password"
                        placeholder="password"
                        value={authPassword}
                        onChange={(e) => setAuthPassword(e.target.value)}
                      />
                    </div>
                  )}

                  {authType === 'header' && (
                    <div className="grid grid-cols-2 gap-3">
                      <Input
                        label="Header Name"
                        placeholder="X-API-Key"
                        value={authHeaderName}
                        onChange={(e) => setAuthHeaderName(e.target.value)}
                      />
                      <Input
                        label="Header Value"
                        placeholder="your-api-key-here"
                        value={authHeaderValue}
                        onChange={(e) => setAuthHeaderValue(e.target.value)}
                      />
                    </div>
                  )}
                </div>
              )}
            </div>

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
            <BrainCircuit className="w-10 h-10 text-dark-600 mx-auto mb-3" />
            <p className="text-dark-400">No operations yet</p>
            <p className="text-dark-500 text-sm mt-1">
              Start a new operation to begin an LLM-driven assessment
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {operations.map((op: AgentV2OperationSummary) => (
              <button
                key={op.operation_id}
                onClick={() => navigate(`/operations/${op.operation_id}`)}
                className="w-full flex items-center gap-4 p-4 bg-dark-900/50 rounded-lg hover:bg-dark-900 transition-colors text-left"
              >
                {/* Status icon */}
                <div className="flex-shrink-0">{getStatusIcon(op.status)}</div>

                {/* Target + Objective */}
                <div className="flex-1 min-w-0">
                  <p className="text-white font-medium truncate">{op.target}</p>
                  <p className="text-xs text-dark-400 truncate mt-0.5">
                    {op.objective}
                  </p>
                </div>

                {/* Status badge */}
                <span
                  className={`text-xs px-2.5 py-1 rounded-full font-medium border ${
                    STATUS_STYLES[op.status] || 'bg-dark-700 text-dark-300 border-dark-600'
                  }`}
                >
                  {op.status}
                </span>

                {/* Steps progress */}
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

                {/* Findings count */}
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
