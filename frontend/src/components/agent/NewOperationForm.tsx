import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Target, Globe, BookOpen, ChevronDown, ChevronUp, Shield,
  Settings2, Sliders,
} from 'lucide-react'
import Button from '../common/Button'
import Input from '../common/Input'
import Textarea from '../common/Textarea'
import AuthInputSection, { AuthState } from '../AuthInputSection'
import CredentialSetsPanel, { CredentialSetEntry } from '../CredentialSetsPanel'
import { agentV2Api } from '../../services/api'
import type { AgentTask } from '../../types'

const SCOPE_OPTIONS = [
  { value: 'full_auto', label: 'Full Auto' },
  { value: 'vuln_lab', label: 'Vuln Lab' },
  { value: 'ctf', label: 'CTF' },
  { value: 'recon_only', label: 'Recon Only' },
]

const GOVERNANCE_OPTIONS = [
  { value: 'warn', label: 'Warn' },
  { value: 'enforce', label: 'Enforce' },
  { value: 'audit', label: 'Audit Only' },
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

export default function NewOperationForm() {
  const navigate = useNavigate()
  const [isStarting, setIsStarting] = useState(false)

  // Target & Objective
  const [target, setTarget] = useState('')
  const [objective, setObjective] = useState('')
  const [scopeProfile, setScopeProfile] = useState('full_auto')
  const [governanceMode, setGovernanceMode] = useState('warn')
  const [multiTarget, setMultiTarget] = useState(false)
  const [additionalTargets, setAdditionalTargets] = useState('')
  const [subdomainDiscovery, setSubdomainDiscovery] = useState(false)

  // Task Library
  const [showTaskLibrary, setShowTaskLibrary] = useState(false)
  const [tasks, setTasks] = useState<AgentTask[]>([])
  const [loadingTasks, setLoadingTasks] = useState(false)
  const [taskCategory, setTaskCategory] = useState('')
  const [selectedTask, setSelectedTask] = useState<AgentTask | null>(null)

  // Auth
  const [showAuth, setShowAuth] = useState(false)
  const [auth, setAuth] = useState<AuthState>({ authType: 'none', authValue: '', username: '', password: '' })
  const [credentialSets, setCredentialSets] = useState<CredentialSetEntry[]>([])

  // Advanced
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [maxSteps, setMaxSteps] = useState(100)
  const [headlessBrowser, setHeadlessBrowser] = useState(true)
  const [saveArtifacts, setSaveArtifacts] = useState(true)

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
    if (showTaskLibrary) fetchTasks(taskCategory)
  }, [showTaskLibrary, taskCategory, fetchTasks])

  const handleTaskSelect = (task: AgentTask) => {
    setSelectedTask(task)
    setObjective(task.prompt)
  }

  const handleStart = async () => {
    if (!target.trim()) return
    setIsStarting(true)
    try {
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

  return (
    <div className="max-w-3xl mx-auto space-y-4">
      {/* Section 1: Target & Objective */}
      <div className="space-y-4">
        <Input
          label="Target URL"
          placeholder="https://example.com"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />

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

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-dark-200 mb-1.5">Scope Profile</label>
            <select
              value={scopeProfile}
              onChange={(e) => setScopeProfile(e.target.value)}
              className="w-full px-4 py-2.5 bg-dark-900 border border-dark-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              {SCOPE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-dark-200 mb-1.5">Governance Mode</label>
            <select
              value={governanceMode}
              onChange={(e) => setGovernanceMode(e.target.value)}
              className="w-full px-4 py-2.5 bg-dark-900 border border-dark-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              {GOVERNANCE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Section 2: Task Library (accordion) */}
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
          {showTaskLibrary ? <ChevronUp className="w-4 h-4 text-dark-400" /> : <ChevronDown className="w-4 h-4 text-dark-400" />}
        </button>

        {showTaskLibrary && (
          <div className="p-4 space-y-3 border-t border-dark-700">
            <div className="flex gap-2 flex-wrap">
              {TASK_CATEGORIES.map((cat) => (
                <button
                  key={cat.id}
                  onClick={() => setTaskCategory(cat.id)}
                  className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${
                    taskCategory === cat.id
                      ? 'bg-purple-500/20 text-purple-400 border-purple-500/30'
                      : 'bg-dark-800 text-dark-400 border-dark-700 hover:text-white'
                  }`}
                >
                  {cat.name}
                </button>
              ))}
            </div>

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
                          <span key={tag} className="text-xs bg-dark-700 text-dark-300 px-1.5 py-0.5 rounded">{tag}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>

            {selectedTask && (
              <div className="p-3 bg-dark-800 rounded-lg border border-dark-700">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-medium text-white text-sm">Selected: {selectedTask.name}</span>
                  <Button variant="ghost" size="sm" onClick={() => { setSelectedTask(null); setObjective('') }}>
                    Clear
                  </Button>
                </div>
                <p className="text-xs text-dark-400 whitespace-pre-wrap line-clamp-3">{selectedTask.prompt}</p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Section 3: Authentication (accordion) */}
      <div className="border border-dark-700 rounded-lg overflow-hidden">
        <button
          type="button"
          onClick={() => setShowAuth(!showAuth)}
          className="w-full flex items-center justify-between px-4 py-3 bg-dark-900/50 hover:bg-dark-900 transition-colors text-left"
        >
          <span className="flex items-center gap-2 text-sm font-medium text-dark-200">
            <Shield className="w-4 h-4" />
            Authentication
            {auth.authType !== 'none' && (
              <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded-full">{auth.authType}</span>
            )}
          </span>
          {showAuth ? <ChevronUp className="w-4 h-4 text-dark-400" /> : <ChevronDown className="w-4 h-4 text-dark-400" />}
        </button>

        {showAuth && (
          <div className="p-4 space-y-4 border-t border-dark-700">
            <AuthInputSection value={auth} onChange={setAuth} />
            <CredentialSetsPanel credentialSets={credentialSets} onChange={setCredentialSets} />
          </div>
        )}
      </div>

      {/* Section 4: Advanced Options (accordion) */}
      <div className="border border-dark-700 rounded-lg overflow-hidden">
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="w-full flex items-center justify-between px-4 py-3 bg-dark-900/50 hover:bg-dark-900 transition-colors text-left"
        >
          <span className="flex items-center gap-2 text-sm font-medium text-dark-200">
            <Sliders className="w-4 h-4" />
            Advanced Options
          </span>
          {showAdvanced ? <ChevronUp className="w-4 h-4 text-dark-400" /> : <ChevronDown className="w-4 h-4 text-dark-400" />}
        </button>

        {showAdvanced && (
          <div className="p-4 space-y-4 border-t border-dark-700">
            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={headlessBrowser}
                  onChange={(e) => setHeadlessBrowser(e.target.checked)}
                  className="w-4 h-4 rounded bg-dark-900 border-dark-600 text-primary-500 focus:ring-primary-500"
                />
                <span className="text-sm text-dark-200">Headless Browser</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={saveArtifacts}
                  onChange={(e) => setSaveArtifacts(e.target.checked)}
                  className="w-4 h-4 rounded bg-dark-900 border-dark-600 text-primary-500 focus:ring-primary-500"
                />
                <span className="text-sm text-dark-200">Save Artifacts</span>
              </label>
            </div>

            <div>
              <label className="block text-sm font-medium text-dark-200 mb-1.5">
                Max Steps: <span className="text-white font-bold">{maxSteps}</span>
              </label>
              <input
                type="range"
                min={10}
                max={500}
                step={10}
                value={maxSteps}
                onChange={(e) => setMaxSteps(Number(e.target.value))}
                className="w-full accent-primary-500"
              />
              <div className="flex justify-between text-xs text-dark-600 mt-1">
                <span>10</span>
                <span>250</span>
                <span>500</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Start Button */}
      <Button
        onClick={handleStart}
        isLoading={isStarting}
        disabled={!target.trim()}
        size="lg"
        className="w-full"
      >
        <Target className="w-5 h-5 mr-2" />
        Start Operation
      </Button>
    </div>
  )
}
