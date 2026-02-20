import { useState, useEffect } from 'react'
import { Bug, CheckCircle, XCircle, Search, FileText, Settings, Play, ChevronDown, ChevronUp } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { bugBountyApi, agentV2Api } from '../services/api'
import type { BugBountyProgram, BugBountyScope, BugBountyScopeAsset, BugBountySubmission } from '../types'

function assetToUrl(asset: BugBountyScopeAsset): string {
  const id = asset.asset_identifier
  const t = (asset.asset_type || '').toUpperCase()
  if (t === 'URL' || id.startsWith('http://') || id.startsWith('https://')) return id
  if (t === 'WILDCARD') return `https://${id.replace(/^\*\./, '')}`
  if (t === 'IP_ADDRESS') return `http://${id}`
  if (t === 'CIDR') return `http://${id}`
  return `https://${id}`
}

export default function BugBountyPage() {
  const navigate = useNavigate()

  // Connection state
  const [connected, setConnected] = useState<boolean | null>(null)
  const [connectionError, setConnectionError] = useState('')
  const [programs, setPrograms] = useState<BugBountyProgram[]>([])
  const [loadingPrograms, setLoadingPrograms] = useState(false)

  // Program selection
  const [selectedProgram, setSelectedProgram] = useState('')
  const [scope, setScope] = useState<BugBountyScope | null>(null)
  const [loadingScope, setLoadingScope] = useState(false)

  // Scope checker
  const [scopeCheckUrl, setScopeCheckUrl] = useState('')
  const [scopeCheckResult, setScopeCheckResult] = useState<{ url: string; in_scope: boolean } | null>(null)
  const [checkingScope, setCheckingScope] = useState(false)

  // Submissions
  const [submissions, setSubmissions] = useState<BugBountySubmission[]>([])
  const [loadingSubmissions, setLoadingSubmissions] = useState(false)

  // Asset selection & launch
  const [selectedAssets, setSelectedAssets] = useState<Set<number>>(new Set())
  const [showLaunchOptions, setShowLaunchOptions] = useState(false)
  const [launchObjective, setLaunchObjective] = useState('')
  const [launchMaxSteps, setLaunchMaxSteps] = useState(100)
  const [isLaunching, setIsLaunching] = useState(false)

  useEffect(() => {
    checkConnection()
    loadSubmissions()
  }, [])

  const checkConnection = async () => {
    try {
      const result = await bugBountyApi.testConnection()
      setConnected(result.success)
      setConnectionError(result.error || '')
      if (result.success) {
        loadPrograms()
      }
    } catch (err: any) {
      if (err?.response?.status === 403) {
        setConnected(false)
        setConnectionError('Bug bounty integration is disabled. Enable it in Settings.')
      } else {
        setConnected(false)
        setConnectionError('Failed to connect')
      }
    }
  }

  const loadPrograms = async () => {
    setLoadingPrograms(true)
    try {
      const data = await bugBountyApi.listPrograms()
      setPrograms(data.programs)
    } catch {
      setPrograms([])
    } finally {
      setLoadingPrograms(false)
    }
  }

  const loadScope = async (handle: string) => {
    if (!handle) { setScope(null); return }
    setLoadingScope(true)
    try {
      const data = await bugBountyApi.getProgramScope(handle)
      setScope(data)
    } catch {
      setScope(null)
    } finally {
      setLoadingScope(false)
    }
  }

  const loadSubmissions = async () => {
    setLoadingSubmissions(true)
    try {
      const data = await bugBountyApi.listSubmissions()
      setSubmissions(data.submissions)
    } catch {
      setSubmissions([])
    } finally {
      setLoadingSubmissions(false)
    }
  }

  const handleProgramChange = (handle: string) => {
    setSelectedProgram(handle)
    setScopeCheckResult(null)
    setSelectedAssets(new Set())
    setShowLaunchOptions(false)
    if (handle) loadScope(handle)
    else setScope(null)
  }

  const toggleAsset = (idx: number) => {
    setSelectedAssets(prev => {
      const next = new Set(prev)
      if (next.has(idx)) next.delete(idx)
      else next.add(idx)
      return next
    })
  }

  const toggleAllAssets = () => {
    if (!scope) return
    if (selectedAssets.size === scope.in_scope.length) {
      setSelectedAssets(new Set())
    } else {
      setSelectedAssets(new Set(scope.in_scope.map((_, i) => i)))
    }
  }

  const handleLaunchAgent = async () => {
    if (!scope || selectedAssets.size === 0) return
    setIsLaunching(true)
    try {
      const assets = Array.from(selectedAssets).sort((a, b) => a - b).map(i => scope.in_scope[i])
      const urls = assets.map(assetToUrl)
      const [target, ...rest] = urls

      const resp = await agentV2Api.start({
        target,
        additional_targets: rest.length > 0 ? rest : undefined,
        objective: launchObjective.trim() || undefined,
        max_steps: launchMaxSteps,
        scope_profile: 'bug_bounty',
        bugbounty_platform: 'hackerone',
        bugbounty_program: selectedProgram,
      })
      navigate(`/agent/${resp.operation_id}`)
    } catch (err: any) {
      console.error('Failed to launch agent:', err)
      alert(err?.response?.data?.detail || 'Failed to launch agent')
    } finally {
      setIsLaunching(false)
    }
  }

  const handleScopeCheck = async () => {
    if (!scopeCheckUrl || !selectedProgram) return
    setCheckingScope(true)
    try {
      const result = await bugBountyApi.checkScope(selectedProgram, scopeCheckUrl)
      setScopeCheckResult(result)
    } catch {
      setScopeCheckResult(null)
    } finally {
      setCheckingScope(false)
    }
  }

  const statusBadge = (status: string) => {
    const colors: Record<string, string> = {
      draft: 'bg-gray-500/20 text-gray-400',
      ready: 'bg-blue-500/20 text-blue-400',
      submitted: 'bg-purple-500/20 text-purple-400',
      triaged: 'bg-yellow-500/20 text-yellow-400',
      resolved: 'bg-green-500/20 text-green-400',
      duplicate: 'bg-red-500/20 text-red-400',
    }
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[status] || 'bg-dark-700 text-dark-400'}`}>
        {status}
      </span>
    )
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fadeIn">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Bug className="w-7 h-7 text-red-400" />
            Bug Bounty
          </h1>
          <p className="text-dark-400 mt-1">HackerOne integration — scope awareness, duplicate detection, report drafting</p>
        </div>
      </div>

      {/* Connection Panel */}
      <Card title="HackerOne Connection">
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            {connected === null ? (
              <div className="w-3 h-3 rounded-full bg-dark-600 animate-pulse" />
            ) : connected ? (
              <CheckCircle className="w-5 h-5 text-green-400" />
            ) : (
              <XCircle className="w-5 h-5 text-red-400" />
            )}
            <span className={`text-sm font-medium ${connected ? 'text-green-400' : connected === false ? 'text-red-400' : 'text-dark-400'}`}>
              {connected === null ? 'Checking connection...' : connected ? 'Connected to HackerOne' : 'Not connected'}
            </span>
          </div>

          {connected === false && (
            <div className="text-sm text-dark-400">
              {connectionError && <p className="text-red-400 mb-2">{connectionError}</p>}
              <Link to="/settings" className="inline-flex items-center gap-1 text-primary-400 hover:text-primary-300">
                <Settings className="w-4 h-4" />
                Configure in Settings
              </Link>
            </div>
          )}

          {connected && (
            <div>
              <label className="block text-sm font-medium text-dark-200 mb-2">Select Program</label>
              <select
                value={selectedProgram}
                onChange={(e) => handleProgramChange(e.target.value)}
                disabled={loadingPrograms}
                className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white focus:outline-none focus:border-primary-500 transition-colors"
              >
                <option value="">— Select a program —</option>
                {programs.map((p) => (
                  <option key={p.handle} value={p.handle}>
                    {p.name || p.handle} {p.offers_bounties ? '($)' : ''}
                  </option>
                ))}
              </select>
              {loadingPrograms && <p className="text-xs text-dark-500 mt-1">Loading programs...</p>}
              {!loadingPrograms && programs.length === 0 && connected && (
                <p className="text-xs text-dark-500 mt-1">No programs found. Verify your H1 credentials have program access.</p>
              )}
            </div>
          )}
        </div>
      </Card>

      {/* Program Scope Panel */}
      {selectedProgram && (
        <Card title="Program Scope" subtitle={selectedProgram}>
          {loadingScope ? (
            <p className="text-dark-400 text-sm">Loading scope...</p>
          ) : scope ? (
            <div className="space-y-4">
              {/* Summary */}
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center p-3 bg-dark-900/50 rounded-lg">
                  <p className="text-xl font-bold text-green-400">{scope.in_scope_count}</p>
                  <p className="text-xs text-dark-500">In Scope</p>
                </div>
                <div className="text-center p-3 bg-dark-900/50 rounded-lg">
                  <p className="text-xl font-bold text-red-400">{scope.out_of_scope_count}</p>
                  <p className="text-xs text-dark-500">Out of Scope</p>
                </div>
                <div className="text-center p-3 bg-dark-900/50 rounded-lg">
                  <p className="text-xl font-bold text-yellow-400">{scope.bounty_eligible_count}</p>
                  <p className="text-xs text-dark-500">Bounty Eligible</p>
                </div>
              </div>

              {/* Scope table */}
              {scope.in_scope.length > 0 && (
                <div>
                  <h3 className="text-sm font-medium text-dark-200 mb-2">In-Scope Assets</h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-dark-700">
                          <th className="py-2 px-3 w-8">
                            <input
                              type="checkbox"
                              checked={selectedAssets.size === scope.in_scope.length && scope.in_scope.length > 0}
                              onChange={toggleAllAssets}
                              className="w-4 h-4 rounded bg-dark-900 border-dark-600 text-primary-500 focus:ring-primary-500 cursor-pointer"
                            />
                          </th>
                          <th className="text-left py-2 px-3 text-dark-400 font-medium">Asset</th>
                          <th className="text-left py-2 px-3 text-dark-400 font-medium">Type</th>
                          <th className="text-center py-2 px-3 text-dark-400 font-medium">Bounty</th>
                          <th className="text-left py-2 px-3 text-dark-400 font-medium">Max Severity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scope.in_scope.map((asset: BugBountyScopeAsset, i: number) => (
                          <tr
                            key={i}
                            onClick={() => toggleAsset(i)}
                            className={`border-b border-dark-800 cursor-pointer transition-colors ${selectedAssets.has(i) ? 'bg-primary-500/10' : 'hover:bg-dark-900/30'}`}
                          >
                            <td className="py-2 px-3" onClick={(e) => e.stopPropagation()}>
                              <input
                                type="checkbox"
                                checked={selectedAssets.has(i)}
                                onChange={() => toggleAsset(i)}
                                className="w-4 h-4 rounded bg-dark-900 border-dark-600 text-primary-500 focus:ring-primary-500 cursor-pointer"
                              />
                            </td>
                            <td className="py-2 px-3 text-white font-mono text-xs">{asset.asset_identifier}</td>
                            <td className="py-2 px-3 text-dark-300">{asset.asset_type}</td>
                            <td className="py-2 px-3 text-center">
                              {asset.eligible_for_bounty ? (
                                <span className="text-green-400">$</span>
                              ) : (
                                <span className="text-dark-600">—</span>
                              )}
                            </td>
                            <td className="py-2 px-3 text-dark-300">{asset.max_severity || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Launch action bar */}
                  {selectedAssets.size > 0 && (
                    <div className="mt-3 p-4 bg-dark-900/50 rounded-lg space-y-3 border border-primary-500/20">
                      <div className="flex items-center justify-between">
                        <div className="text-sm text-dark-200">
                          <span className="font-medium text-primary-400">{selectedAssets.size}</span> asset{selectedAssets.size !== 1 ? 's' : ''} selected:
                          <span className="ml-2 text-dark-400 font-mono text-xs">
                            {Array.from(selectedAssets).sort((a, b) => a - b).slice(0, 3).map(i => scope.in_scope[i].asset_identifier).join(', ')}
                            {selectedAssets.size > 3 && ` +${selectedAssets.size - 3} more`}
                          </span>
                        </div>
                        <button
                          onClick={() => setShowLaunchOptions(!showLaunchOptions)}
                          className="text-xs text-dark-400 hover:text-dark-200 flex items-center gap-1"
                        >
                          Options {showLaunchOptions ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                        </button>
                      </div>

                      {showLaunchOptions && (
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <label className="block text-xs text-dark-400 mb-1">Custom Objective</label>
                            <input
                              type="text"
                              placeholder="e.g. Focus on authentication bypasses"
                              value={launchObjective}
                              onChange={(e) => setLaunchObjective(e.target.value)}
                              className="w-full px-3 py-1.5 bg-dark-800 border border-dark-700 rounded text-white text-sm focus:outline-none focus:border-primary-500"
                            />
                          </div>
                          <div>
                            <label className="block text-xs text-dark-400 mb-1">Max Steps</label>
                            <input
                              type="number"
                              min={10}
                              max={1000}
                              value={launchMaxSteps}
                              onChange={(e) => setLaunchMaxSteps(Number(e.target.value))}
                              className="w-full px-3 py-1.5 bg-dark-800 border border-dark-700 rounded text-white text-sm focus:outline-none focus:border-primary-500"
                            />
                          </div>
                        </div>
                      )}

                      <Button
                        onClick={handleLaunchAgent}
                        isLoading={isLaunching}
                        className="w-full"
                      >
                        <Play className="w-4 h-4 mr-2" />
                        Launch Agent on {selectedAssets.size} Asset{selectedAssets.size !== 1 ? 's' : ''}
                      </Button>
                    </div>
                  )}
                </div>
              )}

              {/* URL Scope Checker */}
              <div className="p-4 bg-dark-900/50 rounded-lg space-y-3">
                <h3 className="text-sm font-medium text-dark-200 flex items-center gap-2">
                  <Search className="w-4 h-4" />
                  Check URL Scope
                </h3>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="https://example.com/path"
                    value={scopeCheckUrl}
                    onChange={(e) => setScopeCheckUrl(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleScopeCheck()}
                    className="flex-1 px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500"
                  />
                  <Button variant="secondary" onClick={handleScopeCheck} isLoading={checkingScope}>
                    Check
                  </Button>
                </div>
                {scopeCheckResult && (
                  <div className={`flex items-center gap-2 text-sm ${scopeCheckResult.in_scope ? 'text-green-400' : 'text-red-400'}`}>
                    {scopeCheckResult.in_scope ? (
                      <><CheckCircle className="w-4 h-4" /> <span className="font-mono">{scopeCheckResult.url}</span> is <strong>in scope</strong></>
                    ) : (
                      <><XCircle className="w-4 h-4" /> <span className="font-mono">{scopeCheckResult.url}</span> is <strong>out of scope</strong></>
                    )}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <p className="text-dark-400 text-sm">No scope data available</p>
          )}
        </Card>
      )}

      {/* Submissions Panel */}
      <Card title="Submissions" subtitle="Draft and submitted reports">
        {loadingSubmissions ? (
          <p className="text-dark-400 text-sm">Loading...</p>
        ) : submissions.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700">
                  <th className="text-left py-2 px-3 text-dark-400 font-medium">Title</th>
                  <th className="text-left py-2 px-3 text-dark-400 font-medium">Program</th>
                  <th className="text-center py-2 px-3 text-dark-400 font-medium">Status</th>
                  <th className="text-center py-2 px-3 text-dark-400 font-medium">Dup Score</th>
                  <th className="text-left py-2 px-3 text-dark-400 font-medium">Created</th>
                </tr>
              </thead>
              <tbody>
                {submissions.map((s) => (
                  <tr key={s.id} className="border-b border-dark-800 hover:bg-dark-900/30">
                    <td className="py-2 px-3 text-white max-w-xs truncate">{s.draft_title || '—'}</td>
                    <td className="py-2 px-3 text-dark-300">{s.program_handle || '—'}</td>
                    <td className="py-2 px-3 text-center">{statusBadge(s.status)}</td>
                    <td className="py-2 px-3 text-center text-dark-300">
                      {s.duplicate_check_score != null ? `${(s.duplicate_check_score * 100).toFixed(0)}%` : '—'}
                    </td>
                    <td className="py-2 px-3 text-dark-400 text-xs">
                      {s.created_at ? new Date(s.created_at).toLocaleDateString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8">
            <FileText className="w-10 h-10 text-dark-600 mx-auto mb-3" />
            <p className="text-dark-400 text-sm">No submissions yet</p>
            <p className="text-dark-500 text-xs mt-1">
              Draft reports from vulnerability findings will appear here.
              Use the Agent to find vulnerabilities, then generate H1 drafts from the findings.
            </p>
          </div>
        )}
      </Card>
    </div>
  )
}
