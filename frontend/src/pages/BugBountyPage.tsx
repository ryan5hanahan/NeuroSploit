import { useState, useEffect } from 'react'
import { Bug, CheckCircle, XCircle, Search, FileText, Settings } from 'lucide-react'
import { Link } from 'react-router-dom'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { bugBountyApi } from '../services/api'
import type { BugBountyProgram, BugBountyScope, BugBountyScopeAsset, BugBountySubmission } from '../types'

export default function BugBountyPage() {
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
    if (handle) loadScope(handle)
    else setScope(null)
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
                          <th className="text-left py-2 px-3 text-dark-400 font-medium">Asset</th>
                          <th className="text-left py-2 px-3 text-dark-400 font-medium">Type</th>
                          <th className="text-center py-2 px-3 text-dark-400 font-medium">Bounty</th>
                          <th className="text-left py-2 px-3 text-dark-400 font-medium">Max Severity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scope.in_scope.map((asset: BugBountyScopeAsset, i: number) => (
                          <tr key={i} className="border-b border-dark-800">
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
