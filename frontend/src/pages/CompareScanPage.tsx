import { useEffect, useState } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeftRight, Shield, Globe, ChevronDown, ChevronRight,
  Plus, Minus, RefreshCw, Equal, ArrowRight
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { SeverityBadge } from '../components/common/Badge'
import { scansApi } from '../services/api'
import type { Scan, ScanComparisonResponse } from '../types'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export default function CompareScanPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()

  const preselectedScanId = searchParams.get('scan') || ''

  const [scans, setScans] = useState<Scan[]>([])
  const [scanIdA, setScanIdA] = useState<string>(preselectedScanId)
  const [scanIdB, setScanIdB] = useState<string>('')
  const [comparison, setComparison] = useState<ScanComparisonResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [isLoadingScans, setIsLoadingScans] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'vulns' | 'endpoints'>('vulns')
  const [vulnFilter, setVulnFilter] = useState<'all' | 'new' | 'resolved' | 'persistent' | 'changed'>('all')
  const [endpointFilter, setEndpointFilter] = useState<'all' | 'new' | 'removed' | 'changed' | 'stable'>('all')

  // Load available scans
  useEffect(() => {
    const loadScans = async () => {
      setIsLoadingScans(true)
      try {
        const data = await scansApi.list(1, 100)
        const eligible = (data.scans as Scan[]).filter(
          (s) => ['completed', 'stopped', 'failed'].includes(s.status)
        )
        setScans(eligible)
      } catch {
        console.error('Failed to load scans')
      } finally {
        setIsLoadingScans(false)
      }
    }
    loadScans()
  }, [])

  // Auto-compare if URL params contain both IDs
  useEffect(() => {
    const a = searchParams.get('a')
    const b = searchParams.get('b')
    if (a && b) {
      setScanIdA(a)
      setScanIdB(b)
      runCompare(a, b)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const runCompare = async (idA?: string, idB?: string) => {
    const a = idA || scanIdA
    const b = idB || scanIdB
    if (!a || !b) return
    if (a === b) {
      setError('Please select two different scans')
      return
    }

    setIsLoading(true)
    setError(null)
    setComparison(null)
    try {
      const data = await scansApi.compare(a, b)
      setComparison(data)
      setSearchParams({ a, b })
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to compare scans')
    } finally {
      setIsLoading(false)
    }
  }

  const getScanLabel = (scan: Scan) => {
    const date = new Date(scan.created_at).toLocaleDateString()
    return `${scan.name || 'Unnamed'} (${date}) - ${scan.total_vulnerabilities} vulns`
  }

  const vulnItems = comparison ? (() => {
    if (vulnFilter === 'all') {
      return [
        ...comparison.vulnerabilities.new.map(v => ({ ...v, _diff: 'new' as const })),
        ...comparison.vulnerabilities.resolved.map(v => ({ ...v, _diff: 'resolved' as const })),
        ...comparison.vulnerabilities.changed.map(v => ({ ...v, _diff: 'changed' as const })),
        ...comparison.vulnerabilities.persistent.map(v => ({ ...v, _diff: 'persistent' as const })),
      ]
    }
    return (comparison.vulnerabilities[vulnFilter] || []).map(v => ({ ...v, _diff: vulnFilter }))
  })() : []

  const endpointItems = comparison ? (() => {
    if (endpointFilter === 'all') {
      return [
        ...comparison.endpoints.new.map(e => ({ ...e, _diff: 'new' as const })),
        ...comparison.endpoints.removed.map(e => ({ ...e, _diff: 'removed' as const })),
        ...comparison.endpoints.changed.map(e => ({ ...e, _diff: 'changed' as const })),
        ...comparison.endpoints.stable.map(e => ({ ...e, _diff: 'stable' as const })),
      ]
    }
    return (comparison.endpoints[endpointFilter] || []).map(e => ({ ...e, _diff: endpointFilter }))
  })() : []

  const diffColors = {
    new: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', icon: Plus, label: 'New' },
    resolved: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', icon: Minus, label: 'Resolved' },
    removed: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', icon: Minus, label: 'Removed' },
    changed: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', icon: ArrowRight, label: 'Changed' },
    persistent: { bg: 'bg-dark-700/50', border: 'border-dark-600/30', text: 'text-dark-400', icon: Equal, label: 'Unchanged' },
    stable: { bg: 'bg-dark-700/50', border: 'border-dark-600/30', text: 'text-dark-400', icon: Equal, label: 'Stable' },
  }

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <ArrowLeftRight className="w-6 h-6 text-primary-500" />
          Compare Scans
        </h2>
        <Button variant="ghost" onClick={() => navigate('/')}>Back to Dashboard</Button>
      </div>

      {/* Scan Selectors */}
      <Card>
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <label className="block text-sm text-dark-400 mb-1">Scan A (baseline)</label>
            <select
              value={scanIdA}
              onChange={(e) => setScanIdA(e.target.value)}
              className="w-full bg-dark-700 text-white border border-dark-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-primary-500"
              disabled={isLoadingScans}
            >
              <option value="">Select a scan...</option>
              {scans.map(s => (
                <option key={s.id} value={s.id}>{getScanLabel(s)}</option>
              ))}
            </select>
          </div>

          <div className="flex items-center pt-5">
            <ArrowLeftRight className="w-5 h-5 text-dark-400" />
          </div>

          <div className="flex-1">
            <label className="block text-sm text-dark-400 mb-1">Scan B (comparison)</label>
            <select
              value={scanIdB}
              onChange={(e) => setScanIdB(e.target.value)}
              className="w-full bg-dark-700 text-white border border-dark-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-primary-500"
              disabled={isLoadingScans}
            >
              <option value="">Select a scan...</option>
              {scans.map(s => (
                <option key={s.id} value={s.id}>{getScanLabel(s)}</option>
              ))}
            </select>
          </div>

          <div className="pt-5">
            <Button
              onClick={() => runCompare()}
              isLoading={isLoading}
              disabled={!scanIdA || !scanIdB}
            >
              Compare
            </Button>
          </div>
        </div>

        {error && (
          <div className="mt-3 text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
            {error}
          </div>
        )}
      </Card>

      {isLoading && (
        <div className="flex items-center justify-center h-32">
          <RefreshCw className="w-8 h-8 animate-spin text-primary-500" />
        </div>
      )}

      {comparison && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4 text-center">
              <div className="text-3xl font-bold text-green-400">{comparison.summary.vuln_summary.new}</div>
              <div className="text-sm text-green-400/70 mt-1">New Vulns</div>
            </div>
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-center">
              <div className="text-3xl font-bold text-red-400">{comparison.summary.vuln_summary.resolved}</div>
              <div className="text-sm text-red-400/70 mt-1">Resolved</div>
            </div>
            <div className="bg-dark-800 border border-dark-600/50 rounded-xl p-4 text-center">
              <div className="text-3xl font-bold text-dark-300">{comparison.summary.vuln_summary.persistent}</div>
              <div className="text-sm text-dark-400 mt-1">Unchanged</div>
            </div>
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4 text-center">
              <div className="text-3xl font-bold text-yellow-400">{comparison.summary.vuln_summary.changed}</div>
              <div className="text-sm text-yellow-400/70 mt-1">Changed</div>
            </div>
          </div>

          {/* Scan Info Cards */}
          <div className="grid grid-cols-2 gap-4">
            {(['scan_a', 'scan_b'] as const).map((key, idx) => {
              const info = comparison.summary[key] as Record<string, any>
              return (
                <Card key={key}>
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <div className="text-xs text-dark-400 uppercase tracking-wider">
                        Scan {idx === 0 ? 'A (Baseline)' : 'B (Comparison)'}
                      </div>
                      <div className="text-lg font-semibold text-white mt-1">
                        {info.name || 'Unnamed Scan'}
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => navigate(`/scan/${info.id}`)}
                    >
                      View
                    </Button>
                  </div>
                  <div className="grid grid-cols-3 gap-3 text-sm">
                    <div>
                      <span className="text-dark-400">Date: </span>
                      <span className="text-white">{info.created_at ? new Date(info.created_at).toLocaleDateString() : 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-dark-400">Endpoints: </span>
                      <span className="text-white">{info.total_endpoints}</span>
                    </div>
                    <div>
                      <span className="text-dark-400">Vulns: </span>
                      <span className="text-white">{info.total_vulnerabilities}</span>
                    </div>
                  </div>
                  <div className="flex gap-2 mt-3">
                    {SEVERITY_ORDER.map(sev => {
                      const count = info[`${sev}_count`] || 0
                      if (count === 0) return null
                      return (
                        <SeverityBadge key={sev} severity={sev}>
                          {sev.charAt(0).toUpperCase()}: {count}
                        </SeverityBadge>
                      )
                    })}
                  </div>
                </Card>
              )
            })}
          </div>

          {/* Tabs */}
          <div className="flex gap-2">
            <Button
              variant={activeTab === 'vulns' ? 'primary' : 'ghost'}
              onClick={() => setActiveTab('vulns')}
            >
              <Shield className="w-4 h-4 mr-2" />
              Vulnerabilities ({
                comparison.summary.vuln_summary.new +
                comparison.summary.vuln_summary.resolved +
                comparison.summary.vuln_summary.persistent +
                comparison.summary.vuln_summary.changed
              })
            </Button>
            <Button
              variant={activeTab === 'endpoints' ? 'primary' : 'ghost'}
              onClick={() => setActiveTab('endpoints')}
            >
              <Globe className="w-4 h-4 mr-2" />
              Endpoints ({
                comparison.summary.endpoint_summary.new +
                comparison.summary.endpoint_summary.removed +
                comparison.summary.endpoint_summary.changed +
                comparison.summary.endpoint_summary.stable
              })
            </Button>
          </div>

          {/* Vulnerabilities Tab */}
          {activeTab === 'vulns' && (
            <Card>
              <div className="flex gap-2 mb-4 flex-wrap">
                {(['all', 'new', 'resolved', 'persistent', 'changed'] as const).map(f => {
                  const count = f === 'all'
                    ? comparison.summary.vuln_summary.new + comparison.summary.vuln_summary.resolved + comparison.summary.vuln_summary.persistent + comparison.summary.vuln_summary.changed
                    : comparison.summary.vuln_summary[f]
                  return (
                    <button
                      key={f}
                      onClick={() => setVulnFilter(f)}
                      className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                        vulnFilter === f
                          ? 'bg-primary-500/20 text-primary-400 border border-primary-500/30'
                          : 'bg-dark-700 text-dark-400 border border-dark-600/50 hover:text-white'
                      }`}
                    >
                      {f.charAt(0).toUpperCase() + f.slice(1)} ({count})
                    </button>
                  )
                })}
              </div>

              {vulnItems.length === 0 ? (
                <div className="text-center text-dark-400 py-8">No vulnerabilities in this category</div>
              ) : (
                <div className="space-y-2">
                  {vulnItems.map((vuln, idx) => {
                    const style = diffColors[vuln._diff]
                    const Icon = style.icon
                    return (
                      <div key={vuln.id || idx} className={`${style.bg} border ${style.border} rounded-lg p-3`}>
                        <div className="flex items-center gap-3">
                          <Icon className={`w-4 h-4 ${style.text} flex-shrink-0`} />
                          <span className={`text-xs font-medium px-2 py-0.5 rounded ${style.bg} ${style.text} border ${style.border}`}>
                            {style.label}
                          </span>
                          <SeverityBadge severity={vuln.severity} />
                          <span className="text-white font-medium flex-1 truncate">{vuln.title}</span>
                          {vuln.cvss_score && (
                            <span className="text-dark-400 text-sm">CVSS: {vuln.cvss_score}</span>
                          )}
                        </div>
                        <div className="mt-2 ml-7 text-sm text-dark-400">
                          <span>{vuln.vulnerability_type}</span>
                          {vuln.affected_endpoint && (
                            <span className="ml-3 text-dark-500">{vuln.affected_endpoint}</span>
                          )}
                        </div>
                        {vuln._diff === 'changed' && (
                          <div className="mt-2 ml-7 flex gap-4 text-xs">
                            {(vuln as any).severity_changed && (
                              <span className="text-yellow-400">
                                Severity: {(vuln as any).severity_changed.from} <ArrowRight className="w-3 h-3 inline" /> {(vuln as any).severity_changed.to}
                              </span>
                            )}
                            {(vuln as any).cvss_changed && (
                              <span className="text-yellow-400">
                                CVSS: {(vuln as any).cvss_changed.from ?? 'N/A'} <ArrowRight className="w-3 h-3 inline" /> {(vuln as any).cvss_changed.to ?? 'N/A'}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </Card>
          )}

          {/* Endpoints Tab */}
          {activeTab === 'endpoints' && (
            <Card>
              <div className="flex gap-2 mb-4 flex-wrap">
                {(['all', 'new', 'removed', 'changed', 'stable'] as const).map(f => {
                  const count = f === 'all'
                    ? comparison.summary.endpoint_summary.new + comparison.summary.endpoint_summary.removed + comparison.summary.endpoint_summary.changed + comparison.summary.endpoint_summary.stable
                    : comparison.summary.endpoint_summary[f]
                  return (
                    <button
                      key={f}
                      onClick={() => setEndpointFilter(f)}
                      className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                        endpointFilter === f
                          ? 'bg-primary-500/20 text-primary-400 border border-primary-500/30'
                          : 'bg-dark-700 text-dark-400 border border-dark-600/50 hover:text-white'
                      }`}
                    >
                      {f.charAt(0).toUpperCase() + f.slice(1)} ({count})
                    </button>
                  )
                })}
              </div>

              {endpointItems.length === 0 ? (
                <div className="text-center text-dark-400 py-8">No endpoints in this category</div>
              ) : (
                <div className="space-y-2">
                  {endpointItems.map((ep, idx) => {
                    const style = diffColors[ep._diff]
                    const Icon = style.icon
                    return (
                      <div key={ep.id || idx} className={`${style.bg} border ${style.border} rounded-lg p-3`}>
                        <div className="flex items-center gap-3">
                          <Icon className={`w-4 h-4 ${style.text} flex-shrink-0`} />
                          <span className={`text-xs font-medium px-2 py-0.5 rounded ${style.bg} ${style.text} border ${style.border}`}>
                            {style.label}
                          </span>
                          <span className="text-xs font-mono bg-dark-700 px-2 py-0.5 rounded text-blue-400">
                            {ep.method}
                          </span>
                          <span className="text-white text-sm flex-1 truncate font-mono">{ep.url}</span>
                          {ep.response_status && (
                            <span className={`text-sm ${ep.response_status >= 400 ? 'text-red-400' : 'text-green-400'}`}>
                              {ep.response_status}
                            </span>
                          )}
                        </div>
                        {ep._diff === 'changed' && (ep as any).changes && (
                          <div className="mt-2 ml-7 text-xs space-y-1">
                            {Object.entries((ep as any).changes).map(([field, change]: [string, any]) => (
                              <div key={field} className="text-yellow-400">
                                {field}: {JSON.stringify(change.from)} <ArrowRight className="w-3 h-3 inline" /> {JSON.stringify(change.to)}
                              </div>
                            ))}
                          </div>
                        )}
                        {ep.technologies && ep.technologies.length > 0 && (
                          <div className="mt-1 ml-7 flex gap-1 flex-wrap">
                            {ep.technologies.map((tech, i) => (
                              <span key={i} className="text-xs bg-dark-700 text-dark-400 px-1.5 py-0.5 rounded">
                                {tech}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </Card>
          )}
        </>
      )}
    </div>
  )
}
