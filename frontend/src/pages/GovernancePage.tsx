import { useState, useEffect, useCallback } from 'react'
import {
  Shield, CheckCircle, XCircle,
  ChevronDown, ChevronRight, RefreshCw,
  Plus, Trash2, Save, Eye,
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import { governanceApi } from '../services/api'
import type { GovernanceOverview, GovernanceViolation, GovernanceProfile } from '../types'

// Phase policy matrix data for visualization
const PHASES = [
  'initializing', 'passive_recon', 'recon', 'analyzing',
  'testing', 'exploitation', 'full_auto', 'post_exploitation', 'reporting', 'completed',
]
const ACTION_CATEGORIES = [
  'passive_recon', 'active_recon', 'analysis',
  'vulnerability_scan', 'exploitation', 'post_exploitation', 'reporting',
]
const PHASE_POLICY: Record<string, string[]> = {
  initializing: ['passive_recon', 'active_recon', 'analysis', 'reporting'],
  passive_recon: ['passive_recon', 'analysis', 'reporting'],
  recon: ['passive_recon', 'active_recon', 'analysis', 'reporting'],
  analyzing: ['passive_recon', 'analysis', 'reporting'],
  testing: ['passive_recon', 'active_recon', 'analysis', 'vulnerability_scan', 'reporting'],
  exploitation: ['passive_recon', 'active_recon', 'analysis', 'vulnerability_scan', 'exploitation', 'reporting'],
  full_auto: ['passive_recon', 'active_recon', 'analysis', 'vulnerability_scan', 'exploitation', 'reporting'],
  post_exploitation: ['passive_recon', 'active_recon', 'analysis', 'vulnerability_scan', 'exploitation', 'post_exploitation', 'reporting'],
  reporting: ['reporting', 'analysis'],
  completed: ['reporting', 'analysis'],
}

const SCOPE_PROFILES = ['bug_bounty', 'ctf', 'pentest', 'auto_pwn']
const GOV_MODES = ['strict', 'warn', 'off']
const RECON_DEPTHS = ['quick', 'medium', 'full']
const FALLBACK_POLICIES = ['allow', 'warn', 'deny']

function dispositionBadge(disposition: string) {
  return disposition === 'blocked' ? (
    <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-500/20 text-red-400">blocked</span>
  ) : (
    <span className="px-2 py-0.5 rounded text-xs font-medium bg-yellow-500/20 text-yellow-400">warned</span>
  )
}

function layerBadge(layer: string) {
  return layer === 'scope' ? (
    <span className="px-2 py-0.5 rounded text-xs font-medium bg-blue-500/20 text-blue-400">scope</span>
  ) : (
    <span className="px-2 py-0.5 rounded text-xs font-medium bg-purple-500/20 text-purple-400">phase</span>
  )
}

const defaultProfile: Partial<GovernanceProfile> = {
  name: '',
  description: '',
  scope_profile: 'full_auto',
  governance_mode: 'warn',
  allowed_vuln_types: [],
  include_subdomains: true,
  max_recon_depth: 'medium',
  max_steps: 100,
  max_duration_seconds: 3600,
  budget_usd: 5.0,
  sandbox_fallback_policy: 'warn',
}

export default function GovernancePage() {
  const [overview, setOverview] = useState<GovernanceOverview | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  // Section collapse state
  const [policyExpanded, setPolicyExpanded] = useState(false)

  // Profiles
  const [profiles, setProfiles] = useState<GovernanceProfile[]>([])
  const [loadingProfiles, setLoadingProfiles] = useState(false)
  const [editingProfile, setEditingProfile] = useState<Partial<GovernanceProfile> | null>(null)
  const [savingProfile, setSavingProfile] = useState(false)
  const [profileError, setProfileError] = useState('')

  const loadOverview = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const data = await governanceApi.overview()
      setOverview(data)
    } catch (err: any) {
      setError(err?.message || 'Failed to load governance overview')
    } finally {
      setLoading(false)
    }
  }, [])

  const loadProfiles = useCallback(async () => {
    setLoadingProfiles(true)
    try {
      const data = await governanceApi.listProfiles()
      setProfiles(data.profiles)
    } catch {
      setProfiles([])
    } finally {
      setLoadingProfiles(false)
    }
  }, [])

  useEffect(() => {
    loadOverview()
    loadProfiles()
  }, [loadOverview, loadProfiles])

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(loadOverview, 30000)
    return () => clearInterval(interval)
  }, [loadOverview])

  const handleSaveProfile = async () => {
    if (!editingProfile?.name) {
      setProfileError('Name is required')
      return
    }
    setSavingProfile(true)
    setProfileError('')
    try {
      if (editingProfile.id) {
        await governanceApi.updateProfile(editingProfile.id, editingProfile)
      } else {
        await governanceApi.createProfile(editingProfile)
      }
      setEditingProfile(null)
      await loadProfiles()
    } catch (err: any) {
      setProfileError(err?.response?.data?.detail || 'Failed to save profile')
    } finally {
      setSavingProfile(false)
    }
  }

  const handleDeleteProfile = async (id: string) => {
    try {
      await governanceApi.deleteProfile(id)
      await loadProfiles()
    } catch {
      // ignore
    }
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Shield className="w-7 h-7 text-primary-400" />
            Governance
          </h1>
          <p className="text-dark-400 mt-1">Scope enforcement, phase control, and audit trail</p>
        </div>
        <Button variant="secondary" onClick={loadOverview} isLoading={loading}>
          <RefreshCw className="w-4 h-4" />
          Refresh
        </Button>
      </div>

      {error && (
        <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">
          {error}
        </div>
      )}

      {/* Stats Cards */}
      {overview && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 bg-dark-800 rounded-lg border border-dark-700">
            <p className="text-2xl font-bold text-white">{overview.total_violations}</p>
            <p className="text-xs text-dark-400 mt-1">Total Violations</p>
          </div>
          <div className="p-4 bg-dark-800 rounded-lg border border-dark-700">
            <p className="text-2xl font-bold text-red-400">{overview.blocked}</p>
            <p className="text-xs text-dark-400 mt-1">Blocked</p>
          </div>
          <div className="p-4 bg-dark-800 rounded-lg border border-dark-700">
            <p className="text-2xl font-bold text-yellow-400">{overview.warned}</p>
            <p className="text-xs text-dark-400 mt-1">Warned</p>
          </div>
          <div className="p-4 bg-dark-800 rounded-lg border border-dark-700">
            <p className="text-2xl font-bold text-primary-400">{overview.scans_with_violations}</p>
            <p className="text-xs text-dark-400 mt-1">Scans w/ Violations</p>
          </div>
        </div>
      )}

      {/* Violations by Layer */}
      {overview && (overview.scope_violations > 0 || overview.phase_violations > 0) && (
        <div className="grid grid-cols-2 gap-4">
          <div className="p-4 bg-dark-800 rounded-lg border border-dark-700">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2 h-2 rounded-full bg-blue-400" />
              <p className="text-sm font-medium text-dark-200">Scope Violations</p>
            </div>
            <p className="text-xl font-bold text-blue-400">{overview.scope_violations}</p>
            <p className="text-xs text-dark-500 mt-1">Out-of-scope targets, blocked vuln types</p>
          </div>
          <div className="p-4 bg-dark-800 rounded-lg border border-dark-700">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2 h-2 rounded-full bg-purple-400" />
              <p className="text-sm font-medium text-dark-200">Phase Violations</p>
            </div>
            <p className="text-xl font-bold text-purple-400">{overview.phase_violations}</p>
            <p className="text-xs text-dark-500 mt-1">Wrong-phase actions, invalid transitions</p>
          </div>
        </div>
      )}

      {/* Violations by Category */}
      {overview && Object.keys(overview.by_category).length > 0 && (
        <Card title="Violations by Category">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(overview.by_category)
              .sort((a, b) => b[1] - a[1])
              .map(([cat, count]) => (
                <div key={cat} className="flex items-center justify-between p-2 bg-dark-900/50 rounded">
                  <span className="text-sm text-dark-300 truncate">{cat}</span>
                  <span className="text-sm font-mono font-bold text-dark-200">{count}</span>
                </div>
              ))}
          </div>
        </Card>
      )}

      {/* Phase Policy Matrix */}
      <Card title="Phase Policy Matrix">
        <div>
          <button
            onClick={() => setPolicyExpanded(!policyExpanded)}
            className="flex items-center gap-2 text-sm text-dark-300 hover:text-white transition-colors mb-3"
          >
            {policyExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            {policyExpanded ? 'Collapse' : 'Expand'} policy matrix
          </button>

          {policyExpanded && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-dark-700">
                    <th className="text-left py-2 px-2 text-dark-400 font-medium">Phase</th>
                    {ACTION_CATEGORIES.map((cat) => (
                      <th key={cat} className="text-center py-2 px-1 text-dark-400 font-medium whitespace-nowrap">
                        {cat.replace('_', ' ')}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {PHASES.map((phase) => (
                    <tr key={phase} className="border-b border-dark-800">
                      <td className="py-2 px-2 text-dark-200 font-mono whitespace-nowrap">{phase}</td>
                      {ACTION_CATEGORIES.map((cat) => {
                        const allowed = PHASE_POLICY[phase]?.includes(cat)
                        return (
                          <td key={cat} className="text-center py-2 px-1">
                            {allowed ? (
                              <CheckCircle className="w-3.5 h-3.5 text-green-400 mx-auto" />
                            ) : (
                              <XCircle className="w-3.5 h-3.5 text-red-400/50 mx-auto" />
                            )}
                          </td>
                        )
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Card>

      {/* Recent Violations Feed */}
      <Card title="Recent Violations" subtitle="Last 50 across all operations">
        {!overview || overview.recent_violations.length === 0 ? (
          <div className="text-center py-8">
            <CheckCircle className="w-10 h-10 text-green-500/30 mx-auto mb-3" />
            <p className="text-dark-400 text-sm">No governance violations recorded</p>
            <p className="text-dark-500 text-xs mt-1">
              Violations appear when the agent attempts actions outside its configured scope or phase.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700">
                  <th className="text-left py-2 px-3 text-dark-400 font-medium">Time</th>
                  <th className="text-center py-2 px-3 text-dark-400 font-medium">Layer</th>
                  <th className="text-center py-2 px-3 text-dark-400 font-medium">Disposition</th>
                  <th className="text-left py-2 px-3 text-dark-400 font-medium">Action</th>
                  <th className="text-left py-2 px-3 text-dark-400 font-medium">Phase</th>
                  <th className="text-left py-2 px-3 text-dark-400 font-medium">Detail</th>
                </tr>
              </thead>
              <tbody>
                {overview.recent_violations.map((v: GovernanceViolation, i: number) => (
                  <ViolationRow key={v.id || i} violation={v} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Governance Profiles */}
      <Card
        title="Governance Profiles"
        subtitle="Reusable governance configurations"
      >
        <div className="space-y-4">
          {/* Profile list */}
          {loadingProfiles ? (
            <p className="text-dark-400 text-sm">Loading profiles...</p>
          ) : profiles.length > 0 ? (
            <div className="space-y-2">
              {profiles.map((p) => (
                <div key={p.id} className="flex items-center justify-between p-3 bg-dark-900/50 rounded-lg">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-white">{p.name}</span>
                      <span className="px-2 py-0.5 rounded text-xs font-medium bg-dark-700 text-dark-300">
                        {p.scope_profile}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        p.governance_mode === 'strict' ? 'bg-red-500/20 text-red-400' :
                        p.governance_mode === 'warn' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-dark-700 text-dark-400'
                      }`}>
                        {p.governance_mode}
                      </span>
                    </div>
                    {p.description && (
                      <p className="text-xs text-dark-400 mt-1 truncate">{p.description}</p>
                    )}
                  </div>
                  <div className="flex items-center gap-2 ml-4">
                    <button
                      onClick={() => setEditingProfile({ ...p })}
                      className="p-1.5 text-dark-400 hover:text-white transition-colors"
                      title="Edit profile"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDeleteProfile(p.id)}
                      className="p-1.5 text-dark-400 hover:text-red-400 transition-colors"
                      title="Delete profile"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-dark-500 text-sm">No custom profiles yet.</p>
          )}

          {/* Create / Edit form */}
          {editingProfile ? (
            <ProfileEditor
              profile={editingProfile}
              onChange={setEditingProfile}
              onSave={handleSaveProfile}
              onCancel={() => { setEditingProfile(null); setProfileError('') }}
              saving={savingProfile}
              error={profileError}
            />
          ) : (
            <Button
              variant="secondary"
              onClick={() => setEditingProfile({ ...defaultProfile })}
              className="w-full"
            >
              <Plus className="w-4 h-4" />
              Create Profile
            </Button>
          )}
        </div>
      </Card>
    </div>
  )
}

function ViolationRow({ violation: v }: { violation: GovernanceViolation }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <>
      <tr
        className="border-b border-dark-800 hover:bg-dark-900/30 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <td className="py-2 px-3 text-dark-400 text-xs whitespace-nowrap">
          {v.created_at ? new Date(v.created_at).toLocaleString() : '--'}
        </td>
        <td className="py-2 px-3 text-center">{layerBadge(v.layer)}</td>
        <td className="py-2 px-3 text-center">{dispositionBadge(v.disposition)}</td>
        <td className="py-2 px-3 text-white font-mono text-xs max-w-xs truncate">
          {v.action || '--'}
        </td>
        <td className="py-2 px-3 text-dark-300 text-xs">{v.phase || '--'}</td>
        <td className="py-2 px-3 text-dark-400 text-xs max-w-sm truncate">
          {v.detail || v.action_category || '--'}
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-dark-800 bg-dark-900/20">
          <td colSpan={6} className="py-3 px-6">
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <span className="text-dark-500">Scan ID:</span>{' '}
                <span className="text-dark-300 font-mono">{v.scan_id}</span>
              </div>
              <div>
                <span className="text-dark-500">Category:</span>{' '}
                <span className="text-dark-300">{v.action_category}</span>
              </div>
              {v.allowed_categories && v.allowed_categories.length > 0 && (
                <div className="col-span-2">
                  <span className="text-dark-500">Allowed categories:</span>{' '}
                  <span className="text-dark-300">{v.allowed_categories.join(', ')}</span>
                </div>
              )}
              {v.context && Object.keys(v.context).length > 0 && (
                <div className="col-span-2">
                  <span className="text-dark-500">Context:</span>
                  <pre className="mt-1 p-2 bg-dark-900 rounded text-dark-300 overflow-x-auto">
                    {JSON.stringify(v.context, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function ProfileEditor({
  profile,
  onChange,
  onSave,
  onCancel,
  saving,
  error,
}: {
  profile: Partial<GovernanceProfile>
  onChange: (p: Partial<GovernanceProfile>) => void
  onSave: () => void
  onCancel: () => void
  saving: boolean
  error: string
}) {
  const update = (fields: Partial<GovernanceProfile>) => onChange({ ...profile, ...fields })

  return (
    <div className="p-4 bg-dark-900/50 rounded-lg border border-dark-700 space-y-4">
      <h3 className="text-sm font-medium text-white">
        {profile.id ? 'Edit Profile' : 'New Profile'}
      </h3>

      {error && (
        <p className="text-xs text-red-400">{error}</p>
      )}

      <div className="grid grid-cols-2 gap-4">
        {/* Name */}
        <div className="col-span-2 sm:col-span-1">
          <label className="block text-xs text-dark-400 mb-1">Name</label>
          <input
            type="text"
            value={profile.name || ''}
            onChange={(e) => update({ name: e.target.value })}
            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500"
            placeholder="My Profile"
          />
        </div>

        {/* Description */}
        <div className="col-span-2 sm:col-span-1">
          <label className="block text-xs text-dark-400 mb-1">Description</label>
          <input
            type="text"
            value={profile.description || ''}
            onChange={(e) => update({ description: e.target.value })}
            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500"
            placeholder="Optional description"
          />
        </div>

        {/* Scope Profile */}
        <div>
          <label className="block text-xs text-dark-400 mb-1">Scope Profile</label>
          <select
            value={profile.scope_profile || 'full_auto'}
            onChange={(e) => update({ scope_profile: e.target.value })}
            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500"
          >
            {SCOPE_PROFILES.map((sp) => (
              <option key={sp} value={sp}>{sp}</option>
            ))}
          </select>
        </div>

        {/* Governance Mode */}
        <div>
          <label className="block text-xs text-dark-400 mb-1">Governance Mode</label>
          <select
            value={profile.governance_mode || 'warn'}
            onChange={(e) => update({ governance_mode: e.target.value })}
            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500"
          >
            {GOV_MODES.map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
        </div>

        {/* Recon Depth */}
        <div>
          <label className="block text-xs text-dark-400 mb-1">Recon Depth</label>
          <select
            value={profile.max_recon_depth || 'medium'}
            onChange={(e) => update({ max_recon_depth: e.target.value })}
            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500"
          >
            {RECON_DEPTHS.map((d) => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
        </div>

        {/* Sandbox Fallback */}
        <div>
          <label className="block text-xs text-dark-400 mb-1">Sandbox Fallback</label>
          <select
            value={profile.sandbox_fallback_policy || 'warn'}
            onChange={(e) => update({ sandbox_fallback_policy: e.target.value })}
            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500"
          >
            {FALLBACK_POLICIES.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </div>

        {/* Max Steps */}
        <div>
          <label className="block text-xs text-dark-400 mb-1">Max Steps</label>
          <input
            type="number"
            value={profile.max_steps ?? 100}
            onChange={(e) => update({ max_steps: parseInt(e.target.value) || 100 })}
            min={1}
            max={500}
            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500"
          />
        </div>

        {/* Max Duration */}
        <div>
          <label className="block text-xs text-dark-400 mb-1">Max Duration (seconds)</label>
          <input
            type="number"
            value={profile.max_duration_seconds ?? 3600}
            onChange={(e) => update({ max_duration_seconds: parseInt(e.target.value) || 3600 })}
            min={60}
            max={86400}
            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500"
          />
        </div>

        {/* Budget */}
        <div>
          <label className="block text-xs text-dark-400 mb-1">Budget (USD)</label>
          <input
            type="number"
            value={profile.budget_usd ?? 5.0}
            onChange={(e) => update({ budget_usd: parseFloat(e.target.value) || 5.0 })}
            min={0.1}
            max={100}
            step={0.5}
            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500"
          />
        </div>

        {/* Include Subdomains */}
        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="include_subdomains"
            checked={profile.include_subdomains ?? true}
            onChange={(e) => update({ include_subdomains: e.target.checked })}
            className="rounded border-dark-600 bg-dark-800 text-primary-500 focus:ring-primary-500"
          />
          <label htmlFor="include_subdomains" className="text-xs text-dark-300">
            Include subdomains in scope
          </label>
        </div>
      </div>

      {/* Actions */}
      <div className="flex justify-end gap-2 pt-2 border-t border-dark-700">
        <Button variant="secondary" onClick={onCancel}>Cancel</Button>
        <Button variant="primary" onClick={onSave} isLoading={saving}>
          <Save className="w-4 h-4" />
          {profile.id ? 'Update' : 'Create'}
        </Button>
      </div>
    </div>
  )
}
