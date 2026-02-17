import React from 'react'
import { Shield, Plus, Trash2, ChevronDown, ChevronUp } from 'lucide-react'

export interface CredentialSetEntry {
  label: string
  auth_type: string
  cookie?: string
  bearer_token?: string
  header_name?: string
  header_value?: string
  username?: string
  password?: string
  role: string
}

interface Props {
  credentialSets: CredentialSetEntry[]
  onChange: (sets: CredentialSetEntry[]) => void
}

const AUTH_TYPES = [
  { value: 'bearer', label: 'Bearer Token' },
  { value: 'cookie', label: 'Cookie' },
  { value: 'basic', label: 'Basic Auth' },
  { value: 'header', label: 'Custom Header' },
  { value: 'login', label: 'Login (user/pass)' },
]

const ROLES = ['user', 'admin', 'moderator', 'guest']

const emptySet = (): CredentialSetEntry => ({
  label: '',
  auth_type: 'bearer',
  role: 'user',
})

export default function CredentialSetsPanel({ credentialSets, onChange }: Props) {
  const [expanded, setExpanded] = React.useState(credentialSets.length > 0)

  const addSet = () => {
    onChange([...credentialSets, emptySet()])
    setExpanded(true)
  }

  const removeSet = (index: number) => {
    onChange(credentialSets.filter((_, i) => i !== index))
  }

  const updateSet = (index: number, patch: Partial<CredentialSetEntry>) => {
    const updated = credentialSets.map((s, i) => (i === index ? { ...s, ...patch } : s))
    onChange(updated)
  }

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 bg-gray-800/50 hover:bg-gray-800 transition-colors text-left"
      >
        <Shield size={18} className="text-purple-400" />
        <span className="text-sm font-medium text-gray-200 flex-1">
          Multi-Credential Differential Testing
          {credentialSets.length > 0 && (
            <span className="ml-2 text-xs text-purple-400">
              ({credentialSets.length} set{credentialSets.length !== 1 ? 's' : ''})
            </span>
          )}
        </span>
        {expanded ? <ChevronUp size={16} className="text-gray-400" /> : <ChevronDown size={16} className="text-gray-400" />}
      </button>

      {expanded && (
        <div className="p-4 space-y-3 bg-gray-900/30">
          <p className="text-xs text-gray-500">
            Add 2+ credential sets to enable differential access control testing (BOLA/BFLA/IDOR detection).
          </p>

          {credentialSets.map((cs, idx) => (
            <div key={idx} className="border border-gray-700 rounded-lg p-3 space-y-2 bg-gray-800/30">
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  placeholder="Label (e.g. admin, user_alice)"
                  value={cs.label}
                  onChange={e => updateSet(idx, { label: e.target.value })}
                  className="flex-1 px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-sm text-gray-200 focus:border-purple-500 focus:outline-none"
                />
                <select
                  value={cs.role}
                  onChange={e => updateSet(idx, { role: e.target.value })}
                  className="px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-sm text-gray-200 focus:border-purple-500 focus:outline-none"
                >
                  {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
                <select
                  value={cs.auth_type}
                  onChange={e => updateSet(idx, { auth_type: e.target.value })}
                  className="px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-sm text-gray-200 focus:border-purple-500 focus:outline-none"
                >
                  {AUTH_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
                <button
                  type="button"
                  onClick={() => removeSet(idx)}
                  className="p-1.5 text-red-400 hover:text-red-300 hover:bg-red-900/30 rounded transition-colors"
                >
                  <Trash2 size={14} />
                </button>
              </div>

              {/* Conditional credential inputs */}
              {cs.auth_type === 'bearer' && (
                <input
                  type="text"
                  placeholder="Bearer / JWT token"
                  value={cs.bearer_token || ''}
                  onChange={e => updateSet(idx, { bearer_token: e.target.value })}
                  className="w-full px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-sm text-gray-200 font-mono focus:border-purple-500 focus:outline-none"
                />
              )}
              {cs.auth_type === 'cookie' && (
                <input
                  type="text"
                  placeholder="Cookie string (e.g. session=abc123)"
                  value={cs.cookie || ''}
                  onChange={e => updateSet(idx, { cookie: e.target.value })}
                  className="w-full px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-sm text-gray-200 font-mono focus:border-purple-500 focus:outline-none"
                />
              )}
              {cs.auth_type === 'header' && (
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Header name"
                    value={cs.header_name || ''}
                    onChange={e => updateSet(idx, { header_name: e.target.value })}
                    className="flex-1 px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-sm text-gray-200 focus:border-purple-500 focus:outline-none"
                  />
                  <input
                    type="text"
                    placeholder="Header value"
                    value={cs.header_value || ''}
                    onChange={e => updateSet(idx, { header_value: e.target.value })}
                    className="flex-1 px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-sm text-gray-200 font-mono focus:border-purple-500 focus:outline-none"
                  />
                </div>
              )}
              {(cs.auth_type === 'basic' || cs.auth_type === 'login') && (
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Username"
                    value={cs.username || ''}
                    onChange={e => updateSet(idx, { username: e.target.value })}
                    className="flex-1 px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-sm text-gray-200 focus:border-purple-500 focus:outline-none"
                  />
                  <input
                    type="password"
                    placeholder="Password"
                    value={cs.password || ''}
                    onChange={e => updateSet(idx, { password: e.target.value })}
                    className="flex-1 px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-sm text-gray-200 focus:border-purple-500 focus:outline-none"
                  />
                </div>
              )}
            </div>
          ))}

          <button
            type="button"
            onClick={addSet}
            className="flex items-center gap-2 px-3 py-2 text-sm text-purple-400 hover:text-purple-300 hover:bg-purple-900/20 border border-dashed border-gray-600 rounded-lg transition-colors w-full justify-center"
          >
            <Plus size={14} />
            Add Credential Set
          </button>
        </div>
      )}
    </div>
  )
}
