import { useState } from 'react'
import { Lock, ChevronDown, ChevronUp } from 'lucide-react'

export type AuthType = '' | 'none' | 'cookie' | 'bearer' | 'basic' | 'header' | 'login'

export interface AuthState {
  authType: AuthType
  /** Single-string value for cookie / bearer / header */
  authValue: string
  /** Separate fields for basic / login */
  username: string
  password: string
}

interface Props {
  value: AuthState
  onChange: (state: AuthState) => void
  disabled?: boolean
  /** Start expanded (default false) */
  defaultExpanded?: boolean
}

const AUTH_OPTIONS: { id: AuthType; label: string; description: string }[] = [
  { id: 'cookie', label: 'Cookie', description: 'Session cookie injected as HTTP header on all requests.' },
  { id: 'bearer', label: 'Bearer Token', description: 'JWT / API token sent as Authorization header on all requests.' },
  { id: 'basic', label: 'Basic Auth (HTTP)', description: 'Credentials sent as HTTP Basic Authorization header (not form login).' },
  { id: 'login', label: 'Form Login', description: 'Agent will find the login form and submit these credentials via the browser.' },
  { id: 'header', label: 'Custom Header', description: 'Custom header injected on all requests.' },
]

export default function AuthInputSection({ value, onChange, disabled, defaultExpanded = false }: Props) {
  const [expanded, setExpanded] = useState(defaultExpanded || (value.authType !== '' && value.authType !== 'none'))

  const update = (patch: Partial<AuthState>) => onChange({ ...value, ...patch })
  const activeType = value.authType === 'none' ? '' : value.authType
  const activeOption = AUTH_OPTIONS.find(o => o.id === activeType)

  return (
    <div className="space-y-3">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        disabled={disabled}
        className="flex items-center gap-2 text-sm text-dark-400 hover:text-white transition-colors disabled:opacity-50"
      >
        <Lock className="w-4 h-4" />
        <span>Authentication {activeType ? `(${activeOption?.label})` : '(Optional)'}</span>
        {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
      </button>

      {expanded && (
        <div className="space-y-3 pl-6">
          <select
            value={activeType}
            onChange={e => update({ authType: (e.target.value || 'none') as AuthType })}
            disabled={disabled}
            className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm focus:outline-none focus:border-purple-500 disabled:opacity-50"
          >
            <option value="">No Authentication</option>
            {AUTH_OPTIONS.map(o => (
              <option key={o.id} value={o.id}>{o.label}</option>
            ))}
          </select>

          {activeOption && (
            <p className="text-xs text-dark-500">{activeOption.description}</p>
          )}

          {(activeType === 'basic' || activeType === 'login') && (
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Username"
                value={value.username}
                onChange={e => update({ username: e.target.value })}
                disabled={disabled}
                className="flex-1 px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm placeholder-dark-500 focus:outline-none focus:border-purple-500 disabled:opacity-50"
              />
              <input
                type="password"
                placeholder="Password"
                value={value.password}
                onChange={e => update({ password: e.target.value })}
                disabled={disabled}
                className="flex-1 px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm placeholder-dark-500 focus:outline-none focus:border-purple-500 disabled:opacity-50"
              />
            </div>
          )}

          {activeType === 'cookie' && (
            <input
              type="text"
              placeholder="session=abc123; token=xyz789"
              value={value.authValue}
              onChange={e => update({ authValue: e.target.value })}
              disabled={disabled}
              className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm placeholder-dark-500 focus:outline-none focus:border-purple-500 disabled:opacity-50"
            />
          )}

          {activeType === 'bearer' && (
            <input
              type="text"
              placeholder="eyJhbGciOiJIUzI1NiIs..."
              value={value.authValue}
              onChange={e => update({ authValue: e.target.value })}
              disabled={disabled}
              className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm placeholder-dark-500 focus:outline-none focus:border-purple-500 disabled:opacity-50"
            />
          )}

          {activeType === 'header' && (
            <input
              type="text"
              placeholder="X-API-Key: your-api-key"
              value={value.authValue}
              onChange={e => update({ authValue: e.target.value })}
              disabled={disabled}
              className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm placeholder-dark-500 focus:outline-none focus:border-purple-500 disabled:opacity-50"
            />
          )}
        </div>
      )}
    </div>
  )
}
