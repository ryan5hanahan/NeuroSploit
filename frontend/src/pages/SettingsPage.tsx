import { useState, useEffect } from 'react'
import { Save, Shield, Trash2, RefreshCw, AlertTriangle, Brain, Router, Eye, Zap } from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import Input from '../components/common/Input'

interface Settings {
  llm_provider: string
  has_anthropic_key: boolean
  has_openai_key: boolean
  has_openrouter_key: boolean
  has_aws_bedrock_config: boolean
  max_concurrent_scans: number
  aggressive_mode: boolean
  default_scan_type: string
  recon_enabled_by_default: boolean
  enable_model_routing: boolean
  enable_knowledge_augmentation: boolean
  enable_browser_validation: boolean
  max_output_tokens: number | null
  aws_bedrock_region: string
  aws_bedrock_model: string
}

interface DbStats {
  scans: number
  vulnerabilities: number
  endpoints: number
  reports: number
}

interface LlmTestResult {
  id?: string
  created_at?: string
  success: boolean
  provider: string
  model: string
  response_time_ms: number
  response_preview: string
  error: string | null
}

interface LlmTestResponse {
  current: LlmTestResult
  previous: LlmTestResult | null
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [dbStats, setDbStats] = useState<DbStats | null>(null)
  const [apiKey, setApiKey] = useState('')
  const [openaiKey, setOpenaiKey] = useState('')
  const [openrouterKey, setOpenrouterKey] = useState('')
  const [awsAccessKeyId, setAwsAccessKeyId] = useState('')
  const [awsSecretAccessKey, setAwsSecretAccessKey] = useState('')
  const [awsSessionToken, setAwsSessionToken] = useState('')
  const [awsBedrockRegion, setAwsBedrockRegion] = useState('us-east-1')
  const [awsBedrockModel, setAwsBedrockModel] = useState('')
  const [llmProvider, setLlmProvider] = useState('claude')
  const [maxConcurrentScans, setMaxConcurrentScans] = useState('3')
  const [maxOutputTokens, setMaxOutputTokens] = useState('')
  const [aggressiveMode, setAggressiveMode] = useState(false)
  const [enableModelRouting, setEnableModelRouting] = useState(false)
  const [enableKnowledgeAugmentation, setEnableKnowledgeAugmentation] = useState(false)
  const [enableBrowserValidation, setEnableBrowserValidation] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [isClearing, setIsClearing] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [testResult, setTestResult] = useState<LlmTestResult | null>(null)
  const [previousResult, setPreviousResult] = useState<LlmTestResult | null>(null)
  const [showClearConfirm, setShowClearConfirm] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)

  useEffect(() => {
    fetchSettings()
    fetchDbStats()
  }, [])

  const fetchSettings = async () => {
    try {
      const response = await fetch('/api/v1/settings')
      if (response.ok) {
        const data = await response.json()
        setSettings(data)
        setLlmProvider(data.llm_provider)
        setMaxConcurrentScans(String(data.max_concurrent_scans))
        setAggressiveMode(data.aggressive_mode)
        setEnableModelRouting(data.enable_model_routing ?? false)
        setEnableKnowledgeAugmentation(data.enable_knowledge_augmentation ?? false)
        setEnableBrowserValidation(data.enable_browser_validation ?? false)
        setMaxOutputTokens(data.max_output_tokens ? String(data.max_output_tokens) : '')
        setAwsBedrockRegion(data.aws_bedrock_region || 'us-east-1')
        setAwsBedrockModel(data.aws_bedrock_model || '')
      }
    } catch (error) {
      console.error('Failed to fetch settings:', error)
    }
  }

  const fetchDbStats = async () => {
    try {
      const response = await fetch('/api/v1/settings/stats')
      if (response.ok) {
        const data = await response.json()
        setDbStats(data)
      }
    } catch (error) {
      console.error('Failed to fetch db stats:', error)
    }
  }

  const handleSave = async () => {
    setIsSaving(true)
    setMessage(null)

    try {
      const response = await fetch('/api/v1/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          llm_provider: llmProvider,
          anthropic_api_key: apiKey || undefined,
          openai_api_key: openaiKey || undefined,
          openrouter_api_key: openrouterKey || undefined,
          aws_access_key_id: awsAccessKeyId || undefined,
          aws_secret_access_key: awsSecretAccessKey || undefined,
          aws_session_token: awsSessionToken || undefined,
          aws_bedrock_region: llmProvider === 'bedrock' ? awsBedrockRegion : undefined,
          aws_bedrock_model: llmProvider === 'bedrock' ? awsBedrockModel : undefined,
          max_concurrent_scans: parseInt(maxConcurrentScans),
          aggressive_mode: aggressiveMode,
          enable_model_routing: enableModelRouting,
          enable_knowledge_augmentation: enableKnowledgeAugmentation,
          enable_browser_validation: enableBrowserValidation,
          max_output_tokens: maxOutputTokens ? parseInt(maxOutputTokens) : null
        })
      })

      if (response.ok) {
        const data = await response.json()
        setSettings(data)
        setApiKey('')
        setOpenaiKey('')
        setOpenrouterKey('')
        setAwsAccessKeyId('')
        setAwsSecretAccessKey('')
        setAwsSessionToken('')
        setMessage({ type: 'success', text: 'Settings saved successfully!' })
      } else {
        setMessage({ type: 'error', text: 'Failed to save settings' })
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to save settings' })
    } finally {
      setIsSaving(false)
    }
  }

  const handleClearDatabase = async () => {
    setIsClearing(true)
    setMessage(null)

    try {
      const response = await fetch('/api/v1/settings/clear-database', {
        method: 'POST'
      })

      if (response.ok) {
        setMessage({ type: 'success', text: 'Database cleared successfully!' })
        setShowClearConfirm(false)
        fetchDbStats()
      } else {
        const data = await response.json()
        setMessage({ type: 'error', text: data.detail || 'Failed to clear database' })
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to clear database' })
    } finally {
      setIsClearing(false)
    }
  }

  const handleTestConnection = async () => {
    setIsTesting(true)
    setTestResult(null)
    setPreviousResult(null)

    try {
      const response = await fetch('/api/v1/settings/test-llm', { method: 'POST' })
      const data: LlmTestResponse = await response.json()
      setTestResult(data.current)
      setPreviousResult(data.previous)
    } catch (error) {
      setTestResult({
        success: false,
        provider: llmProvider,
        model: '',
        response_time_ms: 0,
        response_preview: '',
        error: 'Failed to reach the backend. Is the server running?',
      })
      setPreviousResult(null)
    } finally {
      setIsTesting(false)
    }
  }

  const ToggleSwitch = ({ enabled, onToggle }: { enabled: boolean; onToggle: () => void }) => (
    <button
      onClick={onToggle}
      className={`w-12 h-6 rounded-full transition-colors ${enabled ? 'bg-primary-500' : 'bg-dark-700'}`}
    >
      <div className={`w-5 h-5 bg-white rounded-full shadow-md transform transition-transform ${enabled ? 'translate-x-6' : 'translate-x-0.5'}`} />
    </button>
  )

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fadeIn">
      {/* Status Message */}
      {message && (
        <div className={`p-4 rounded-lg ${message.type === 'success' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
          {message.text}
        </div>
      )}

      {/* LLM Configuration */}
      <Card title="LLM Configuration" subtitle="Configure AI model for vulnerability analysis">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-dark-200 mb-2">
              LLM Provider
            </label>
            <div className="flex gap-2 flex-wrap">
              {['claude', 'openai', 'openrouter', 'ollama', 'bedrock'].map((provider) => (
                <Button
                  key={provider}
                  variant={llmProvider === provider ? 'primary' : 'secondary'}
                  onClick={() => { setLlmProvider(provider); setTestResult(null); setPreviousResult(null) }}
                >
                  {provider === 'openrouter' ? 'OpenRouter' : provider === 'bedrock' ? 'AWS Bedrock' : provider.charAt(0).toUpperCase() + provider.slice(1)}
                </Button>
              ))}
            </div>
          </div>

          {llmProvider === 'claude' && (
            <Input
              label="Anthropic API Key"
              type="password"
              placeholder={settings?.has_anthropic_key ? '••••••••••••••••' : 'sk-ant-...'}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              helperText={settings?.has_anthropic_key ? 'API key is configured. Enter a new key to update.' : 'Required for Claude-powered analysis'}
            />
          )}

          {llmProvider === 'openai' && (
            <Input
              label="OpenAI API Key"
              type="password"
              placeholder={settings?.has_openai_key ? '••••••••••••••••' : 'sk-...'}
              value={openaiKey}
              onChange={(e) => setOpenaiKey(e.target.value)}
              helperText={settings?.has_openai_key ? 'API key is configured. Enter a new key to update.' : 'Required for OpenAI-powered analysis'}
            />
          )}

          {llmProvider === 'openrouter' && (
            <Input
              label="OpenRouter API Key"
              type="password"
              placeholder={settings?.has_openrouter_key ? '••••••••••••••••' : 'sk-or-...'}
              value={openrouterKey}
              onChange={(e) => setOpenrouterKey(e.target.value)}
              helperText={settings?.has_openrouter_key ? 'API key is configured. Enter a new key to update.' : 'Required for OpenRouter model access'}
            />
          )}

          {llmProvider === 'bedrock' && (
            <div className="space-y-4">
              <Input
                label="AWS Access Key ID"
                type="password"
                placeholder={settings?.has_aws_bedrock_config ? '••••••••••••••••' : 'AKIA...'}
                value={awsAccessKeyId}
                onChange={(e) => setAwsAccessKeyId(e.target.value)}
                helperText={settings?.has_aws_bedrock_config ? 'AWS credentials configured. Enter new values to update.' : 'Optional if using AWS profile, IAM role, or SSO'}
              />
              <Input
                label="AWS Secret Access Key"
                type="password"
                placeholder={settings?.has_aws_bedrock_config ? '••••••••••••••••' : 'Secret key...'}
                value={awsSecretAccessKey}
                onChange={(e) => setAwsSecretAccessKey(e.target.value)}
                helperText="Required if using access key authentication"
              />
              <Input
                label="AWS Session Token (Optional)"
                type="password"
                placeholder="Session token for temporary credentials..."
                value={awsSessionToken}
                onChange={(e) => setAwsSessionToken(e.target.value)}
                helperText="Only needed for temporary/assumed role credentials"
              />
              <Input
                label="AWS Region"
                placeholder="us-east-1"
                value={awsBedrockRegion}
                onChange={(e) => setAwsBedrockRegion(e.target.value)}
                helperText="AWS region where Bedrock is enabled (e.g., us-east-1, us-west-2)"
              />
              <Input
                label="Bedrock Model ID"
                placeholder="us.anthropic.claude-sonnet-4-20250514-v1:0"
                value={awsBedrockModel}
                onChange={(e) => setAwsBedrockModel(e.target.value)}
                helperText="Model ID for Bedrock Converse API (e.g., us.anthropic.claude-sonnet-4-20250514-v1:0)"
              />
            </div>
          )}

          {/* Test Connection */}
          <div className="pt-2">
            <Button
              variant="secondary"
              onClick={handleTestConnection}
              isLoading={isTesting}
              className="w-full"
            >
              <Zap className="w-4 h-4 mr-2" />
              {isTesting ? 'Testing Connection...' : 'Test Connection'}
            </Button>
          </div>

          {testResult && (
            <div className={`rounded-lg text-sm ${
              testResult.success
                ? 'bg-green-500/15 border border-green-500/30'
                : 'bg-red-500/15 border border-red-500/30'
            }`}>
              <div className="p-4">
                {testResult.success ? (
                  <div className="space-y-1">
                    <p className="font-medium text-green-400">Connection successful</p>
                    <p className="text-dark-300">
                      <span className="text-dark-400">Provider:</span> {testResult.provider}
                      {' / '}
                      <span className="text-dark-400">Model:</span> {testResult.model}
                    </p>
                    <p className="text-dark-300">
                      <span className="text-dark-400">Response time:</span> {testResult.response_time_ms}ms
                    </p>
                    {testResult.response_preview && (
                      <p className="text-dark-400 mt-1 break-words">
                        <span className="text-dark-500">Response:</span> {testResult.response_preview.slice(0, 200)}
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="space-y-1">
                    <p className="font-medium text-red-400">Connection failed</p>
                    <p className="text-dark-300 break-words">{testResult.error}</p>
                  </div>
                )}
              </div>

              {previousResult && (
                <div className="border-t border-white/10 px-4 py-3 space-y-1">
                  <p className="text-dark-400 text-xs font-medium">
                    Previous test{previousResult.created_at && (
                      <span> ({new Date(previousResult.created_at).toLocaleString()})</span>
                    )}
                  </p>
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
                    <span className="text-dark-300">
                      {previousResult.provider}/{previousResult.model || '—'}
                    </span>
                    {/* Status delta */}
                    {testResult.success !== previousResult.success && (
                      testResult.success
                        ? <span className="text-green-400">(recovered)</span>
                        : <span className="text-red-400">(regressed)</span>
                    )}
                    {/* Response time delta */}
                    {previousResult.response_time_ms > 0 && testResult.response_time_ms > 0 && (() => {
                      const delta = testResult.response_time_ms - previousResult.response_time_ms
                      if (delta === 0) return <span className="text-dark-400">(same)</span>
                      return delta > 0
                        ? <span className="text-yellow-400">(+{delta}ms slower)</span>
                        : <span className="text-green-400">({delta}ms faster)</span>
                    })()}
                    {previousResult.success
                      ? <span className="text-dark-500">{previousResult.response_time_ms}ms</span>
                      : <span className="text-dark-500 truncate max-w-xs">{previousResult.error}</span>
                    }
                  </div>
                </div>
              )}
            </div>
          )}

          <Input
            label="Max Output Tokens"
            type="number"
            min="1024"
            max="64000"
            placeholder="Default (profile-based)"
            value={maxOutputTokens}
            onChange={(e) => setMaxOutputTokens(e.target.value)}
            helperText="Override max output tokens (up to 64000 for Claude). Leave empty for profile defaults."
          />
        </div>
      </Card>

      {/* Advanced Features */}
      <Card title="Advanced Features" subtitle="Optional AI enhancement modules">
        <div className="space-y-3">
          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div className="flex items-center gap-3">
              <Router className="w-5 h-5 text-blue-400" />
              <div>
                <p className="font-medium text-white">Model Routing</p>
                <p className="text-sm text-dark-400">
                  Route tasks to specialized LLM profiles by type (reasoning, analysis, generation)
                </p>
              </div>
            </div>
            <ToggleSwitch enabled={enableModelRouting} onToggle={() => setEnableModelRouting(!enableModelRouting)} />
          </div>

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div className="flex items-center gap-3">
              <Brain className="w-5 h-5 text-purple-400" />
              <div>
                <p className="font-medium text-white">Knowledge Augmentation</p>
                <p className="text-sm text-dark-400">
                  Enrich AI context with bug bounty pattern datasets (19 vuln types)
                </p>
              </div>
            </div>
            <ToggleSwitch enabled={enableKnowledgeAugmentation} onToggle={() => setEnableKnowledgeAugmentation(!enableKnowledgeAugmentation)} />
          </div>

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div className="flex items-center gap-3">
              <Eye className="w-5 h-5 text-green-400" />
              <div>
                <p className="font-medium text-white">Browser Validation</p>
                <p className="text-sm text-dark-400">
                  Playwright-based browser validation with screenshot capture
                </p>
              </div>
            </div>
            <ToggleSwitch enabled={enableBrowserValidation} onToggle={() => setEnableBrowserValidation(!enableBrowserValidation)} />
          </div>
        </div>
      </Card>

      {/* Scan Settings */}
      <Card title="Scan Settings" subtitle="Configure default scan behavior">
        <div className="space-y-4">
          <Input
            label="Max Concurrent Scans"
            type="number"
            min="1"
            max="10"
            value={maxConcurrentScans}
            onChange={(e) => setMaxConcurrentScans(e.target.value)}
            helperText="Maximum number of scans that can run simultaneously"
          />

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div>
              <p className="font-medium text-white">Enable Aggressive Mode</p>
              <p className="text-sm text-dark-400">
                Use more payloads and bypass techniques (may be slower)
              </p>
            </div>
            <ToggleSwitch enabled={aggressiveMode} onToggle={() => setAggressiveMode(!aggressiveMode)} />
          </div>
        </div>
      </Card>

      {/* Database Management */}
      <Card title="Database Management" subtitle="Manage stored data">
        <div className="space-y-4">
          {/* Stats */}
          {dbStats && (
            <div className="grid grid-cols-4 gap-4 p-4 bg-dark-900/50 rounded-lg">
              <div className="text-center">
                <p className="text-2xl font-bold text-white">{dbStats.scans}</p>
                <p className="text-xs text-dark-400">Scans</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-white">{dbStats.vulnerabilities}</p>
                <p className="text-xs text-dark-400">Vulnerabilities</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-white">{dbStats.endpoints}</p>
                <p className="text-xs text-dark-400">Endpoints</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-white">{dbStats.reports}</p>
                <p className="text-xs text-dark-400">Reports</p>
              </div>
            </div>
          )}

          {/* Clear Database */}
          {!showClearConfirm ? (
            <div className="flex items-center justify-between p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
              <div>
                <p className="font-medium text-white">Clear All Data</p>
                <p className="text-sm text-dark-400">
                  Remove all scans, vulnerabilities, and reports
                </p>
              </div>
              <Button variant="danger" onClick={() => setShowClearConfirm(true)}>
                <Trash2 className="w-4 h-4 mr-2" />
                Clear Database
              </Button>
            </div>
          ) : (
            <div className="p-4 bg-red-500/20 border border-red-500/50 rounded-lg space-y-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="font-medium text-red-400">Are you sure?</p>
                  <p className="text-sm text-dark-300 mt-1">
                    This will permanently delete all scans, vulnerabilities, endpoints, and reports.
                    This action cannot be undone.
                  </p>
                </div>
              </div>
              <div className="flex gap-3 justify-end">
                <Button variant="secondary" onClick={() => setShowClearConfirm(false)}>
                  Cancel
                </Button>
                <Button variant="danger" onClick={handleClearDatabase} isLoading={isClearing}>
                  <Trash2 className="w-4 h-4 mr-2" />
                  Yes, Clear Everything
                </Button>
              </div>
            </div>
          )}

          {/* Refresh Stats */}
          <Button variant="secondary" onClick={fetchDbStats} className="w-full">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh Statistics
          </Button>
        </div>
      </Card>

      {/* About */}
      <Card title="About NeuroSploit">
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-primary-500" />
            <div>
              <p className="font-bold text-white text-lg">NeuroSploit v3.0</p>
              <p className="text-sm text-dark-400">AI-Powered Penetration Testing Platform</p>
            </div>
          </div>
          <div className="text-sm text-dark-400 space-y-1">
            <p>Dynamic vulnerability testing driven by AI prompts</p>
            <p>50+ vulnerability types across 10 categories</p>
            <p>Multi-provider LLM support (Claude, GPT, OpenRouter, Ollama, AWS Bedrock)</p>
            <p>Task-type model routing and knowledge augmentation</p>
            <p>Playwright browser validation with screenshot capture</p>
            <p>OHVR-structured PoC reporting</p>
            <p>Scheduled recurring scans with cron/interval triggers</p>
          </div>
        </div>
      </Card>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button onClick={handleSave} isLoading={isSaving} size="lg">
          <Save className="w-5 h-5 mr-2" />
          Save Settings
        </Button>
      </div>
    </div>
  )
}
