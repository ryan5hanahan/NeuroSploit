import { useState, useEffect } from 'react'
import { Save, Shield, Trash2, RefreshCw, AlertTriangle, Brain, Router, Eye, Zap, Lightbulb, Database, Activity, Bug, DollarSign, ShieldCheck } from 'lucide-react'
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
  enable_extended_thinking: boolean
  enable_tracing: boolean
  enable_persistent_memory: boolean
  enable_bugbounty_integration: boolean
  has_shodan_key: boolean
  has_censys_key: boolean
  has_virustotal_key: boolean
  has_builtwith_key: boolean
  has_hackerone_config: boolean
  max_output_tokens: number | null
  aws_bedrock_region: string
  aws_bedrock_model: string
  llm_model: string
  model_fast: string
  model_balanced: string
  model_deep: string
  provider_fast: string
  provider_balanced: string
  provider_deep: string
  // Cost tracking
  cost_budget_per_scan: number
  cost_warn_at_pct: number
  enable_cost_tracking: boolean
  // Security testing
  enable_waf_evasion: boolean
  waf_confidence_threshold: number
  confidence_pivot_threshold: number
  confidence_reject_threshold: number
  // Scan tuning
  default_timeout: number
  max_requests_per_second: number
  // Vulnerability enrichment
  has_nvd_key: boolean
  enable_vuln_enrichment: boolean
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

const MODEL_PRESETS: Record<string, { label: string; value: string }[]> = {
  claude: [
    { label: 'Claude Sonnet 4.6 (Default)', value: 'claude-sonnet-4-6' },
    { label: 'Claude Opus 4.6', value: 'claude-opus-4-6' },
    { label: 'Claude Haiku 4.5', value: 'claude-haiku-4-5-20251001' },
    { label: 'Custom', value: '__custom__' },
  ],
  openai: [
    { label: 'GPT-4o (Default)', value: 'gpt-4o' },
    { label: 'GPT-4o Mini', value: 'gpt-4o-mini' },
    { label: 'GPT-4 Turbo', value: 'gpt-4-turbo' },
    { label: 'Custom', value: '__custom__' },
  ],
  openrouter: [
    { label: 'Claude Sonnet 4.6 (Default)', value: 'anthropic/claude-sonnet-4-6' },
    { label: 'Claude Opus 4.6', value: 'anthropic/claude-opus-4-6' },
    { label: 'GPT-4o', value: 'openai/gpt-4o' },
    { label: 'Custom', value: '__custom__' },
  ],
  ollama: [
    { label: 'Llama 3.2 (Default)', value: 'llama3.2' },
    { label: 'Llama 3.1', value: 'llama3.1' },
    { label: 'Mistral', value: 'mistral' },
    { label: 'Custom', value: '__custom__' },
  ],
  bedrock: [
    { label: 'Claude Sonnet 4.6 (Default)', value: 'us.anthropic.claude-sonnet-4-6-v1:0' },
    { label: 'Claude Opus 4.6', value: 'us.anthropic.claude-opus-4-6-v1:0' },
    { label: 'Claude Haiku 4.5', value: 'us.anthropic.claude-haiku-4-5-20251001-v1:0' },
    { label: 'Custom', value: '__custom__' },
  ],
}

// Default model per tier per provider (matches router.py DEFAULT_TIER_CONFIG)
const TIER_DEFAULTS: Record<string, Record<string, string>> = {
  claude: { fast: 'claude-haiku-4-5-20251001', balanced: 'claude-sonnet-4-6', deep: 'claude-opus-4-6' },
  anthropic: { fast: 'claude-haiku-4-5-20251001', balanced: 'claude-sonnet-4-6', deep: 'claude-opus-4-6' },
  openai: { fast: 'gpt-4o-mini', balanced: 'gpt-4o', deep: 'gpt-4o' },
  openrouter: { fast: 'anthropic/claude-haiku-4-5-20251001', balanced: 'anthropic/claude-sonnet-4-6', deep: 'anthropic/claude-opus-4-6' },
  ollama: { fast: 'llama3.2:3b', balanced: 'llama3.2', deep: 'llama3.2' },
  bedrock: { fast: 'us.anthropic.claude-haiku-4-5-20251001-v1:0', balanced: 'us.anthropic.claude-sonnet-4-6-v1:0', deep: 'us.anthropic.claude-opus-4-6-v1:0' },
  gemini: { fast: 'gemini-2.0-flash', balanced: 'gemini-2.0-pro', deep: 'gemini-2.0-pro' },
  lmstudio: { fast: 'default', balanced: 'default', deep: 'default' },
}

const TIER_PRESETS: Record<string, { label: string; value: string }[]> = {
  anthropic: [
    { label: 'Claude Haiku 4.5', value: 'claude-haiku-4-5-20251001' },
    { label: 'Claude Sonnet 4.6', value: 'claude-sonnet-4-6' },
    { label: 'Claude Opus 4.6', value: 'claude-opus-4-6' },
    { label: 'Custom', value: '__custom__' },
  ],
  claude: [
    { label: 'Claude Haiku 4.5', value: 'claude-haiku-4-5-20251001' },
    { label: 'Claude Sonnet 4.6', value: 'claude-sonnet-4-6' },
    { label: 'Claude Opus 4.6', value: 'claude-opus-4-6' },
    { label: 'Custom', value: '__custom__' },
  ],
  openai: [
    { label: 'GPT-4o Mini', value: 'gpt-4o-mini' },
    { label: 'GPT-4o', value: 'gpt-4o' },
    { label: 'GPT-4 Turbo', value: 'gpt-4-turbo' },
    { label: 'Custom', value: '__custom__' },
  ],
  openrouter: [
    { label: 'Claude Haiku 4.5', value: 'anthropic/claude-haiku-4-5-20251001' },
    { label: 'Claude Sonnet 4.6', value: 'anthropic/claude-sonnet-4-6' },
    { label: 'Claude Opus 4.6', value: 'anthropic/claude-opus-4-6' },
    { label: 'GPT-4o', value: 'openai/gpt-4o' },
    { label: 'Custom', value: '__custom__' },
  ],
  ollama: [
    { label: 'Llama 3.2 3B', value: 'llama3.2:3b' },
    { label: 'Llama 3.2', value: 'llama3.2' },
    { label: 'Llama 3.1', value: 'llama3.1' },
    { label: 'Mistral', value: 'mistral' },
    { label: 'Custom', value: '__custom__' },
  ],
  bedrock: [
    { label: 'Claude Haiku 4.5', value: 'us.anthropic.claude-haiku-4-5-20251001-v1:0' },
    { label: 'Claude Sonnet 4.6', value: 'us.anthropic.claude-sonnet-4-6-v1:0' },
    { label: 'Claude Opus 4.6', value: 'us.anthropic.claude-opus-4-6-v1:0' },
    { label: 'Custom', value: '__custom__' },
  ],
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
  const [llmModel, setLlmModel] = useState('')
  const [isCustomModel, setIsCustomModel] = useState(false)
  const [maxConcurrentScans, setMaxConcurrentScans] = useState('3')
  const [maxOutputTokens, setMaxOutputTokens] = useState('')
  const [aggressiveMode, setAggressiveMode] = useState(false)
  const [defaultScanType, setDefaultScanType] = useState('full')
  const [reconEnabledByDefault, setReconEnabledByDefault] = useState(true)
  const [enableModelRouting, setEnableModelRouting] = useState(false)
  const [modelFast, setModelFast] = useState('')
  const [modelBalanced, setModelBalanced] = useState('')
  const [modelDeep, setModelDeep] = useState('')
  const [isCustomFast, setIsCustomFast] = useState(false)
  const [isCustomBalanced, setIsCustomBalanced] = useState(false)
  const [isCustomDeep, setIsCustomDeep] = useState(false)
  // Per-tier provider overrides
  const [providerFast, setProviderFast] = useState('')
  const [providerBalanced, setProviderBalanced] = useState('')
  const [providerDeep, setProviderDeep] = useState('')
  // Dynamic model lists from API
  const [dynamicModels, setDynamicModels] = useState<Record<string, { id: string; name: string }[]>>({})
  const [enableKnowledgeAugmentation, setEnableKnowledgeAugmentation] = useState(false)
  const [enableBrowserValidation, setEnableBrowserValidation] = useState(false)
  const [enableExtendedThinking, setEnableExtendedThinking] = useState(false)
  const [enableTracing, setEnableTracing] = useState(false)
  const [enablePersistentMemory, setEnablePersistentMemory] = useState(true)
  const [enableBugbountyIntegration, setEnableBugbountyIntegration] = useState(false)
  // Cost tracking
  const [costBudgetPerScan, setCostBudgetPerScan] = useState('5.00')
  const [costWarnAtPct, setCostWarnAtPct] = useState('80')
  const [enableCostTracking, setEnableCostTracking] = useState(true)
  // Security testing
  const [enableWafEvasion, setEnableWafEvasion] = useState(true)
  const [wafConfidenceThreshold, setWafConfidenceThreshold] = useState('0.7')
  const [confidencePivotThreshold, setConfidencePivotThreshold] = useState('30')
  const [confidenceRejectThreshold, setConfidenceRejectThreshold] = useState('40')
  // Scan tuning
  const [defaultTimeout, setDefaultTimeout] = useState('30')
  const [maxRequestsPerSecond, setMaxRequestsPerSecond] = useState('10')
  // Vulnerability enrichment
  const [nvdApiKey, setNvdApiKey] = useState('')
  const [enableVulnEnrichment, setEnableVulnEnrichment] = useState(true)
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
        setDefaultScanType(data.default_scan_type || 'full')
        setReconEnabledByDefault(data.recon_enabled_by_default ?? true)
        setEnableModelRouting(data.enable_model_routing ?? false)
        // Load per-tier models
        const savedFast = data.model_fast || ''
        const savedBalanced = data.model_balanced || ''
        const savedDeep = data.model_deep || ''
        setModelFast(savedFast)
        setModelBalanced(savedBalanced)
        setModelDeep(savedDeep)
        const tierPresets = TIER_PRESETS[data.llm_provider] || []
        setIsCustomFast(savedFast !== '' && !tierPresets.some((p: { value: string }) => p.value === savedFast))
        setIsCustomBalanced(savedBalanced !== '' && !tierPresets.some((p: { value: string }) => p.value === savedBalanced))
        setIsCustomDeep(savedDeep !== '' && !tierPresets.some((p: { value: string }) => p.value === savedDeep))
        // Load per-tier provider overrides
        setProviderFast(data.provider_fast || '')
        setProviderBalanced(data.provider_balanced || '')
        setProviderDeep(data.provider_deep || '')
        setEnableKnowledgeAugmentation(data.enable_knowledge_augmentation ?? false)
        setEnableBrowserValidation(data.enable_browser_validation ?? false)
        setEnableExtendedThinking(data.enable_extended_thinking ?? false)
        setEnableTracing(data.enable_tracing ?? false)
        setEnablePersistentMemory(data.enable_persistent_memory ?? true)
        setEnableBugbountyIntegration(data.enable_bugbounty_integration ?? false)
        setMaxOutputTokens(data.max_output_tokens ? String(data.max_output_tokens) : '')
        // Cost tracking
        setCostBudgetPerScan(String(data.cost_budget_per_scan ?? 5.00))
        setCostWarnAtPct(String(data.cost_warn_at_pct ?? 80))
        setEnableCostTracking(data.enable_cost_tracking ?? true)
        // Security testing
        setEnableWafEvasion(data.enable_waf_evasion ?? true)
        setWafConfidenceThreshold(String(data.waf_confidence_threshold ?? 0.7))
        setConfidencePivotThreshold(String(data.confidence_pivot_threshold ?? 30))
        setConfidenceRejectThreshold(String(data.confidence_reject_threshold ?? 40))
        // Scan tuning
        setDefaultTimeout(String(data.default_timeout ?? 30))
        setMaxRequestsPerSecond(String(data.max_requests_per_second ?? 10))
        // Vulnerability enrichment
        setEnableVulnEnrichment(data.enable_vuln_enrichment ?? true)
        setAwsBedrockRegion(data.aws_bedrock_region || 'us-east-1')
        setAwsBedrockModel(data.aws_bedrock_model || '')
        const savedModel = data.llm_model || ''
        setLlmModel(savedModel)
        const presets = MODEL_PRESETS[data.llm_provider] || []
        const isPreset = presets.some((p: { value: string }) => p.value === savedModel)
        setIsCustomModel(savedModel !== '' && !isPreset)
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

  const fetchModelsForProvider = async (providerName: string) => {
    if (!providerName || dynamicModels[providerName]) return
    try {
      const response = await fetch(`/api/v1/settings/available-models?provider=${providerName}`)
      if (response.ok) {
        const data = await response.json()
        if (data.models && data.models.length > 0) {
          setDynamicModels(prev => ({ ...prev, [providerName]: data.models }))
        }
      }
    } catch {
      // Fallback to TIER_PRESETS
    }
  }

  // Helper to get effective provider for a tier
  const getTierProvider = (tier: 'fast' | 'balanced' | 'deep') => {
    const overrides = { fast: providerFast, balanced: providerBalanced, deep: providerDeep }
    return overrides[tier] || llmProvider
  }

  // Get model options for a tier (dynamic API models or fallback to presets)
  const getTierModelOptions = (tier: 'fast' | 'balanced' | 'deep') => {
    const effectiveProvider = getTierProvider(tier)
    const dynamic = dynamicModels[effectiveProvider]
    if (dynamic && dynamic.length > 0) {
      return [
        ...dynamic.map(m => ({ label: m.name, value: m.id })),
        { label: 'Custom', value: '__custom__' },
      ]
    }
    return TIER_PRESETS[effectiveProvider] || TIER_PRESETS[llmProvider] || []
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
          llm_model: llmModel,
          max_concurrent_scans: parseInt(maxConcurrentScans),
          aggressive_mode: aggressiveMode,
          default_scan_type: defaultScanType,
          recon_enabled_by_default: reconEnabledByDefault,
          enable_model_routing: enableModelRouting,
          model_fast: enableModelRouting ? modelFast : undefined,
          model_balanced: enableModelRouting ? modelBalanced : undefined,
          model_deep: enableModelRouting ? modelDeep : undefined,
          provider_fast: enableModelRouting ? providerFast : undefined,
          provider_balanced: enableModelRouting ? providerBalanced : undefined,
          provider_deep: enableModelRouting ? providerDeep : undefined,
          enable_knowledge_augmentation: enableKnowledgeAugmentation,
          enable_browser_validation: enableBrowserValidation,
          enable_extended_thinking: enableExtendedThinking,
          enable_tracing: enableTracing,
          enable_persistent_memory: enablePersistentMemory,
          enable_bugbounty_integration: enableBugbountyIntegration,
          max_output_tokens: maxOutputTokens ? parseInt(maxOutputTokens) : null,
          // Cost tracking
          cost_budget_per_scan: parseFloat(costBudgetPerScan),
          cost_warn_at_pct: parseFloat(costWarnAtPct),
          enable_cost_tracking: enableCostTracking,
          // Security testing
          enable_waf_evasion: enableWafEvasion,
          waf_confidence_threshold: parseFloat(wafConfidenceThreshold),
          confidence_pivot_threshold: parseInt(confidencePivotThreshold),
          confidence_reject_threshold: parseInt(confidenceRejectThreshold),
          // Scan tuning
          default_timeout: parseInt(defaultTimeout),
          max_requests_per_second: parseInt(maxRequestsPerSecond),
          // Vulnerability enrichment
          nvd_api_key: nvdApiKey || undefined,
          enable_vuln_enrichment: enableVulnEnrichment,
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
        setNvdApiKey('')
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
                  onClick={() => { setLlmProvider(provider); setLlmModel(''); setIsCustomModel(false); setModelFast(''); setModelBalanced(''); setModelDeep(''); setIsCustomFast(false); setIsCustomBalanced(false); setIsCustomDeep(false); setProviderFast(''); setProviderBalanced(''); setProviderDeep(''); setTestResult(null); setPreviousResult(null) }}
                >
                  {provider === 'openrouter' ? 'OpenRouter' : provider === 'bedrock' ? 'AWS Bedrock' : provider.charAt(0).toUpperCase() + provider.slice(1)}
                </Button>
              ))}
            </div>
          </div>

          {/* Model Selection */}
          {MODEL_PRESETS[llmProvider] && (
            <div>
              <label className="block text-sm font-medium text-dark-200 mb-2">
                Model
              </label>
              <select
                value={isCustomModel ? '__custom__' : llmModel}
                onChange={(e) => {
                  if (e.target.value === '__custom__') {
                    setIsCustomModel(true)
                    setLlmModel('')
                  } else {
                    setIsCustomModel(false)
                    setLlmModel(e.target.value)
                  }
                }}
                className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white focus:outline-none focus:border-primary-500 transition-colors"
              >
                <option value="">Default</option>
                {MODEL_PRESETS[llmProvider].map((preset) => (
                  <option key={preset.value} value={preset.value}>
                    {preset.label}
                  </option>
                ))}
              </select>
              {isCustomModel && (
                <Input
                  label=""
                  placeholder="Enter custom model ID..."
                  value={llmModel}
                  onChange={(e) => setLlmModel(e.target.value)}
                  helperText="Enter the full model identifier"
                />
              )}
            </div>
          )}

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

      {/* Cost & Budget */}
      <Card title="Cost & Budget" subtitle="LLM cost tracking and budget limits">
        <div className="space-y-4">
          <div className="flex items-center gap-3 mb-2">
            <DollarSign className="w-5 h-5 text-green-400" />
            <p className="text-sm text-dark-400">
              Track per-scan LLM costs and enforce budget limits to prevent runaway spending.
            </p>
          </div>

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div>
              <p className="font-medium text-white">Enable Cost Tracking</p>
              <p className="text-sm text-dark-400">
                Track token usage and estimated cost per scan
              </p>
            </div>
            <ToggleSwitch enabled={enableCostTracking} onToggle={() => setEnableCostTracking(!enableCostTracking)} />
          </div>

          {enableCostTracking && (
            <>
              <Input
                label="Budget per Scan ($)"
                type="number"
                min="0.50"
                max="100"
                step="0.50"
                placeholder="5.00"
                value={costBudgetPerScan}
                onChange={(e) => setCostBudgetPerScan(e.target.value)}
                helperText="Maximum USD spend per scan. Scan pauses if exceeded."
              />
              <Input
                label="Warning Threshold (%)"
                type="number"
                min="10"
                max="100"
                placeholder="80"
                value={costWarnAtPct}
                onChange={(e) => setCostWarnAtPct(e.target.value)}
                helperText="Emit a warning when this percentage of the budget is consumed."
              />
            </>
          )}
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

          {/* Per-tier model & provider selection (shown when routing is enabled) */}
          {enableModelRouting && (
            <div className="ml-8 p-4 bg-dark-800/50 border border-dark-700 rounded-lg space-y-4">
              <p className="text-xs text-dark-400 mb-2">
                Configure provider and model for each tier. Leave provider empty to use the global default.
              </p>
              {[
                { tier: 'fast' as const, label: 'Fast', desc: 'Recon parsing, tool selection, classification', model: modelFast, setModel: setModelFast, isCustom: isCustomFast, setIsCustom: setIsCustomFast, provider: providerFast, setProvider: setProviderFast },
                { tier: 'balanced' as const, label: 'Balanced', desc: 'Vuln testing, payload generation, analysis', model: modelBalanced, setModel: setModelBalanced, isCustom: isCustomBalanced, setIsCustom: setIsCustomBalanced, provider: providerBalanced, setProvider: setProviderBalanced },
                { tier: 'deep' as const, label: 'Deep', desc: 'Strategy planning, confirmation, reporting', model: modelDeep, setModel: setModelDeep, isCustom: isCustomDeep, setIsCustom: setIsCustomDeep, provider: providerDeep, setProvider: setProviderDeep },
              ].map(({ tier, label, desc, model, setModel, isCustom, setIsCustom, provider, setProvider }) => {
                const effectiveProvider = provider || llmProvider
                const modelOptions = getTierModelOptions(tier)
                return (
                  <div key={tier} className="space-y-2">
                    <label className="block text-sm font-medium text-dark-200">
                      {label} Tier
                      <span className="text-xs text-dark-500 ml-2">{desc}</span>
                    </label>
                    <div className="flex gap-2">
                      <select
                        value={provider}
                        onChange={(e) => {
                          setProvider(e.target.value)
                          setModel('')
                          setIsCustom(false)
                          if (e.target.value) fetchModelsForProvider(e.target.value)
                        }}
                        className="w-40 px-3 py-2 bg-dark-900 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500 transition-colors"
                      >
                        <option value="">Same as default</option>
                        {['claude', 'openai', 'ollama', 'bedrock', 'gemini', 'lmstudio'].map(p => (
                          <option key={p} value={p === 'claude' ? 'anthropic' : p}>
                            {p === 'claude' ? 'Claude' : p === 'bedrock' ? 'AWS Bedrock' : p === 'lmstudio' ? 'LM Studio' : p.charAt(0).toUpperCase() + p.slice(1)}
                          </option>
                        ))}
                      </select>
                      <select
                        value={isCustom ? '__custom__' : model}
                        onChange={(e) => {
                          if (e.target.value === '__custom__') {
                            setIsCustom(true)
                            setModel('')
                          } else {
                            setIsCustom(false)
                            setModel(e.target.value)
                          }
                        }}
                        className="flex-1 px-3 py-2 bg-dark-900 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500 transition-colors"
                      >
                        <option value="">Default ({TIER_DEFAULTS[effectiveProvider]?.[tier] || TIER_DEFAULTS[llmProvider]?.[tier] || '—'})</option>
                        {modelOptions.map((preset) => (
                          <option key={preset.value} value={preset.value}>
                            {preset.label}
                          </option>
                        ))}
                      </select>
                    </div>
                    {isCustom && (
                      <input
                        type="text"
                        placeholder="Enter custom model ID..."
                        value={model}
                        onChange={(e) => setModel(e.target.value)}
                        className="w-full px-3 py-1.5 bg-dark-900 border border-dark-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500"
                      />
                    )}
                  </div>
                )
              })}
            </div>
          )}

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

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div className="flex items-center gap-3">
              <Lightbulb className="w-5 h-5 text-yellow-400" />
              <div>
                <p className="font-medium text-white">Extended Thinking</p>
                <p className="text-sm text-dark-400">
                  Enable Claude's thinking mode for deeper exploit reasoning and analysis
                </p>
              </div>
            </div>
            <ToggleSwitch enabled={enableExtendedThinking} onToggle={() => setEnableExtendedThinking(!enableExtendedThinking)} />
          </div>

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div className="flex items-center gap-3">
              <Database className="w-5 h-5 text-cyan-400" />
              <div>
                <p className="font-medium text-white">Persistent Memory</p>
                <p className="text-sm text-dark-400">
                  Cross-session learning: remember successful payloads and target fingerprints
                </p>
              </div>
            </div>
            <ToggleSwitch enabled={enablePersistentMemory} onToggle={() => setEnablePersistentMemory(!enablePersistentMemory)} />
          </div>

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div className="flex items-center gap-3">
              <Activity className="w-5 h-5 text-orange-400" />
              <div>
                <p className="font-medium text-white">Observability Tracing</p>
                <p className="text-sm text-dark-400">
                  Structured tracing for agent decisions, tool calls, and token usage
                </p>
              </div>
            </div>
            <ToggleSwitch enabled={enableTracing} onToggle={() => setEnableTracing(!enableTracing)} />
          </div>

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div className="flex items-center gap-3">
              <Bug className="w-5 h-5 text-red-400" />
              <div>
                <p className="font-medium text-white">Bug Bounty Integration</p>
                <p className="text-sm text-dark-400">
                  HackerOne scope parsing, duplicate detection (read-only, no auto-submit)
                </p>
              </div>
            </div>
            <ToggleSwitch enabled={enableBugbountyIntegration} onToggle={() => setEnableBugbountyIntegration(!enableBugbountyIntegration)} />
          </div>

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div className="flex items-center gap-3">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
              <div>
                <p className="font-medium text-white">Vulnerability Enrichment</p>
                <p className="text-sm text-dark-400">
                  Auto-enrich findings with CVE data from NVD and known exploits from ExploitDB
                </p>
              </div>
            </div>
            <ToggleSwitch enabled={enableVulnEnrichment} onToggle={() => setEnableVulnEnrichment(!enableVulnEnrichment)} />
          </div>

          {enableVulnEnrichment && (
            <div className="ml-8">
              <Input
                label="NVD API Key (Optional)"
                type="password"
                value={nvdApiKey}
                onChange={(e) => setNvdApiKey(e.target.value)}
                placeholder={settings?.has_nvd_key ? '••••••••••••••••' : 'Enter NVD API key for faster rate limits'}
                helperText={
                  settings?.has_nvd_key
                    ? 'NVD API key configured (1.5 req/s). Leave empty to keep current key.'
                    : 'Free tier: 0.16 req/s. Get a key at https://nvd.nist.gov/developers/request-an-api-key for 1.5 req/s.'
                }
              />
            </div>
          )}
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

          <div>
            <label className="block text-sm font-medium text-dark-200 mb-2">
              Default Scan Type
            </label>
            <select
              value={defaultScanType}
              onChange={(e) => setDefaultScanType(e.target.value)}
              className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-white focus:outline-none focus:border-primary-500 transition-colors"
            >
              <option value="full">Full (comprehensive)</option>
              <option value="quick">Quick (fast surface scan)</option>
              <option value="custom">Custom</option>
            </select>
            <p className="text-xs text-dark-400 mt-1">Default scan type when creating new scans</p>
          </div>

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div>
              <p className="font-medium text-white">Recon Enabled by Default</p>
              <p className="text-sm text-dark-400">
                Enable reconnaissance phase for new scans by default
              </p>
            </div>
            <ToggleSwitch enabled={reconEnabledByDefault} onToggle={() => setReconEnabledByDefault(!reconEnabledByDefault)} />
          </div>

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

      {/* Security Testing */}
      <Card title="Security Testing" subtitle="WAF evasion and confidence thresholds">
        <div className="space-y-4">
          <div className="flex items-center gap-3 mb-2">
            <ShieldCheck className="w-5 h-5 text-blue-400" />
            <p className="text-sm text-dark-400">
              Configure WAF evasion behavior and confidence-based pivoting for smarter test selection.
            </p>
          </div>

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div>
              <p className="font-medium text-white">Enable WAF Evasion</p>
              <p className="text-sm text-dark-400">
                Auto-apply encoding and bypass techniques when WAF is detected
              </p>
            </div>
            <ToggleSwitch enabled={enableWafEvasion} onToggle={() => setEnableWafEvasion(!enableWafEvasion)} />
          </div>

          <Input
            label="WAF Confidence Threshold"
            type="number"
            min="0"
            max="1"
            step="0.1"
            placeholder="0.7"
            value={wafConfidenceThreshold}
            onChange={(e) => setWafConfidenceThreshold(e.target.value)}
            helperText="Minimum detection confidence (0.0-1.0) before applying WAF evasion techniques"
          />

          <Input
            label="Confidence Pivot Threshold"
            type="number"
            min="0"
            max="100"
            placeholder="30"
            value={confidencePivotThreshold}
            onChange={(e) => setConfidencePivotThreshold(e.target.value)}
            helperText="Pivot away from a vuln type when avg confidence drops below this (0-100)"
          />

          <Input
            label="Confidence Reject Threshold"
            type="number"
            min="0"
            max="100"
            placeholder="40"
            value={confidenceRejectThreshold}
            onChange={(e) => setConfidenceRejectThreshold(e.target.value)}
            helperText="Reject a vuln type after 3+ failures when avg confidence is below this (0-100)"
          />

          <Input
            label="Default Timeout (seconds)"
            type="number"
            min="5"
            max="120"
            placeholder="30"
            value={defaultTimeout}
            onChange={(e) => setDefaultTimeout(e.target.value)}
            helperText="Default HTTP request timeout in seconds"
          />

          <Input
            label="Max Requests per Second"
            type="number"
            min="1"
            max="100"
            placeholder="10"
            value={maxRequestsPerSecond}
            onChange={(e) => setMaxRequestsPerSecond(e.target.value)}
            helperText="Rate limit: maximum requests per second per target"
          />
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
            <p>100 vulnerability types across 10 categories</p>
            <p>665 payloads across 114 libraries</p>
            <p>Multi-provider LLM support (Claude, GPT, OpenRouter, Ollama, AWS Bedrock)</p>
            <p>3-tier model routing with cost tracking</p>
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
