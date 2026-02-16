import { useEffect, useState, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  MessageSquare, Plus, Trash2, Play, Search, X, Save, Copy,
  Upload, Edit3, Shield, Tag
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import Input from '../components/common/Input'
import Textarea from '../components/common/Textarea'
import { promptsApi } from '../services/api'
import type { Prompt, PromptPreset } from '../types'

const CATEGORIES = [
  { id: 'all', name: 'All' },
  { id: 'pentest', name: 'Pentest' },
  { id: 'api', name: 'API' },
  { id: 'bug_bounty', name: 'Bug Bounty' },
  { id: 'compliance', name: 'Compliance' },
  { id: 'auth', name: 'Auth' },
  { id: 'quick', name: 'Quick' },
  { id: 'custom', name: 'Custom' },
]

interface PresetDetail {
  id: string
  name: string
  description: string
  category: string
  content: string
}

type SelectedItem =
  | { type: 'preset'; data: PresetDetail }
  | { type: 'custom'; data: Prompt }

export default function PromptsPage() {
  const navigate = useNavigate()
  const fileInputRef = useRef<HTMLInputElement>(null)

  const [presets, setPresets] = useState<PromptPreset[]>([])
  const [customPrompts, setCustomPrompts] = useState<Prompt[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [selected, setSelected] = useState<SelectedItem | null>(null)
  const [loadingDetail, setLoadingDetail] = useState(false)

  // Create/Edit modal
  const [showModal, setShowModal] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [form, setForm] = useState({ name: '', description: '', category: 'custom', content: '' })
  const [saving, setSaving] = useState(false)
  const [parsedVulns, setParsedVulns] = useState<string[]>([])
  const [parsing, setParsing] = useState(false)
  const parseTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Delete confirmation
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const [presetList, customList] = await Promise.all([
        promptsApi.getPresets(),
        promptsApi.list(),
      ])
      setPresets(presetList)
      setCustomPrompts(customList)
    } catch (error) {
      console.error('Failed to load prompts:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleSelectPreset = async (preset: PromptPreset) => {
    setLoadingDetail(true)
    try {
      const detail = await promptsApi.getPreset(preset.id)
      setSelected({ type: 'preset', data: detail })
    } catch (error) {
      console.error('Failed to load preset detail:', error)
    } finally {
      setLoadingDetail(false)
    }
  }

  const handleSelectCustom = (prompt: Prompt) => {
    setSelected({ type: 'custom', data: prompt })
  }

  const handleUseInScan = (content: string) => {
    navigate('/scan/new', { state: { promptContent: content } })
  }

  const handleDuplicate = (preset: PresetDetail) => {
    setEditingId(null)
    setForm({
      name: `${preset.name} (Copy)`,
      description: preset.description,
      category: preset.category,
      content: preset.content,
    })
    setParsedVulns([])
    setShowModal(true)
    debounceParse(preset.content)
  }

  const handleEdit = (prompt: Prompt) => {
    setEditingId(prompt.id)
    setForm({
      name: prompt.name,
      description: prompt.description || '',
      category: prompt.category || 'custom',
      content: prompt.content,
    })
    setParsedVulns(
      Array.isArray(prompt.parsed_vulnerabilities)
        ? prompt.parsed_vulnerabilities.map((v: any) => v.name || v.type || String(v))
        : []
    )
    setShowModal(true)
  }

  const handleCreate = () => {
    setEditingId(null)
    setForm({ name: '', description: '', category: 'custom', content: '' })
    setParsedVulns([])
    setShowModal(true)
  }

  const debounceParse = useCallback((content: string) => {
    if (parseTimer.current) clearTimeout(parseTimer.current)
    if (!content.trim()) {
      setParsedVulns([])
      return
    }
    parseTimer.current = setTimeout(async () => {
      setParsing(true)
      try {
        const result = await promptsApi.parse(content)
        const vulns = result.vulnerabilities_to_test || result.vulnerabilities || []
        setParsedVulns(vulns.map((v: any) => v.name || v.type || String(v)))
      } catch {
        // ignore parse errors
      } finally {
        setParsing(false)
      }
    }, 600)
  }, [])

  const handleContentChange = (content: string) => {
    setForm(f => ({ ...f, content }))
    debounceParse(content)
  }

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    try {
      const result = await promptsApi.upload(file)
      setForm(f => ({ ...f, content: result.content }))
      debounceParse(result.content)
    } catch (error) {
      console.error('Failed to upload file:', error)
    }
    // Reset input so same file can be re-uploaded
    e.target.value = ''
  }

  const handleSave = async () => {
    if (!form.name.trim() || !form.content.trim()) return

    setSaving(true)
    try {
      if (editingId) {
        const updated = await promptsApi.update(editingId, {
          name: form.name,
          description: form.description || undefined,
          content: form.content,
          category: form.category,
        })
        setCustomPrompts(prev => prev.map(p => (p.id === editingId ? updated : p)))
        setSelected({ type: 'custom', data: updated })
      } else {
        const created = await promptsApi.create({
          name: form.name,
          description: form.description || undefined,
          content: form.content,
          category: form.category,
        })
        setCustomPrompts(prev => [created, ...prev])
        setSelected({ type: 'custom', data: created })
      }
      setShowModal(false)
    } catch (error) {
      console.error('Failed to save prompt:', error)
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id: string) => {
    try {
      await promptsApi.delete(id)
      setCustomPrompts(prev => prev.filter(p => p.id !== id))
      setDeleteConfirm(null)
      if (selected?.type === 'custom' && selected.data.id === id) {
        setSelected(null)
      }
    } catch (error) {
      console.error('Failed to delete prompt:', error)
    }
  }

  // Filtering
  const filteredPresets = presets.filter(p => {
    if (selectedCategory !== 'all' && p.category !== selectedCategory) return false
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      return p.name.toLowerCase().includes(q) || p.description.toLowerCase().includes(q)
    }
    return true
  })

  const filteredCustom = customPrompts.filter(p => {
    if (selectedCategory !== 'all' && p.category !== selectedCategory) return false
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      return (
        p.name.toLowerCase().includes(q) ||
        (p.description || '').toLowerCase().includes(q) ||
        p.content.toLowerCase().includes(q)
      )
    }
    return true
  })

  const categoryColor = (cat: string) => {
    switch (cat) {
      case 'pentest': return 'bg-red-500/20 text-red-400'
      case 'api': return 'bg-blue-500/20 text-blue-400'
      case 'bug_bounty': return 'bg-orange-500/20 text-orange-400'
      case 'compliance': return 'bg-green-500/20 text-green-400'
      case 'auth': return 'bg-yellow-500/20 text-yellow-400'
      case 'quick': return 'bg-cyan-500/20 text-cyan-400'
      default: return 'bg-purple-500/20 text-purple-400'
    }
  }

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <MessageSquare className="w-8 h-8 text-primary-500" />
            Prompt Library
          </h1>
          <p className="text-dark-400 mt-1">Browse, create, and manage reusable security testing prompts</p>
        </div>
        <Button onClick={handleCreate}>
          <Plus className="w-4 h-4 mr-2" />
          Create Prompt
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <div className="flex flex-wrap gap-4">
          <div className="flex-1 min-w-[200px]">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
              <input
                type="text"
                placeholder="Search prompts..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-dark-900 border border-dark-700 rounded-lg text-white placeholder-dark-500 focus:border-primary-500 focus:outline-none"
              />
            </div>
          </div>
          <div className="flex gap-2 flex-wrap">
            {CATEGORIES.map((cat) => (
              <Button
                key={cat.id}
                variant={selectedCategory === cat.id ? 'primary' : 'secondary'}
                size="sm"
                onClick={() => setSelectedCategory(cat.id)}
              >
                {cat.name}
              </Button>
            ))}
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Prompt List */}
        <div className="lg:col-span-2 space-y-6">
          {loading ? (
            <Card>
              <p className="text-dark-400 text-center py-8">Loading prompts...</p>
            </Card>
          ) : (
            <>
              {/* Presets Section */}
              {filteredPresets.length > 0 && (
                <div className="space-y-3">
                  <h2 className="text-sm font-semibold text-dark-400 uppercase tracking-wider flex items-center gap-2">
                    <Shield className="w-4 h-4" />
                    Preset Prompts
                  </h2>
                  {filteredPresets.map((preset) => (
                    <div
                      key={preset.id}
                      onClick={() => handleSelectPreset(preset)}
                      className={`bg-dark-800 rounded-lg border p-4 cursor-pointer transition-all ${
                        selected?.type === 'preset' && selected.data.id === preset.id
                          ? 'border-primary-500 bg-primary-500/5'
                          : 'border-dark-700 hover:border-dark-500'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-medium text-white">{preset.name}</span>
                            <span className="text-xs bg-primary-500/20 text-primary-400 px-2 py-0.5 rounded">
                              Preset
                            </span>
                          </div>
                          <p className="text-sm text-dark-400 line-clamp-2">{preset.description}</p>
                          <div className="flex items-center gap-3 mt-3">
                            <span className={`text-xs px-2 py-0.5 rounded ${categoryColor(preset.category)}`}>
                              {preset.category}
                            </span>
                            <span className="text-xs text-dark-500 flex items-center gap-1">
                              <Tag className="w-3 h-3" />
                              {preset.vulnerability_count} vuln types
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={async (e) => {
                              e.stopPropagation()
                              try {
                                const detail = await promptsApi.getPreset(preset.id)
                                handleUseInScan(detail.content)
                              } catch (error) {
                                console.error('Failed to load preset:', error)
                              }
                            }}
                            title="Use in Scan"
                          >
                            <Play className="w-4 h-4" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Custom Prompts Section */}
              <div className="space-y-3">
                <h2 className="text-sm font-semibold text-dark-400 uppercase tracking-wider flex items-center gap-2">
                  <Edit3 className="w-4 h-4" />
                  Custom Prompts
                </h2>
                {filteredCustom.length === 0 ? (
                  <Card>
                    <p className="text-dark-400 text-center py-8">
                      {searchQuery || selectedCategory !== 'all'
                        ? 'No custom prompts match your filters'
                        : 'No custom prompts yet. Create one or duplicate a preset!'}
                    </p>
                  </Card>
                ) : (
                  filteredCustom.map((prompt) => (
                    <div
                      key={prompt.id}
                      onClick={() => handleSelectCustom(prompt)}
                      className={`bg-dark-800 rounded-lg border p-4 cursor-pointer transition-all ${
                        selected?.type === 'custom' && selected.data.id === prompt.id
                          ? 'border-primary-500 bg-primary-500/5'
                          : 'border-dark-700 hover:border-dark-500'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-medium text-white">{prompt.name}</span>
                          </div>
                          {prompt.description && (
                            <p className="text-sm text-dark-400 line-clamp-2">{prompt.description}</p>
                          )}
                          <div className="flex items-center gap-3 mt-3">
                            <span className={`text-xs px-2 py-0.5 rounded ${categoryColor(prompt.category || 'custom')}`}>
                              {prompt.category || 'custom'}
                            </span>
                            {Array.isArray(prompt.parsed_vulnerabilities) && prompt.parsed_vulnerabilities.length > 0 && (
                              <span className="text-xs text-dark-500 flex items-center gap-1">
                                <Tag className="w-3 h-3" />
                                {prompt.parsed_vulnerabilities.length} vuln types
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation()
                              handleUseInScan(prompt.content)
                            }}
                            title="Use in Scan"
                          >
                            <Play className="w-4 h-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation()
                              handleEdit(prompt)
                            }}
                            title="Edit"
                          >
                            <Edit3 className="w-4 h-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation()
                              setDeleteConfirm(prompt.id)
                            }}
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4 text-red-400" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </>
          )}
        </div>

        {/* Details Panel */}
        <div>
          <Card title="Prompt Details">
            {loadingDetail ? (
              <p className="text-dark-400 text-center py-8">Loading...</p>
            ) : selected ? (
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-dark-400">Name</p>
                  <p className="text-white font-medium">{selected.data.name}</p>
                </div>

                <div>
                  <p className="text-sm text-dark-400">Description</p>
                  <p className="text-dark-300">{selected.data.description || 'No description'}</p>
                </div>

                <div>
                  <p className="text-sm text-dark-400">Category</p>
                  <span className={`text-xs px-2 py-0.5 rounded ${categoryColor(selected.data.category || 'custom')}`}>
                    {selected.data.category || 'custom'}
                  </span>
                </div>

                <div>
                  <p className="text-sm text-dark-400 mb-1">Content</p>
                  <pre className="text-xs bg-dark-900 p-3 rounded-lg overflow-auto max-h-60 text-dark-300 whitespace-pre-wrap">
                    {selected.data.content}
                  </pre>
                </div>

                {/* Parsed vulnerabilities */}
                {selected.type === 'custom' && Array.isArray(selected.data.parsed_vulnerabilities) && selected.data.parsed_vulnerabilities.length > 0 && (
                  <div>
                    <p className="text-sm text-dark-400 mb-1">Parsed Vulnerability Types</p>
                    <div className="flex gap-1 flex-wrap">
                      {selected.data.parsed_vulnerabilities.map((v: any, i: number) => (
                        <span key={i} className="text-xs bg-red-500/15 text-red-400 px-2 py-0.5 rounded">
                          {v.name || v.type || String(v)}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {selected.type === 'custom' && (
                  <div className="text-xs text-dark-500 space-y-1">
                    <p>Created: {new Date(selected.data.created_at).toLocaleString()}</p>
                    <p>Updated: {new Date(selected.data.updated_at).toLocaleString()}</p>
                  </div>
                )}

                <div className="pt-4 border-t border-dark-700 space-y-2">
                  <Button
                    className="w-full"
                    onClick={() => handleUseInScan(selected.data.content)}
                  >
                    <Play className="w-4 h-4 mr-2" />
                    Use in Scan
                  </Button>
                  {selected.type === 'preset' && (
                    <Button
                      variant="secondary"
                      className="w-full"
                      onClick={() => handleDuplicate(selected.data)}
                    >
                      <Copy className="w-4 h-4 mr-2" />
                      Duplicate to Custom
                    </Button>
                  )}
                  {selected.type === 'custom' && (
                    <Button
                      variant="secondary"
                      className="w-full"
                      onClick={() => handleEdit(selected.data)}
                    >
                      <Edit3 className="w-4 h-4 mr-2" />
                      Edit Prompt
                    </Button>
                  )}
                </div>
              </div>
            ) : (
              <p className="text-dark-400 text-center py-8">
                Select a prompt to view details
              </p>
            )}
          </Card>
        </div>
      </div>

      {/* Create/Edit Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 rounded-xl border border-dark-700 w-full max-w-2xl max-h-[90vh] overflow-auto">
            <div className="flex items-center justify-between p-4 border-b border-dark-700">
              <h3 className="text-xl font-bold text-white">
                {editingId ? 'Edit Prompt' : 'Create New Prompt'}
              </h3>
              <Button variant="ghost" size="sm" onClick={() => setShowModal(false)}>
                <X className="w-5 h-5" />
              </Button>
            </div>

            <div className="p-4 space-y-4">
              <Input
                label="Name"
                placeholder="My Custom Prompt"
                value={form.name}
                onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))}
              />

              <Input
                label="Description"
                placeholder="Brief description of what this prompt tests"
                value={form.description}
                onChange={(e) => setForm(f => ({ ...f, description: e.target.value }))}
              />

              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">Category</label>
                <select
                  value={form.category}
                  onChange={(e) => setForm(f => ({ ...f, category: e.target.value }))}
                  className="w-full px-4 py-2 bg-dark-900 border border-dark-700 rounded-lg text-white focus:border-primary-500 focus:outline-none"
                >
                  <option value="custom">Custom</option>
                  <option value="pentest">Pentest</option>
                  <option value="api">API</option>
                  <option value="bug_bounty">Bug Bounty</option>
                  <option value="compliance">Compliance</option>
                  <option value="auth">Auth</option>
                  <option value="quick">Quick</option>
                </select>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-sm font-medium text-dark-300">Content</label>
                  <div>
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleFileUpload}
                      accept=".md,.txt"
                      className="hidden"
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => fileInputRef.current?.click()}
                    >
                      <Upload className="w-4 h-4 mr-1" />
                      Upload File
                    </Button>
                  </div>
                </div>
                <Textarea
                  placeholder="Enter your security testing prompt...&#10;&#10;Example: Test for SQL injection on all form inputs, check for authentication bypass..."
                  rows={12}
                  value={form.content}
                  onChange={(e) => handleContentChange(e.target.value)}
                />
              </div>

              {/* Live parse preview */}
              {(parsedVulns.length > 0 || parsing) && (
                <div>
                  <p className="text-sm text-dark-400 mb-1">
                    {parsing ? 'Parsing vulnerability types...' : 'Detected Vulnerability Types'}
                  </p>
                  {!parsing && (
                    <div className="flex gap-1 flex-wrap">
                      {parsedVulns.map((v, i) => (
                        <span key={i} className="text-xs bg-red-500/15 text-red-400 px-2 py-0.5 rounded">
                          {v}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3 p-4 border-t border-dark-700">
              <Button variant="secondary" onClick={() => setShowModal(false)}>
                Cancel
              </Button>
              <Button
                onClick={handleSave}
                isLoading={saving}
                disabled={!form.name.trim() || !form.content.trim()}
              >
                <Save className="w-4 h-4 mr-2" />
                {editingId ? 'Update Prompt' : 'Create Prompt'}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 rounded-xl border border-dark-700 p-6 max-w-md">
            <h3 className="text-xl font-bold text-white mb-2">Delete Prompt?</h3>
            <p className="text-dark-400 mb-6">
              Are you sure you want to delete this prompt? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <Button variant="secondary" onClick={() => setDeleteConfirm(null)}>
                Cancel
              </Button>
              <Button variant="danger" onClick={() => handleDelete(deleteConfirm)}>
                <Trash2 className="w-4 h-4 mr-2" />
                Delete
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
