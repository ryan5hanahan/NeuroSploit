import { useEffect, useState } from 'react'
import {
  Crosshair, Plus, Trash2, Search, X, Save, Edit3, Shield, ToggleLeft, ToggleRight
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import Input from '../components/common/Input'
import Textarea from '../components/common/Textarea'
import { tradecraftApi } from '../services/api'
import type { TradecraftTTP } from '../types'

const CATEGORIES = [
  { id: 'all', name: 'All' },
  { id: 'evasion', name: 'Evasion' },
  { id: 'reconnaissance', name: 'Recon' },
  { id: 'exploitation', name: 'Exploitation' },
  { id: 'validation', name: 'Validation' },
]

const categoryColor = (cat: string) => {
  switch (cat) {
    case 'evasion': return 'bg-red-500/20 text-red-400'
    case 'reconnaissance': return 'bg-blue-500/20 text-blue-400'
    case 'exploitation': return 'bg-orange-500/20 text-orange-400'
    case 'validation': return 'bg-green-500/20 text-green-400'
    default: return 'bg-purple-500/20 text-purple-400'
  }
}

export default function TradecraftPage() {
  const [ttps, setTtps] = useState<TradecraftTTP[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [selected, setSelected] = useState<TradecraftTTP | null>(null)

  // Create/Edit modal
  const [showModal, setShowModal] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [form, setForm] = useState({ name: '', description: '', category: 'evasion', content: '' })
  const [saving, setSaving] = useState(false)

  // Delete confirmation
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const list = await tradecraftApi.list()
      setTtps(list)
    } catch (error) {
      console.error('Failed to load tradecraft TTPs:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleToggle = async (ttp: TradecraftTTP, e: React.MouseEvent) => {
    e.stopPropagation()
    try {
      const updated = await tradecraftApi.update(ttp.id, { enabled: !ttp.enabled })
      setTtps(prev => prev.map(t => (t.id === ttp.id ? updated : t)))
      if (selected?.id === ttp.id) setSelected(updated)
    } catch (error) {
      console.error('Failed to toggle TTP:', error)
    }
  }

  const handleCreate = () => {
    setEditingId(null)
    setForm({ name: '', description: '', category: 'evasion', content: '' })
    setShowModal(true)
  }

  const handleEdit = (ttp: TradecraftTTP) => {
    setEditingId(ttp.id)
    setForm({
      name: ttp.name,
      description: ttp.description || '',
      category: ttp.category,
      content: ttp.content,
    })
    setShowModal(true)
  }

  const handleSave = async () => {
    if (!form.name.trim() || !form.content.trim()) return
    setSaving(true)
    try {
      if (editingId) {
        const updated = await tradecraftApi.update(editingId, {
          name: form.name,
          description: form.description || undefined,
          content: form.content,
          category: form.category,
        })
        setTtps(prev => prev.map(t => (t.id === editingId ? updated : t)))
        setSelected(updated)
      } else {
        const created = await tradecraftApi.create({
          name: form.name,
          description: form.description || undefined,
          content: form.content,
          category: form.category,
        })
        setTtps(prev => [created, ...prev])
        setSelected(created)
      }
      setShowModal(false)
    } catch (error) {
      console.error('Failed to save TTP:', error)
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id: string) => {
    try {
      await tradecraftApi.delete(id)
      setTtps(prev => prev.filter(t => t.id !== id))
      setDeleteConfirm(null)
      if (selected?.id === id) setSelected(null)
    } catch (error) {
      console.error('Failed to delete TTP:', error)
    }
  }

  // Filtering
  const filtered = ttps.filter(t => {
    if (selectedCategory !== 'all' && t.category !== selectedCategory) return false
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      return (
        t.name.toLowerCase().includes(q) ||
        (t.description || '').toLowerCase().includes(q) ||
        t.content.toLowerCase().includes(q)
      )
    }
    return true
  })

  const builtins = filtered.filter(t => t.is_builtin)
  const custom = filtered.filter(t => !t.is_builtin)

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Crosshair className="w-8 h-8 text-primary-500" />
            Tradecraft
          </h1>
          <p className="text-dark-400 mt-1">Manage TTPs that guide agent behavior during security engagements</p>
        </div>
        <Button onClick={handleCreate}>
          <Plus className="w-4 h-4 mr-2" />
          Create TTP
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
                placeholder="Search TTPs..."
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
        {/* TTP List */}
        <div className="lg:col-span-2 space-y-6">
          {loading ? (
            <Card>
              <p className="text-dark-400 text-center py-8">Loading TTPs...</p>
            </Card>
          ) : (
            <>
              {/* Built-in TTPs */}
              {builtins.length > 0 && (
                <div className="space-y-3">
                  <h2 className="text-sm font-semibold text-dark-400 uppercase tracking-wider flex items-center gap-2">
                    <Shield className="w-4 h-4" />
                    Built-in TTPs
                  </h2>
                  {builtins.map((ttp) => (
                    <div
                      key={ttp.id}
                      onClick={() => setSelected(ttp)}
                      className={`bg-dark-800 rounded-lg border p-4 cursor-pointer transition-all ${
                        selected?.id === ttp.id
                          ? 'border-primary-500 bg-primary-500/5'
                          : 'border-dark-700 hover:border-dark-500'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-medium text-white">{ttp.name}</span>
                            <span className="text-xs bg-primary-500/20 text-primary-400 px-2 py-0.5 rounded">
                              Built-in
                            </span>
                          </div>
                          {ttp.description && (
                            <p className="text-sm text-dark-400 line-clamp-2">{ttp.description}</p>
                          )}
                          <div className="flex items-center gap-3 mt-3">
                            <span className={`text-xs px-2 py-0.5 rounded ${categoryColor(ttp.category)}`}>
                              {ttp.category}
                            </span>
                          </div>
                        </div>
                        <button
                          onClick={(e) => handleToggle(ttp, e)}
                          className="flex-shrink-0"
                          title={ttp.enabled ? 'Disable' : 'Enable'}
                        >
                          {ttp.enabled ? (
                            <ToggleRight className="w-8 h-8 text-green-500" />
                          ) : (
                            <ToggleLeft className="w-8 h-8 text-dark-500" />
                          )}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Custom TTPs */}
              <div className="space-y-3">
                <h2 className="text-sm font-semibold text-dark-400 uppercase tracking-wider flex items-center gap-2">
                  <Edit3 className="w-4 h-4" />
                  Custom TTPs
                </h2>
                {custom.length === 0 ? (
                  <Card>
                    <p className="text-dark-400 text-center py-8">
                      {searchQuery || selectedCategory !== 'all'
                        ? 'No custom TTPs match your filters'
                        : 'No custom TTPs yet. Create one to extend the agent\'s methodology!'}
                    </p>
                  </Card>
                ) : (
                  custom.map((ttp) => (
                    <div
                      key={ttp.id}
                      onClick={() => setSelected(ttp)}
                      className={`bg-dark-800 rounded-lg border p-4 cursor-pointer transition-all ${
                        selected?.id === ttp.id
                          ? 'border-primary-500 bg-primary-500/5'
                          : 'border-dark-700 hover:border-dark-500'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-medium text-white">{ttp.name}</span>
                          </div>
                          {ttp.description && (
                            <p className="text-sm text-dark-400 line-clamp-2">{ttp.description}</p>
                          )}
                          <div className="flex items-center gap-3 mt-3">
                            <span className={`text-xs px-2 py-0.5 rounded ${categoryColor(ttp.category)}`}>
                              {ttp.category}
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={(e) => handleToggle(ttp, e)}
                            className="flex-shrink-0"
                            title={ttp.enabled ? 'Disable' : 'Enable'}
                          >
                            {ttp.enabled ? (
                              <ToggleRight className="w-8 h-8 text-green-500" />
                            ) : (
                              <ToggleLeft className="w-8 h-8 text-dark-500" />
                            )}
                          </button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation()
                              handleEdit(ttp)
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
                              setDeleteConfirm(ttp.id)
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
          <Card title="TTP Details">
            {selected ? (
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-dark-400">Name</p>
                  <p className="text-white font-medium">{selected.name}</p>
                </div>

                <div>
                  <p className="text-sm text-dark-400">Description</p>
                  <p className="text-dark-300">{selected.description || 'No description'}</p>
                </div>

                <div>
                  <p className="text-sm text-dark-400">Category</p>
                  <span className={`text-xs px-2 py-0.5 rounded ${categoryColor(selected.category)}`}>
                    {selected.category}
                  </span>
                </div>

                <div>
                  <p className="text-sm text-dark-400">Status</p>
                  <span className={`text-xs px-2 py-0.5 rounded ${selected.enabled ? 'bg-green-500/20 text-green-400' : 'bg-dark-600 text-dark-400'}`}>
                    {selected.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                  {selected.is_builtin && (
                    <span className="text-xs bg-primary-500/20 text-primary-400 px-2 py-0.5 rounded ml-2">
                      Built-in
                    </span>
                  )}
                </div>

                <div>
                  <p className="text-sm text-dark-400 mb-1">Content</p>
                  <pre className="text-xs bg-dark-900 p-3 rounded-lg overflow-auto max-h-80 text-dark-300 whitespace-pre-wrap">
                    {selected.content}
                  </pre>
                </div>

                <div className="text-xs text-dark-500 space-y-1">
                  <p>Created: {new Date(selected.created_at).toLocaleString()}</p>
                  <p>Updated: {new Date(selected.updated_at).toLocaleString()}</p>
                </div>

                {!selected.is_builtin && (
                  <div className="pt-4 border-t border-dark-700 space-y-2">
                    <Button
                      variant="secondary"
                      className="w-full"
                      onClick={() => handleEdit(selected)}
                    >
                      <Edit3 className="w-4 h-4 mr-2" />
                      Edit TTP
                    </Button>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-dark-400 text-center py-8">
                Select a TTP to view details
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
                {editingId ? 'Edit TTP' : 'Create New TTP'}
              </h3>
              <Button variant="ghost" size="sm" onClick={() => setShowModal(false)}>
                <X className="w-5 h-5" />
              </Button>
            </div>

            <div className="p-4 space-y-4">
              <Input
                label="Name"
                placeholder="My Custom TTP"
                value={form.name}
                onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))}
              />

              <Input
                label="Description"
                placeholder="Brief description of this technique"
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
                  <option value="evasion">Evasion</option>
                  <option value="reconnaissance">Reconnaissance</option>
                  <option value="exploitation">Exploitation</option>
                  <option value="validation">Validation</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">Content</label>
                <Textarea
                  placeholder="Enter the TTP guidance that will be injected into the agent's prompt pipeline...&#10;&#10;Example: When encountering rate limiting, rotate X-Forwarded-For headers..."
                  rows={12}
                  value={form.content}
                  onChange={(e) => setForm(f => ({ ...f, content: e.target.value }))}
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 p-4 border-t border-dark-700">
              <Button variant="secondary" onClick={() => setShowModal(false)}>
                Cancel
              </Button>
              <Button
                onClick={handleSave}
                isLoading={saving}
                disabled={!form.name.trim() || form.content.trim().length < 10}
              >
                <Save className="w-4 h-4 mr-2" />
                {editingId ? 'Update TTP' : 'Create TTP'}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 rounded-xl border border-dark-700 p-6 max-w-md">
            <h3 className="text-xl font-bold text-white mb-2">Delete TTP?</h3>
            <p className="text-dark-400 mb-6">
              Are you sure you want to delete this TTP? This action cannot be undone.
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
