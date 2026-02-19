import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Plus, ArrowRight } from 'lucide-react'
import Button from '../common/Button'

export default function CommandBar() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = target.trim()
    if (trimmed) {
      navigate(`/agent?target=${encodeURIComponent(trimmed)}`)
    }
  }

  return (
    <div className="flex items-center gap-4">
      <Link to="/agent">
        <Button size="lg">
          <Plus className="w-5 h-5 mr-2" />
          New Operation
        </Button>
      </Link>
      <form onSubmit={handleSubmit} className="flex-1 flex items-center gap-2">
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="Quick target: enter URL to start..."
          className="flex-1 bg-dark-900 border border-dark-700 rounded-lg px-4 py-2.5 text-white placeholder-dark-500 focus:outline-none focus:border-primary-500 transition-colors"
        />
        <button
          type="submit"
          disabled={!target.trim()}
          className="p-2.5 rounded-lg bg-dark-900 border border-dark-700 text-dark-400 hover:text-white hover:border-primary-500 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <ArrowRight className="w-5 h-5" />
        </button>
      </form>
    </div>
  )
}
