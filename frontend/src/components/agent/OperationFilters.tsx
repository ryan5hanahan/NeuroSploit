import { Search, ArrowUpDown } from 'lucide-react'

const STATUS_FILTERS = [
  { value: 'all', label: 'All' },
  { value: 'completed', label: 'Completed' },
  { value: 'stopped', label: 'Stopped' },
  { value: 'error', label: 'Error' },
  { value: 'budget_exhausted', label: 'Budget' },
  { value: 'cancelled', label: 'Cancelled' },
]

const SORT_OPTIONS = [
  { value: 'newest', label: 'Newest first' },
  { value: 'oldest', label: 'Oldest first' },
  { value: 'findings', label: 'Most findings' },
]

interface Props {
  statusFilter: string
  onStatusChange: (status: string) => void
  sortBy: string
  onSortChange: (sort: string) => void
  searchQuery: string
  onSearchChange: (query: string) => void
}

export default function OperationFilters({
  statusFilter, onStatusChange,
  sortBy, onSortChange,
  searchQuery, onSearchChange,
}: Props) {
  return (
    <div className="flex flex-col sm:flex-row gap-3">
      {/* Status Filters */}
      <div className="flex gap-1.5 flex-wrap flex-1">
        {STATUS_FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => onStatusChange(f.value)}
            className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${
              statusFilter === f.value
                ? 'bg-purple-500/20 text-purple-400 border-purple-500/30'
                : 'bg-dark-800 text-dark-400 border-dark-700 hover:text-white hover:border-dark-600'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Sort */}
      <div className="flex items-center gap-2">
        <ArrowUpDown className="w-3.5 h-3.5 text-dark-500" />
        <select
          value={sortBy}
          onChange={(e) => onSortChange(e.target.value)}
          className="text-xs bg-dark-800 border border-dark-700 rounded-lg px-2 py-1.5 text-dark-300 focus:outline-none focus:ring-1 focus:ring-purple-500"
        >
          {SORT_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-dark-500" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Filter targets..."
          className="text-xs bg-dark-800 border border-dark-700 rounded-lg pl-8 pr-3 py-1.5 text-dark-300 placeholder-dark-600 focus:outline-none focus:ring-1 focus:ring-purple-500 w-40"
        />
      </div>
    </div>
  )
}
