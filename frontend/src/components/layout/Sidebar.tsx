import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  Home,
  Bot,
  BookOpen,
  FileText,
  Settings,
  Activity,
  Zap,
  Clock,
  FlaskConical,
  Terminal,
  Container,
  MessageSquare,
  Crosshair,
  Bug,
  ShieldCheck,
  Swords,
  ChevronDown,
  Library,
} from 'lucide-react'
import { useThemeStore, type Theme } from '../../store/theme'
import SploitLogo from './SploitLogo'

interface NavLink {
  kind: 'link'
  path: string
  icon: typeof Home
  label: string
}

interface NavGroup {
  kind: 'group'
  id: string
  icon: typeof Home
  label: string
  children: NavLink[]
}

type NavItem = NavLink | NavGroup

const navItems: NavItem[] = [
  { kind: 'link', path: '/', icon: Home, label: 'Dashboard' },
  { kind: 'link', path: '/agent', icon: Bot, label: 'Agent' },
  {
    kind: 'group',
    id: 'testing-lab',
    icon: Swords,
    label: 'Testing Lab',
    children: [
      { kind: 'link', path: '/vuln-lab', icon: FlaskConical, label: 'Vuln Lab' },
      { kind: 'link', path: '/terminal', icon: Terminal, label: 'Terminal Agent' },
      { kind: 'link', path: '/realtime', icon: Zap, label: 'Real-time Task' },
    ],
  },
  { kind: 'link', path: '/sandboxes', icon: Container, label: 'Sandboxes' },
  {
    kind: 'group',
    id: 'knowledge-base',
    icon: Library,
    label: 'Knowledge Base',
    children: [
      { kind: 'link', path: '/tasks', icon: BookOpen, label: 'Task Library' },
      { kind: 'link', path: '/prompts', icon: MessageSquare, label: 'Prompt Library' },
      { kind: 'link', path: '/tradecraft', icon: Crosshair, label: 'Tradecraft' },
    ],
  },
  { kind: 'link', path: '/bugbounty', icon: Bug, label: 'Bug Bounty' },
  { kind: 'link', path: '/governance', icon: ShieldCheck, label: 'Governance' },
  { kind: 'link', path: '/scheduler', icon: Clock, label: 'Scheduler' },
  { kind: 'link', path: '/reports', icon: FileText, label: 'Reports' },
  { kind: 'link', path: '/settings', icon: Settings, label: 'Settings' },
]

const themes: { id: Theme; label: string; color: string }[] = [
  { id: 'midnight', label: 'Midnight', color: 'bg-[#e94560]' },
  { id: 'cyber', label: 'Cyber', color: 'bg-[#00D1FF]' },
  { id: 'terminal', label: 'Terminal', color: 'bg-[#00FF88]' },
]

function NavLinkItem({ item, isActive, indented = false }: {
  item: NavLink
  isActive: boolean
  indented?: boolean
}) {
  const Icon = item.icon
  return (
    <li>
      <Link
        to={item.path}
        className={`flex items-center gap-3 ${indented ? 'pl-10 pr-4' : 'px-4'} py-3 rounded-lg transition-colors ${
          isActive
            ? 'bg-primary-500/20 text-primary-500'
            : 'text-dark-300 hover:bg-dark-900/50 hover:text-white'
        }`}
      >
        <Icon className="w-5 h-5" />
        <span>{item.label}</span>
      </Link>
    </li>
  )
}

function NavGroupItem({ group, isOpen, onToggle, isPathActive }: {
  group: NavGroup
  isOpen: boolean
  onToggle: () => void
  isPathActive: (path: string) => boolean
}) {
  const Icon = group.icon
  const hasActiveChild = group.children.some(child => isPathActive(child.path))

  return (
    <li>
      <button
        onClick={onToggle}
        aria-expanded={isOpen}
        className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
          hasActiveChild
            ? 'text-primary-500'
            : 'text-dark-300 hover:bg-dark-900/50 hover:text-white'
        }`}
      >
        <Icon className="w-5 h-5" />
        <span className="flex-1 text-left">{group.label}</span>
        <ChevronDown
          className={`w-4 h-4 transition-transform duration-200 ${
            isOpen ? 'rotate-0' : '-rotate-90'
          }`}
        />
      </button>
      <div
        className={`overflow-hidden transition-all duration-200 ease-in-out ${
          isOpen ? 'max-h-96 opacity-100' : 'max-h-0 opacity-0'
        }`}
      >
        <ul className="mt-1 space-y-1">
          {group.children.map(child => (
            <NavLinkItem
              key={child.path}
              item={child}
              isActive={isPathActive(child.path)}
              indented
            />
          ))}
        </ul>
      </div>
    </li>
  )
}

export default function Sidebar() {
  const location = useLocation()
  const { theme, setTheme } = useThemeStore()
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set())

  const isPathActive = (path: string): boolean => {
    if (path === '/') return location.pathname === '/'
    return location.pathname === path || location.pathname.startsWith(path + '/')
  }

  const isGroupActive = (group: NavGroup): boolean => {
    return group.children.some(child => isPathActive(child.path))
  }

  const isGroupOpen = (group: NavGroup): boolean => {
    return openGroups.has(group.id) || isGroupActive(group)
  }

  const toggleGroup = (groupId: string) => {
    setOpenGroups(prev => {
      const next = new Set(prev)
      if (next.has(groupId)) {
        next.delete(groupId)
      } else {
        next.add(groupId)
      }
      return next
    })
  }

  return (
    <aside className="w-64 bg-dark-800 border-r border-dark-900/50 flex flex-col">
      {/* Logo */}
      <div className="px-5 py-4 border-b border-dark-900/50">
        <Link to="/">
          <SploitLogo className="h-10 w-auto" />
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4">
        <ul className="space-y-2">
          {navItems.map((item) => {
            if (item.kind === 'group') {
              return (
                <NavGroupItem
                  key={item.id}
                  group={item}
                  isOpen={isGroupOpen(item)}
                  onToggle={() => toggleGroup(item.id)}
                  isPathActive={isPathActive}
                />
              )
            }
            return (
              <NavLinkItem
                key={item.path}
                item={item}
                isActive={isPathActive(item.path)}
              />
            )
          })}
        </ul>
      </nav>

      {/* Status + Theme */}
      <div className="p-4 border-t border-dark-900/50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm">
            <Activity className="w-4 h-4 text-green-500" />
            <span className="text-dark-400">System Online</span>
          </div>
          <div className="flex items-center gap-1.5">
            {themes.map((t) => (
              <button
                key={t.id}
                onClick={() => setTheme(t.id)}
                title={t.label}
                className={`w-3.5 h-3.5 rounded-full ${t.color} transition-all ${
                  theme === t.id
                    ? 'ring-2 ring-white/60 ring-offset-1 ring-offset-dark-800 scale-110'
                    : 'opacity-50 hover:opacity-80'
                }`}
              />
            ))}
          </div>
        </div>
      </div>
    </aside>
  )
}
