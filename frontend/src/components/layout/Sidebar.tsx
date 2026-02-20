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
} from 'lucide-react'
import { useThemeStore, type Theme } from '../../store/theme'
import SploitLogo from './SploitLogo'

const navItems = [
  { path: '/', icon: Home, label: 'Dashboard' },
  { path: '/agent', icon: Bot, label: 'Agent' },
  { path: '/vuln-lab', icon: FlaskConical, label: 'Vuln Lab' },
  { path: '/terminal', icon: Terminal, label: 'Terminal Agent' },
  { path: '/sandboxes', icon: Container, label: 'Sandboxes' },
  { path: '/realtime', icon: Zap, label: 'Real-time Task' },
  { path: '/tasks', icon: BookOpen, label: 'Task Library' },
  { path: '/prompts', icon: MessageSquare, label: 'Prompt Library' },
  { path: '/tradecraft', icon: Crosshair, label: 'Tradecraft' },
  { path: '/bugbounty', icon: Bug, label: 'Bug Bounty' },
  { path: '/governance', icon: ShieldCheck, label: 'Governance' },
  { path: '/scheduler', icon: Clock, label: 'Scheduler' },
  { path: '/reports', icon: FileText, label: 'Reports' },
  { path: '/settings', icon: Settings, label: 'Settings' },
]

const themes: { id: Theme; label: string; color: string }[] = [
  { id: 'midnight', label: 'Midnight', color: 'bg-[#e94560]' },
  { id: 'cyber', label: 'Cyber', color: 'bg-[#00D1FF]' },
  { id: 'terminal', label: 'Terminal', color: 'bg-[#00FF88]' },
]

export default function Sidebar() {
  const location = useLocation()
  const { theme, setTheme } = useThemeStore()

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
            const isActive = item.path === '/'
              ? location.pathname === '/'
              : location.pathname === item.path || location.pathname.startsWith(item.path + '/')
            const Icon = item.icon
            return (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
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
