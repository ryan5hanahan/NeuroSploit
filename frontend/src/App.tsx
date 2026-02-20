import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/layout/Layout'
import HomePage from './pages/HomePage'
import ScanDetailsPage from './pages/ScanDetailsPage'

import TaskLibraryPage from './pages/TaskLibraryPage'
import RealtimeTaskPage from './pages/RealtimeTaskPage'
import ReportsPage from './pages/ReportsPage'
import ReportViewPage from './pages/ReportViewPage'
import SettingsPage from './pages/SettingsPage'
import SchedulerPage from './pages/SchedulerPage'
import VulnLabPage from './pages/VulnLabPage'
import TerminalAgentPage from './pages/TerminalAgentPage'
import SandboxDashboardPage from './pages/SandboxDashboardPage'
import CompareScanPage from './pages/CompareScanPage'
import PromptsPage from './pages/PromptsPage'
import TradecraftPage from './pages/TradecraftPage'
import AgentPage from './pages/AgentPage'
import AgentDetailPage from './pages/AgentDetailPage'
import BugBountyPage from './pages/BugBountyPage'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<HomePage />} />

        {/* Unified Agent routes */}
        <Route path="/agent" element={<AgentPage />} />
        <Route path="/agent/:operationId" element={<AgentDetailPage />} />

        {/* Redirects from old routes */}
        <Route path="/operations" element={<Navigate to="/agent" replace />} />
        <Route path="/operations/:id" element={<NavigateOperationToAgent />} />
        <Route path="/scan/new" element={<Navigate to="/agent" replace />} />
        <Route path="/auto" element={<Navigate to="/agent" replace />} />

        {/* Existing routes */}
        <Route path="/vuln-lab" element={<VulnLabPage />} />
        <Route path="/terminal" element={<TerminalAgentPage />} />
        <Route path="/scan/:scanId" element={<ScanDetailsPage />} />
        <Route path="/compare" element={<CompareScanPage />} />
        <Route path="/tasks" element={<TaskLibraryPage />} />
        <Route path="/prompts" element={<PromptsPage />} />
        <Route path="/tradecraft" element={<TradecraftPage />} />
        <Route path="/bugbounty" element={<BugBountyPage />} />
        <Route path="/realtime" element={<RealtimeTaskPage />} />
        <Route path="/scheduler" element={<SchedulerPage />} />
        <Route path="/sandboxes" element={<SandboxDashboardPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/reports/:reportId" element={<ReportViewPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Routes>
    </Layout>
  )
}

/** Redirect /operations/:id → /agent/:id */
function NavigateOperationToAgent() {
  const id = window.location.pathname.split('/').pop() || ''
  return <Navigate to={`/agent/${id}`} replace />
}

export default App
