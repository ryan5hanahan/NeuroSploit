import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'

interface ToolUsageChartProps {
  toolUsage: Record<string, number> | null
}

const TOOL_COLORS: Record<string, string> = {
  shell_execute: '#3b82f6',
  http_request: '#22c55e',
  browser_navigate: '#a855f7',
  browser_extract_links: '#a855f7',
  browser_extract_forms: '#a855f7',
  browser_execute_js: '#a855f7',
  browser_screenshot: '#a855f7',
  memory_store: '#06b6d4',
  memory_search: '#06b6d4',
  save_artifact: '#f97316',
  report_finding: '#f97316',
  update_plan: '#eab308',
  stop: '#ef4444',
}

const DEFAULT_COLOR = '#64748b'

export default function ToolUsageChart({ toolUsage }: ToolUsageChartProps) {
  if (!toolUsage || Object.keys(toolUsage).length === 0) {
    return (
      <div className="text-center py-6 text-dark-400 text-sm">
        No tool data yet
      </div>
    )
  }

  const data = Object.entries(toolUsage)
    .filter(([, count]) => count > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([tool, count]) => ({
      tool: tool.replace(/_/g, ' '),
      toolKey: tool,
      count,
    }))

  return (
    <div className="w-full" style={{ height: Math.max(data.length * 32 + 40, 120) }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20, top: 5, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
          <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
          <YAxis
            dataKey="tool"
            type="category"
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            width={120}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#e2e8f0',
              fontSize: 12,
            }}
            formatter={(value: number) => [`${value} calls`, 'Count']}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]}>
            {data.map((entry) => (
              <Cell
                key={entry.toolKey}
                fill={TOOL_COLORS[entry.toolKey] || DEFAULT_COLOR}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
