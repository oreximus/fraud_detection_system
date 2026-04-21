import { useQuery } from "@tanstack/react-query"
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts"
import { api } from "../lib/api"

interface Stats {
  total_detections: number
  blocked_count: number
  quarantined_count: number
  warned_count: number
  allowed_count: number
  recent_threats: Array<{
    id: string
    source: string
    threat_score: number
    threat_level: string
    timestamp: number
  }>
}

const COLORS = ["#4CAF50", "#FFC107", "#FF9800", "#F44336", "#2196F3"]

export default function Dashboard() {
  const { data: stats, isLoading } = useQuery<Stats>({
    queryKey: ["stats"],
    queryFn: api.getStats,
  })

  if (isLoading) {
    return <div className="text-center py-12">Loading...</div>
  }

  const pieData = stats
    ? [
        { name: "Allowed", value: stats.allowed_count },
        { name: "Warned", value: stats.warned_count },
        { name: "Quarantined", value: stats.quarantined_count },
        { name: "Blocked", value: stats.blocked_count },
      ].filter((d) => d.value > 0)
    : []

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-gray-900">Dashboard</h2>

      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <StatCard label="Total" value={stats?.total_detections || 0} color="primary" />
        <StatCard
          label="Allowed"
          value={stats?.allowed_count || 0}
          color="green"
          type="allowed"
        />
        <StatCard
          label="Warned"
          value={stats?.warned_count || 0}
          color="yellow"
          type="warned"
        />
        <StatCard
          label="Quarantined"
          value={stats?.quarantined_count || 0}
          color="orange"
          type="quarantined"
        />
        <StatCard
          label="Blocked"
          value={stats?.blocked_count || 0}
          color="red"
          type="blocked"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Threat Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                  label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(0)}%`
                  }
                >
                  {pieData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Actions by Count</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={[
                  { name: "Allowed", count: stats?.allowed_count || 0 },
                  { name: "Warned", count: stats?.warned_count || 0 },
                  { name: "Quarantined", count: stats?.quarantined_count || 0 },
                  { name: "Blocked", count: stats?.blocked_count || 0 },
                ]}
              >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#0ea5e9" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {stats?.recent_threats && stats.recent_threats.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Recent Threats</h3>
          <div className="space-y-3">
            {stats.recent_threats.map((threat) => (
              <div
                key={threat.id}
                className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
              >
                <div>
                  <span className="font-medium">{threat.threat_level}</span>
                  <span className="ml-2 text-sm text-gray-500">{threat.source}</span>
                </div>
                <span
                  className={`font-semibold ${
                    threat.threat_score > 0.85
                      ? "text-red-600"
                      : threat.threat_score > 0.6
                      ? "text-orange-500"
                      : "text-yellow-500"
                  }`}
                >
                  {(threat.threat_score * 100).toFixed(0)}%
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function StatCard({
  label,
  value,
  color,
  type,
}: {
  label: string
  value: number
  color?: string
  type?: string
}) {
  const bgColors: Record<string, string> = {
    green: "bg-green-50 border-green-200",
    yellow: "bg-yellow-50 border-yellow-200",
    orange: "bg-orange-50 border-orange-200",
    red: "bg-red-50 border-red-200",
    primary: "bg-primary-50 border-primary-200",
  }

  const textColors: Record<string, string> = {
    green: "text-green-700",
    yellow: "text-yellow-700",
    orange: "text-orange-700",
    red: "text-red-700",
    primary: "text-primary-700",
  }

  return (
    <div className={`card stat-card ${type || ""} ${
      type ? bgColors[type] : ""
    }`}>
      <p className={`text-2xl font-bold ${color ? textColors[color] : ""}`}>
        {value}
      </p>
      <p className="text-sm text-gray-600">{label}</p>
    </div>
  )
}