import { useQuery } from "@tanstack/react-query"
import { api } from "../lib/api"

interface Report {
  id: string
  hash: string
  threat_score: number
  timestamp: number
  source: string
  indicator_type: string
  report_count: number
}

export default function Reports() {
  const { data: reports, isLoading } = useQuery<Report[]>({
    queryKey: ["reports"],
    queryFn: () => api.getReports(100),
  })

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-gray-900">Community Reports</h2>

      <div className="card">
        <p className="text-gray-600 mb-4">
          Privacy-preserving community threat intelligence. Only hashed
          indicators are shared, never raw content.
        </p>
      </div>

      {isLoading ? (
        <div className="text-center py-12">Loading...</div>
      ) : reports?.length === 0 ? (
        <div className="card text-center py-12">
          <p className="text-gray-500">No reports yet</p>
        </div>
      ) : (
        <div className="card">
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left py-3 text-sm font-medium text-gray-500">
                  Hash (truncated)
                </th>
                <th className="text-left py-3 text-sm font-medium text-gray-500">
                  Type
                </th>
                <th className="text-left py-3 text-sm font-medium text-gray-500">
                  Source
                </th>
                <th className="text-left py-3 text-sm font-medium text-gray-500">
                  Score
                </th>
                <th className="text-left py-3 text-sm font-medium text-gray-500">
                  Reports
                </th>
                <th className="text-left py-3 text-sm font-medium text-gray-500">
                  Date
                </th>
              </tr>
            </thead>
            <tbody>
              {reports?.map((report) => (
                <tr key={report.id} className="border-b hover:bg-gray-50">
                  <td className="py-3 font-mono text-sm">
                    {report.hash.substring(0, 12)}...
                  </td>
                  <td className="py-3">{report.indicator_type}</td>
                  <td className="py-3">{report.source}</td>
                  <td className="py-3">
                    <span
                      className={`px-2 py-1 text-xs rounded ${
                        report.threat_score > 0.85
                          ? "bg-red-100 text-red-800"
                          : report.threat_score > 0.6
                          ? "bg-orange-100 text-orange-800"
                          : "bg-yellow-100 text-yellow-800"
                      }`}
                    >
                      {(report.threat_score * 100).toFixed(0)}%
                    </span>
                  </td>
                  <td className="py-3">{report.report_count}</td>
                  <td className="py-3 text-sm text-gray-500">
                    {new Date(report.timestamp * 1000).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}