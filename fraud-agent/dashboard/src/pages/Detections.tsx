import { useState } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { api } from "../lib/api"

interface Detection {
  id: string
  timestamp: number
  source: string
  content: string
  threat_score: number
  threat_level: string
  confidence: number
  action: string
  notification_level: string
  explanation: string
  indicators: Array<{
    type: string
    value: string
    description: string
  }>
}

export default function Detections() {
  const [selected, setSelected] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const { data: detections, isLoading } = useQuery<Detection[]>({
    queryKey: ["detections"],
    queryFn: () => api.getDetections(100, 0),
  })

  const { data: detection } = useQuery<Detection>({
    queryKey: ["detection", selected],
    queryFn: () => api.getDetection(selected!),
    enabled: !!selected,
  })

  const analyzeMutation = useMutation({
    mutationFn: ({ content, source }: { content: string; source: string }) =>
      api.analyzeContent(content, source),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["detections"] })
      queryClient.invalidateQueries({ queryKey: ["stats"] })
    },
  })

  const [newContent, setNewContent] = useState("")
  const [newSource, setNewSource] = useState("SMS")

  const handleAnalyze = () => {
    if (newContent.trim()) {
      analyzeMutation.mutate({ content: newContent, source: newSource })
      setNewContent("")
    }
  }

  const getActionColor = (action: string) => {
    const colors: Record<string, string> = {
      BLOCK: "bg-red-100 text-red-800",
      QUARANTINE: "bg-orange-100 text-orange-800",
      WARN: "bg-yellow-100 text-yellow-800",
      ALLOW: "bg-green-100 text-green-800",
    }
    return colors[action] || "bg-gray-100 text-gray-800"
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-gray-900">Detections</h2>
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold mb-4">Analyze Content</h3>
        <div className="flex gap-4">
          <select
            value={newSource}
            onChange={(e) => setNewSource(e.target.value)}
            className="input max-w-32"
          >
            <option value="SMS">SMS</option>
            <option value="EMAIL">Email</option>
            <option value="BROWSER">Browser</option>
          </select>
          <input
            type="text"
            value={newContent}
            onChange={(e) => setNewContent(e.target.value)}
            placeholder="Enter content to analyze..."
            className="input flex-1"
          />
          <button
            onClick={handleAnalyze}
            disabled={analyzeMutation.isPending || !newContent.trim()}
            className="btn btn-primary"
          >
            {analyzeMutation.isPending ? "Analyzing..." : "Analyze"}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">History</h3>
          {isLoading ? (
            <p className="text-gray-500">Loading...</p>
          ) : detections?.length === 0 ? (
            <p className="text-gray-500">No detections yet</p>
          ) : (
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {detections?.map((d) => (
                <div
                  key={d.id}
                  onClick={() => setSelected(d.id)}
                  className={`p-3 rounded-lg cursor-pointer transition-colors ${
                    selected === d.id
                      ? "bg-primary-50 border border-primary-200"
                      : "bg-gray-50 hover:bg-gray-100"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm text-gray-500">{d.source}</span>
                      <p className="text-sm truncate max-w-xs">
                        {d.content.substring(0, 50)}...
                      </p>
                    </div>
                    <span
                      className={`px-2 py-1 text-xs font-medium rounded ${getActionColor(
                        d.action
                      )}`}
                    >
                      {d.action}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Details</h3>
          {detection ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-gray-600">Threat Level</span>
                <span
                  className={`font-semibold ${
                    detection.threat_level === "SCAM"
                      ? "text-red-600"
                      : detection.threat_level === "PHISHING"
                      ? "text-orange-600"
                      : detection.threat_level === "SUSPICIOUS"
                      ? "text-yellow-600"
                      : "text-green-600"
                  }`}
                >
                  {detection.threat_level}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-gray-600">Score</span>
                <span className="font-semibold">
                  {(detection.threat_score * 100).toFixed(0)}%
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-gray-600">Confidence</span>
                <span className="font-semibold">
                  {(detection.confidence * 100).toFixed(0)}%
                </span>
              </div>

              <div className="pt-2 border-t">
                <p className="text-gray-600 text-sm mb-1">Explanation</p>
                <p className="text-gray-900">{detection.explanation}</p>
              </div>

              {detection.indicators.length > 0 && (
                <div className="pt-2 border-t">
                  <p className="text-gray-600 text-sm mb-2">Indicators</p>
                  <div className="flex flex-wrap gap-2">
                    {detection.indicators.map((ind, i) => (
                      <span
                        key={i}
                        className="px-2 py-1 text-xs bg-gray-100 rounded"
                      >
                        {ind.type}: {ind.value}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="pt-2 border-t text-sm text-gray-500">
                {detection.source} • {new Date(detection.timestamp).toLocaleString()}
              </div>
            </div>
          ) : (
            <p className="text-gray-500">Select a detection to view details</p>
          )}
        </div>
      </div>
    </div>
  )
}