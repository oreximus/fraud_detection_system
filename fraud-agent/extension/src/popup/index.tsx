import { useState, useEffect } from "react"
import type { ReactElement } from "react"

interface ThreatScore {
  score: number
  level: string
  confidence: number
}

interface DetectionResult {
  id: string
  timestamp: number
  source: string
  content: string
  threatScore: ThreatScore
  action: string
  notificationLevel: string
  explanation: string
  detectedIndicators: Array<{
    type: string
    value: string
    description: string
  }>
}

interface Stats {
  total: number
  blocked: number
  quarantined: number
  warned: number
  allowed: number
}

export default function Popup(): ReactElement {
  const [detections, setDetections] = useState<DetectionResult[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [activeTab, setActiveTab] = useState<"history" | "stats">("history")

  useEffect(() => {
    loadData()
  }, [])

  async function loadData(): Promise<void> {
    try {
      const [detectionsResponse, statsResponse] = await Promise.all([
        chrome.runtime.sendMessage({ type: "GET_DETECTIONS" }),
        chrome.runtime.sendMessage({ type: "GET_STATS" }),
      ])

      if (detectionsResponse?.detections) {
        setDetections(detectionsResponse.detections)
      }
      if (statsResponse) {
        setStats(statsResponse)
      }
    } catch (error) {
      console.error("Failed to load data:", error)
    }
  }

  const getActionColor = (action: string): string => {
    const colors: Record<string, string> = {
      BLOCK: "#F44336",
      QUARANTINE: "#FF9800",
      WARN: "#FFC107",
      ALLOW: "#4CAF50",
    }
    return colors[action] || "#999999"
  }

  return (
    <div className="popup">
      <header className="popup-header">
        <h1>Fraud Agent</h1>
        <span className="popup-badge">v0.1.0</span>
      </header>

      <nav className="popup-nav">
        <button
          className={`nav-button ${activeTab === "history" ? "active" : ""}`}
          onClick={() => setActiveTab("history")}
        >
          History
        </button>
        <button
          className={`nav-button ${activeTab === "stats" ? "active" : ""}`}
          onClick={() => setActiveTab("stats")}
        >
          Stats
        </button>
      </nav>

      <main className="popup-content">
        {activeTab === "history" && (
          <div className="detections-list">
            {detections.length === 0 ? (
              <p className="empty-message">No detections yet</p>
            ) : (
              detections.slice(0, 10).map((detection) => (
                <div key={detection.id} className="detection-item">
                  <div className="detection-header">
                    <span
                      className="detection-score"
                      style={{ color: getActionColor(detection.action) }}
                    >
                      {(detection.threatScore.score * 100).toFixed(0)}%
                    </span>
                    <span className="detection-action">{detection.action}</span>
                  </div>
                  <p className="detection-explanation">{detection.explanation}</p>
                  {detection.detectedIndicators.length > 0 && (
                    <div className="detection-indicators">
                      {detection.detectedIndicators.slice(0, 3).map((ind, i) => (
                        <span key={i} className="indicator">
                          {ind.type}: {ind.value}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "stats" && stats && (
          <div className="stats-grid">
            <div className="stat-card total">
              <span className="stat-value">{stats.total}</span>
              <span className="stat-label">Total</span>
            </div>
            <div className="stat-card blocked">
              <span className="stat-value">{stats.blocked}</span>
              <span className="stat-label">Blocked</span>
            </div>
            <div className="stat-card quarantined">
              <span className="stat-value">{stats.quarantined}</span>
              <span className="stat-label">Quarantined</span>
            </div>
            <div className="stat-card warned">
              <span className="stat-value">{stats.warned}</span>
              <span className="stat-label">Warned</span>
            </div>
            <div className="stat-card allowed">
              <span className="stat-value">{stats.allowed}</span>
              <span className="stat-label">Allowed</span>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}