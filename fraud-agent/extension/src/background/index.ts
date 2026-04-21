import type { PlasmoBackground } from "plasmo"

export const config: PlasmoBackground = {
  service_worker: "index.ts",
  type: "module",
}

interface DetectionResult {
  id: string
  timestamp: number
  source: string
  content: string
  threatScore: {
    score: number
    level: string
    confidence: number
  }
  action: string
  notificationLevel: string
  explanation: string
  detectedIndicators: Array<{
    type: string
    value: string
    description: string
  }>
}

const THREAT_SCORE_ALLOW = 0.3

interface StoredDetections {
  detections: DetectionResult[]
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "DETECTION_RESULT") {
    const result = message.payload as DetectionResult

    storeDetection(result)

    if (result.action !== "ALLOW") {
      updateBadge(result.threatScore.score, result.action)
    }

    return true
  }

  if (message.type === "GET_DETECTIONS") {
    getDetections().then((detections) => {
      sendResponse({ detections })
    })
    return true
  }

  if (message.type === "GET_STATS") {
    getStats().then((stats) => {
      sendResponse(stats)
    })
    return true
  }

  return false
})

chrome.runtime.onInstalled.addListener(() => {
  console.log("Fraud Agent installed")
  initializeStorage()
})

async function initializeStorage(): Promise<void> {
  const stored = await chrome.storage.local.get("fraudAgent")
  if (!stored.fraudAgent) {
    await chrome.storage.local.set({
      fraudAgent: {
        detections: [],
        stats: {
          total: 0,
          blocked: 0,
          quarantined: 0,
          warned: 0,
          allowed: 0,
        },
      },
    })
  }
}

async function storeDetection(detection: DetectionResult): Promise<void> {
  const stored = await chrome.storage.local.get("fraudAgent")
  const data = stored.fraudAgent as StoredDetections

  const detections = [detection, ...data.detections].slice(0, 100)

  const stats = { ...data.stats }
  stats.total++

  switch (detection.action) {
    case "BLOCK":
      stats.blocked++
      break
    case "QUARANTINE":
      stats.quarantined++
      break
    case "WARN":
      stats.warned++
      break
    case "ALLOW":
      stats.allowed++
      break
  }

  await chrome.storage.local.set({
    fraudAgent: {
      detections,
      stats,
    },
  })
}

async function getDetections(): Promise<DetectionResult[]> {
  const stored = await chrome.storage.local.get("fraudAgent")
  const data = stored.fraudAgent as StoredDetections
  return data.detections
}

async function getStats(): Promise<{
  total: number
  blocked: number
  quarantined: number
  warned: number
  allowed: number
}> {
  const stored = await chrome.storage.local.get("fraudAgent")
  const data = stored.fraudAgent as { stats: { total: number; blocked: number; quarantined: number; warned: number; allowed: number } }
  return data.stats
}

function updateBadge(score: number, action: string): void {
  if (action === "ALLOW" || score <= THREAT_SCORE_ALLOW) {
    chrome.action.setBadgeText({ text: "" })
    return
  }

  const colors: Record<string, string> = {
    WARN: "#FFC107",
    QUARANTINE: "#FF9800",
    BLOCK: "#F44336",
  }

  const color = colors[action] || "#FF9800"
  const text = score >= 0.85 ? "!" : score >= 0.6 ? "?" : "!"

  chrome.action.setBadgeText({ text })
  chrome.action.setBadgeBackgroundColor({ color })
}