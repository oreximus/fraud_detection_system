import type { PlasmoContentScript } from "plasmo"

export const config: PlasmoContentScript = {
  matches: ["<all_urls>"],
  run_at: "document_idle",
  js: ["index.ts"],
  css: ["styles.css"],
}

const THREAT_SCORE_ALLOW = 0.30
const THREAT_SCORE_WARN = 0.60
const THREAT_SCORE_QUARANTINE = 0.85

interface ThreatScore {
  score: number
  level: string
  confidence: number
}

interface Indicator {
  type: string
  value: string
  description: string
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
  detectedIndicators: Indicator[]
}

const QUICK_PATTERNS = {
  URL: [
    /https?:\/\/[^\s]+/gi,
    /www\.[^\s]+\.[^\s]+/gi,
  ],
  PHONE: [
    /\+?[1-9]\d{9,14}/g,
    /\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
  ],
  EMAIL: [
    /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi,
  ],
  KEYWORD: [
    /\b(urgent|immediate|verify|confirm|account|locked|suspended)\b/gi,
    /\b(password|login|credential|security|bank)\b/gi,
    /\b(click|link|update|action|required)\b/gi,
  ],
}

const SCAM_KEYWORDS = new Set([
  "urgent",
  "immediate action",
  "account suspended",
  "verify your identity",
  "confirm your account",
  "unauthorized access",
  "security alert",
  "click here",
  "limited time",
  "act now",
  "immediate payment",
  "gift card",
  "bitcoin",
  "wire transfer",
  "bank transfer",
])

const SUSPICIOUS_URL_TLDS = new Set([
  ".xyz",
  ".top",
  ".club",
  ".win",
  ".online",
  ".icu",
])

function generateId(): string {
  return `det_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`
}

function scoreToAction(score: number): string {
  if (score <= THREAT_SCORE_ALLOW) return "ALLOW"
  if (score <= THREAT_SCORE_WARN) return "WARN"
  if (score <= THREAT_SCORE_QUARANTINE) return "QUARANTINE"
  return "BLOCK"
}

function scoreToNotificationLevel(score: number): string {
  if (score <= THREAT_SCORE_ALLOW) return "NONE"
  if (score <= THREAT_SCORE_WARN) return "SOFT"
  if (score <= THREAT_SCORE_QUARANTINE) return "ALERT"
  return "FULL"
}

function scoreToThreatLevel(score: number): string {
  if (score <= THREAT_SCORE_ALLOW) return "SAFE"
  if (score <= THREAT_SCORE_WARN) return "SUSPICIOUS"
  if (score <= THREAT_SCORE_QUARANTINE) return "PHISHING"
  return "SCAM"
}

function quickScan(content: string): { indicators: Indicator[]; score: number } {
  const indicators: Indicator[] = []
  let score = 0
  const contentLower = content.toLowerCase()

  for (const pattern of QUICK_PATTERNS.URL) {
    const matches = content.match(pattern) || []
    for (const match of matches) {
      if (isSuspiciousUrl(match)) {
        indicators.push({
          type: "URL",
          value: match,
          description: "Suspicious URL detected",
        })
        score += 0.3
      }
    }
  }

  for (const pattern of QUICK_PATTERNS.PHONE) {
    const matches = content.match(pattern) || []
    for (const match of matches) {
      if (match.startsWith("1-900") || match.startsWith("0900")) {
        indicators.push({
          type: "PHONE",
          value: match,
          description: "Premium rate number",
        })
        score += 0.25
      }
    }
  }

  for (const keyword of SCAM_KEYWORDS) {
    if (contentLower.includes(keyword)) {
      indicators.push({
        type: "KEYWORD",
        value: keyword,
        description: "Scam-related keyword",
      })
      score += 0.15
    }
  }

  return {
    indicators,
    score: Math.min(score, 1.0),
  }
}

function deepScan(content: string, quickIndicators: Indicator[]): { indicators: Indicator[]; score: number } {
  const indicators: Indicator[] = []
  let score = 0
  const contentLower = content.toLowerCase()

  const brands = ["amazon", "apple", "microsoft", "paypal", "bank"]
  if (brands.some((b) => contentLower.includes(b))) {
    const actionWords = ["verify", "confirm", "update", "account"]
    if (actionWords.some((a) => contentLower.includes(a))) {
      indicators.push({
        type: "PATTERN",
        value: "brand_impersonation",
        description: "Brand impersonation detected",
      })
      score += 0.4
    }
  }

  const urgencyWords = ["urgent", "immediately", "within 24 hours", "act now"]
  if (urgencyWords.some((w) => contentLower.includes(w))) {
    indicators.push({
      type: "PATTERN",
      value: "urgency_tactic",
      description: "Urgency tactic detected",
    })
    score += 0.3
  }

  const rewardWords = ["won", "prize", "lottery", "inheritance", "winner"]
  if (rewardWords.some((w) => contentLower.includes(w))) {
    indicators.push({
      type: "PATTERN",
      value: "reward_scam",
      description: "Reward scam pattern",
    })
    score += 0.35
  }

  const monetaryWords = ["payment", "wire transfer", "gift card", "bitcoin"]
  if (monetaryWords.some((w) => contentLower.includes(w))) {
    indicators.push({
      type: "PATTERN",
      value: "monetary_request",
      description: "Monetary request pattern",
    })
    score += 0.4
  }

  return {
    indicators,
    score: Math.min(score, 1.0),
  }
}

function combineScores(quickScore: number, mlScore: number, deepScore: number): number {
  return 0.2 * quickScore + 0.6 * mlScore + 0.2 * deepScore
}

function generateExplanation(
  finalScore: number,
  threatLevel: string,
  indicators: Indicator[]
): string {
  if (threatLevel === "SAFE") {
    return "This content appears to be safe."
  }

  const indicatorDesc = indicators.length > 0
    ? `Detected: ${indicators.slice(0, 3).map((i) => i.value).join(", ")}`
    : ""

  const recommendation =
    finalScore > 0.85
      ? "Highly likely phishing. Do not interact."
      : finalScore > 0.6
      ? "Suspicious content. Verify through official channels."
      : "Proceed with caution."

  return `${indicatorDesc} ${recommendation}`.trim()
}

function isSuspiciousUrl(url: string): boolean {
  try {
    const urlToCheck = url.startsWith("http") ? url : `http://${url}`
    const parsed = new URL(urlToCheck)

    if (/^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname)) {
      return true
    }

    for (const tld of SUSPICIOUS_URL_TLDS) {
      if (parsed.hostname.endsWith(tld)) {
        return true
      }
    }

    return false
  } catch {
    return false
  }
}

function analyzeContent(content: string): DetectionResult {
  const quickResult = quickScan(content)
  const deepResult = deepScan(content, quickResult.indicators)

  const mlScore = 0.5

  const finalScore = combineScores(
    quickResult.score,
    mlScore,
    deepResult.score
  )

  const action = scoreToAction(finalScore)
  const notificationLevel = scoreToNotificationLevel(finalScore)
  const threatLevel = scoreToThreatLevel(finalScore)

  const allIndicators = [...quickResult.indicators, ...deepResult.indicators]

  const explanation = generateExplanation(finalScore, threatLevel, allIndicators)

  return {
    id: generateId(),
    timestamp: Date.now(),
    source: "BROWSER",
    content,
    threatScore: {
      score: finalScore,
      level: threatLevel,
      confidence: finalScore,
    },
    action,
    notificationLevel,
    explanation,
    detectedIndicators: allIndicators,
  }
}

function showWarningBanner(result: DetectionResult): void {
  const existing = document.getElementById("fraud-agent-banner")
  if (existing) {
    existing.remove()
  }

  const banner = document.createElement("div")
  banner.id = "fraud-agent-banner"
  banner.className = "fraud-agent-banner"

  const colors: Record<string, string> = {
    ALLOW: "#4CAF50",
    WARN: "#FFC107",
    QUARANTINE: "#FF9800",
    BLOCK: "#F44336",
  }

  const color = colors[result.action] || "#FF9800"

  banner.innerHTML = `
    <div class="fraud-agent-banner-content">
      <div class="fraud-agent-banner-icon">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="${color}">
          <path d="M12 2L1 21h22L12 2zm0 3.99L19.53 19H4.47L12 5.99zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z"/>
        </svg>
      </div>
      <div class="fraud-agent-banner-text">
        <div class="fraud-agent-banner-title">${result.threatScore.level}</div>
        <div class="fraud-agent-banner-message">${result.explanation}</div>
      </div>
      <button class="fraud-agent-banner-close" onclick="this.parentElement.parentElement.remove()">×</button>
    </div>
  `

  document.body.appendChild(banner)

  const style = document.createElement("style")
  style.textContent = `
    .fraud-agent-banner {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 999999;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      border-bottom: 3px solid ${color};
      box-shadow: 0 4px 20px rgba(0,0,0,0.3);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .fraud-agent-banner-content {
      display: flex;
      align-items: center;
      padding: 12px 20px;
      max-width: 1200px;
      margin: 0 auto;
    }
    .fraud-agent-banner-icon {
      margin-right: 12px;
    }
    .fraud-agent-banner-text {
      flex: 1;
    }
    .fraud-agent-banner-title {
      color: ${color};
      font-weight: 600;
      font-size: 14px;
    }
    .fraud-agent-banner-message {
      color: #e0e0e0;
      font-size: 13px;
    }
    .fraud-agent-banner-close {
      background: none;
      border: none;
      color: #999;
      font-size: 24px;
      cursor: pointer;
      padding: 0 8px;
    }
    .fraud-agent-banner-close:hover {
      color: #fff;
    }
  `
  document.head.appendChild(style)
}

function processPage(): void {
  const textElements = document.querySelectorAll("p, li, td, th, span, a, div")

  let pageContent = ""
  textElements.forEach((el) => {
    if (el.textContent && el.textContent.length > 20 && el.textContent.length < 500) {
      pageContent += el.textContent + " "
    }
  })

  if (pageContent.length < 50) return

  const result = analyzeContent(pageContent)

  if (result.action !== "ALLOW") {
    showWarningBanner(result)

    chrome.runtime.sendMessage({
      type: "DETECTION_RESULT",
      payload: result,
    })
  }
}

if (document.readyState === "complete") {
  setTimeout(processPage, 1000)
} else {
  window.addEventListener("load", () => setTimeout(processPage, 1000))
}