import axios from "axios"

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:8000",
  timeout: 10000,
})

export const api = {
  async getDetections(limit = 100, offset = 0) {
    const response = await client.get(`/api/v1/detections`, {
      params: { limit, offset },
    })
    return response.data
  },

  async getDetection(id: string) {
    const response = await client.get(`/api/v1/detections/${id}`)
    return response.data
  },

  async analyzeContent(content: string, source: string) {
    const response = await client.post(`/api/v1/detect`, {
      content,
      source,
    })
    return response.data
  },

  async getStats() {
    const response = await client.get(`/api/v1/stats`)
    return response.data
  },

  async getReports(limit = 100) {
    const response = await client.get(`/api/v1/reports`, {
      params: { limit },
    })
    return response.data
  },

  async createReport(
    indicatorHash: string,
    threatScore: number,
    indicatorType: string,
    source: string
  ) {
    const response = await client.post(`/api/v1/reports`, {
      indicator_hash: indicatorHash,
      threat_score: threatScore,
      indicator_type: indicatorType,
      source,
    })
    return response.data
  },
}