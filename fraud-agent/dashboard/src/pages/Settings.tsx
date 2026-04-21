import { useState } from "react"

export default function Settings() {
  const [apiUrl, setApiUrl] = useState(
    import.meta.env.VITE_API_URL || "http://localhost:8000"
  )
  const [quickScan, setQuickScan] = useState(true)
  const [deepScan, setDeepScan] = useState(true)
  const [communityReporting, setCommunityReporting] = useState(true)

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-gray-900">Settings</h2>

      <div className="space-y-6">
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">API Configuration</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Backend API URL
              </label>
              <input
                type="text"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                className="input"
              />
              <p className="text-xs text-gray-500 mt-1">
                The backend API endpoint for detection services
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Pipeline Configuration</h3>
          <div className="space-y-4">
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={quickScan}
                onChange={(e) => setQuickScan(e.target.checked)}
                className="mr-3 h-4 w-4 text-primary-600"
              />
              <div>
                <span className="font-medium">Quick Scan</span>
                <p className="text-sm text-gray-500">
                  Fast heuristic scanning for suspicious indicators
                </p>
              </div>
            </label>

            <label className="flex items-center">
              <input
                type="checkbox"
                checked={deepScan}
                onChange={(e) => setDeepScan(e.target.checked)}
                className="mr-3 h-4 w-4 text-primary-600"
              />
              <div>
                <span className="font-medium">Deep Scan</span>
                <p className="text-sm text-gray-500">
                  ML-powered pattern analysis
                </p>
              </div>
            </label>

            <label className="flex items-center">
              <input
                type="checkbox"
                checked={communityReporting}
                onChange={(e) => setCommunityReporting(e.target.checked)}
                className="mr-3 h-4 w-4 text-primary-600"
              />
              <div>
                <span className="font-medium">Community Reporting</span>
                <p className="text-sm text-gray-500">
                  Share threat indicators (SHA-256 hashed only)
                </p>
              </div>
            </label>
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Privacy</h3>
          <p className="text-gray-600">
            All detection processing follows strict privacy principles:
          </p>
          <ul className="mt-2 space-y-2 text-gray-600">
            <li className="flex items-center">
              <span className="text-green-500 mr-2">✓</span>
              Raw content never leaves the device
            </li>
            <li className="flex items-center">
              <span className="text-green-500 mr-2">✓</span>
              Only SHA-256 hashed indicators shared
            </li>
            <li className="flex items-center">
              <span className="text-green-500 mr-2">✓</span>
              Local ML inference (no cloud API calls)
            </li>
            <li className="flex items-center">
              <span className="text-green-500 mr-2">✓</span>
              Encrypted local storage
            </li>
          </ul>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold mb-4">About</h3>
          <div className="space-y-2 text-gray-600">
            <p>
              <strong>Fraud Agent</strong> v0.1.0
            </p>
            <p>A privacy-first fraud detection system</p>
            <p className="text-sm">
              Built with Kotlin, Jetpack Compose, TensorFlow Lite, FastAPI,
              React, and more.
            </p>
          </div>
        </div>

        <button className="btn btn-primary">Save Settings</button>
      </div>
    </div>
  )
}