// =============================================================================
// FootprintHub — Dashboard Page (Reconnaissance Results & Visual Analytics)
// =============================================================================

import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Globe,
  Shield,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  AlertTriangle,
  Info,
  Download,
  Share2,
  Server,
  Lock,
  FileText,
  Cloud,
  Network,
  Search,
  ExternalLink,
  ChevronRight,
  Copy,
  Check,
  Radio,
  Layers,
  ArrowLeft,
} from 'lucide-react'
import {
  scansApi,
  ScanResponse,
  ModuleResultResponse,
  FindingResponse,
} from '../api/client'

// Module metadata & display configuration
const MODULE_META: Record<string, { label: string; icon: string }> = {
  dns: { label: 'DNS & WHOIS', icon: '🌐' },
  subdomains: { label: 'Subdomains', icon: '🔍' },
  ip_network: { label: 'IP & Network', icon: '📡' },
  web_tech: { label: 'Web Tech', icon: '⚙️' },
  ssl_tls: { label: 'SSL/TLS', icon: '🔒' },
  content: { label: 'Content', icon: '📄' },
  ports: { label: 'Ports', icon: '🚪' },
  osint: { label: 'OSINT', icon: '🕵️' },
  cloud: { label: 'Cloud', icon: '☁️' },
  reputation: { label: 'Reputation', icon: '⭐' },
}

const SEVERITY_CONFIG: Record<string, { color: string; badge: string; icon: any; label: string }> = {
  critical: {
    color: 'border-red-500/40 bg-red-950/20 text-red-400',
    badge: 'bg-red-500/20 text-red-400 border border-red-500/30',
    icon: XCircle,
    label: 'Critical',
  },
  high: {
    color: 'border-orange-500/40 bg-orange-950/20 text-orange-400',
    badge: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
    icon: AlertTriangle,
    label: 'High',
  },
  medium: {
    color: 'border-amber-500/40 bg-amber-950/20 text-amber-400',
    badge: 'bg-amber-500/20 text-amber-400 border border-amber-500/30',
    icon: AlertTriangle,
    label: 'Medium',
  },
  low: {
    color: 'border-blue-500/40 bg-blue-950/20 text-blue-400',
    badge: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
    icon: Info,
    label: 'Low',
  },
  info: {
    color: 'border-surface-700 bg-surface-900/40 text-surface-300',
    badge: 'bg-surface-800 text-surface-300 border border-surface-700',
    icon: Info,
    label: 'Info',
  },
}

export default function DashboardPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const [scan, setScan] = useState<ScanResponse | null>(null)
  const [results, setResults] = useState<ModuleResultResponse[]>([])
  const [findings, setFindings] = useState<FindingResponse[]>([])
  const [activeTab, setActiveTab] = useState('overview')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [subdomainSearch, setSubdomainSearch] = useState('')
  const [copiedText, setCopiedText] = useState<string | null>(null)

  useEffect(() => {
    if (!scanId) return
    loadData()

    // Poll every 2s while the scan is still running; stop once completed/failed
    const interval = setInterval(() => {
      loadData(false)
    }, 2000)

    return () => clearInterval(interval)
  }, [scanId])

  // Stop polling once scan is completed or failed
  useEffect(() => {
    if (!scan) return
    if (scan.status === 'completed' || scan.status === 'failed') {
      // Do one final data fetch to ensure we have everything
      loadData(false)
    }
  }, [scan?.status])

  const loadData = async (showLoading = true) => {
    if (showLoading && !scan) setLoading(true)
    try {
      const [scanData, resultsData, findingsData] = await Promise.all([
        scansApi.get(scanId!),
        scansApi.getResults(scanId!),
        scansApi.getFindings(scanId!),
      ])
      setScan(scanData)
      setResults(resultsData)
      setFindings(findingsData)
    } catch {
      setError('Failed to load scan data')
    } finally {
      if (showLoading) setLoading(false)
    }
  }

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedText(text)
    setTimeout(() => setCopiedText(null), 2000)
  }

  if (loading && !scan) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center animate-fade-in">
          <Loader2 className="h-10 w-10 text-brand-500 animate-spin mx-auto mb-4" />
          <p className="text-surface-400">Loading reconnaissance intelligence...</p>
        </div>
      </div>
    )
  }

  if (error || !scan) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center animate-fade-in">
          <XCircle className="h-10 w-10 text-red-500 mx-auto mb-4" />
          <p className="text-surface-300">{error || 'Scan not found'}</p>
          <Link to="/" className="inline-flex items-center gap-2 mt-4 text-brand-400 hover:text-brand-300">
            <ArrowLeft className="h-4 w-4" /> Return to Scanner
          </Link>
        </div>
      </div>
    )
  }

  const completedModules = results.filter((r) => ['success', 'error', 'partial'].includes(r.status)).length
  const totalModules = results.length
  const progressPercent = totalModules > 0 ? Math.round((completedModules / totalModules) * 100) : 0

  const findingCounts = findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1
      return acc
    },
    {} as Record<string, number>
  )

  const resultMap = results.reduce(
    (acc, r) => {
      acc[r.module_name] = r
      return acc
    },
    {} as Record<string, ModuleResultResponse>
  )

  // Risk styling
  const score = scan.risk_score ?? 0
  const riskColor =
    score <= 20
      ? 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10'
      : score <= 50
      ? 'text-amber-400 border-amber-500/40 bg-amber-500/10'
      : score <= 75
      ? 'text-orange-400 border-orange-500/40 bg-orange-500/10'
      : 'text-rose-500 border-rose-500/40 bg-rose-500/10'

  const grade = score <= 10 ? 'A' : score <= 20 ? 'B' : score <= 50 ? 'C' : score <= 75 ? 'D' : 'F'

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 animate-fade-in space-y-6">
      {/* Top Banner & Header */}
      <div className="glass-card p-6 border border-surface-800 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-brand-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <span className="p-2.5 rounded-xl bg-brand-500/15 border border-brand-500/30 text-brand-400">
                <Globe className="h-6 w-6" />
              </span>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
                  {scan.domain}
                  <span className="text-xs px-2.5 py-0.5 rounded-full font-mono font-medium uppercase bg-surface-800 text-surface-300 border border-surface-700">
                    {scan.profile}
                  </span>
                </h1>
                <p className="text-xs text-surface-400 flex items-center gap-2 mt-1">
                  <span>ID: {scan.id.slice(0, 8)}</span>
                  <span>•</span>
                  <span>Started: {new Date(scan.created_at).toLocaleString()}</span>
                  <span>•</span>
                  <span className="capitalize flex items-center gap-1.5">
                    {scan.status === 'completed' && <CheckCircle2 className="h-3.5 w-3.5 text-accent-green" />}
                    {scan.status === 'running' && <Loader2 className="h-3.5 w-3.5 text-brand-400 animate-spin" />}
                    {scan.status}
                  </span>
                </p>
              </div>
            </div>
          </div>

          {/* Quick Actions & Export */}
          <div className="flex items-center gap-3">
            <a
              href={scansApi.getExportUrl(scan.id, 'pdf')}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-surface-800 hover:bg-surface-700 text-white border border-surface-700 transition-colors shadow-sm"
            >
              <Download className="h-3.5 w-3.5 text-brand-400" /> PDF Report
            </a>
            <a
              href={scansApi.getExportUrl(scan.id, 'json')}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-surface-800 hover:bg-surface-700 text-white border border-surface-700 transition-colors shadow-sm"
            >
              <Download className="h-3.5 w-3.5 text-accent-green" /> JSON
            </a>
            <a
              href={scansApi.getExportUrl(scan.id, 'csv')}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-surface-800 hover:bg-surface-700 text-white border border-surface-700 transition-colors shadow-sm"
            >
              <Download className="h-3.5 w-3.5 text-amber-400" /> CSV
            </a>
          </div>
        </div>

        {/* Progress Bar (if still executing) */}
        {scan.status === 'running' && (
          <div className="mt-6 pt-4 border-t border-surface-800/80">
            <div className="flex items-center justify-between text-xs text-surface-400 mb-1.5">
              <span className="flex items-center gap-2">
                <Loader2 className="h-3 w-3 text-brand-400 animate-spin" />
                Scanning in progress ({completedModules} of {totalModules} modules finished)
              </span>
              <span className="font-mono">{progressPercent}%</span>
            </div>
            <div className="w-full bg-surface-900 rounded-full h-2 overflow-hidden border border-surface-800">
              <div
                className="bg-brand-500 h-full rounded-full transition-all duration-500"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-2 border-b border-surface-800 scrollbar-none">
        <button
          onClick={() => setActiveTab('overview')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${
            activeTab === 'overview'
              ? 'bg-brand-600/20 text-brand-400 border border-brand-500/30'
              : 'text-surface-400 hover:text-surface-200 hover:bg-surface-900'
          }`}
        >
          <Layers className="h-4 w-4" /> Overview & Risk
        </button>

        <button
          onClick={() => setActiveTab('topology')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${
            activeTab === 'topology'
              ? 'bg-brand-600/20 text-brand-400 border border-brand-500/30'
              : 'text-surface-400 hover:text-surface-200 hover:bg-surface-900'
          }`}
        >
          <Network className="h-4 w-4" /> Topology Graph
        </button>

        {results.map((r) => {
          const meta = MODULE_META[r.module_name] || { label: r.module_name, icon: '📦' }
          const isActive = activeTab === r.module_name
          return (
            <button
              key={r.module_name}
              onClick={() => setActiveTab(r.module_name)}
              className={`flex items-center gap-2 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${
                isActive
                  ? 'bg-brand-600/20 text-brand-400 border border-brand-500/30'
                  : 'text-surface-400 hover:text-surface-200 hover:bg-surface-900'
              }`}
            >
              <span>{meta.icon}</span>
              <span>{meta.label}</span>
              {r.status === 'running' && <Loader2 className="h-3 w-3 animate-spin text-brand-400" />}
              {r.status === 'error' && <span className="h-1.5 w-1.5 rounded-full bg-red-400" />}
            </button>
          )
        })}
      </div>

      {/* Main Tab Content */}
      {activeTab === 'overview' && (
        <OverviewTab
          scan={scan}
          results={results}
          findings={findings}
          findingCounts={findingCounts}
          score={score}
          grade={grade}
          riskColor={riskColor}
          setActiveTab={setActiveTab}
        />
      )}

      {activeTab === 'topology' && <TopologyTab scanId={scan.id} targetDomain={scan.domain} />}

      {results.map((r) => {
        if (activeTab === r.module_name) {
          const modFindings = findings.filter((f) => f.module_name === r.module_name)
          return (
            <ModuleDetailTab
              key={r.module_name}
              result={r}
              findings={modFindings}
              subdomainSearch={subdomainSearch}
              setSubdomainSearch={setSubdomainSearch}
              handleCopy={handleCopy}
              copiedText={copiedText}
            />
          )
        }
        return null
      })}
    </div>
  )
}

// ── Overview Tab Component ──────────────────────────────────────────────────

function OverviewTab({
  scan,
  results,
  findings,
  findingCounts,
  score,
  grade,
  riskColor,
  setActiveTab,
}: {
  scan: ScanResponse
  results: ModuleResultResponse[]
  findings: FindingResponse[]
  findingCounts: Record<string, number>
  score: number
  grade: string
  riskColor: string
  setActiveTab: (tab: string) => void
}) {
  return (
    <div className="space-y-6">
      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Risk Score Gauge */}
        <div className="glass-card p-5 border border-surface-800 flex items-center justify-between">
          <div>
            <p className="text-xs text-surface-400 font-medium">Risk Exposure Score</p>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-3xl font-extrabold font-mono text-white">{score}</span>
              <span className="text-xs text-surface-500">/ 100</span>
            </div>
            <p className="text-xs text-surface-400 mt-1 capitalize">
              Posture: <span className="font-semibold text-white">{score <= 20 ? 'Low' : score <= 50 ? 'Medium' : score <= 75 ? 'High' : 'Critical'}</span>
            </p>
          </div>
          <div className={`h-16 w-16 rounded-2xl border flex flex-col items-center justify-center font-bold font-mono text-2xl shadow-lg ${riskColor}`}>
            {grade}
          </div>
        </div>

        {/* High/Critical Vulnerabilities */}
        <div className="glass-card p-5 border border-surface-800">
          <p className="text-xs text-surface-400 font-medium">Critical & High Findings</p>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-3xl font-extrabold font-mono text-red-400">
              {(findingCounts['critical'] || 0) + (findingCounts['high'] || 0)}
            </span>
            <span className="text-xs text-surface-500">issues</span>
          </div>
          <p className="text-xs text-surface-400 mt-1">
            Requires immediate defensive remediation
          </p>
        </div>

        {/* Total Active Findings */}
        <div className="glass-card p-5 border border-surface-800">
          <p className="text-xs text-surface-400 font-medium">Total Security Findings</p>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-3xl font-extrabold font-mono text-brand-400">{findings.length}</span>
            <span className="text-xs text-surface-500">findings</span>
          </div>
          <p className="text-xs text-surface-400 mt-1">Aggregated across all 10 recon modules</p>
        </div>

        {/* Recon Coverage */}
        <div className="glass-card p-5 border border-surface-800">
          <p className="text-xs text-surface-400 font-medium">Module Execution</p>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-3xl font-extrabold font-mono text-accent-green">
              {results.filter((r) => r.status === 'success').length}
            </span>
            <span className="text-xs text-surface-500">/ {results.length} active</span>
          </div>
          <p className="text-xs text-surface-400 mt-1">
            {scan.status === 'completed' ? 'All modules completed successfully' : 'Recon execution in progress...'}
          </p>
        </div>
      </div>

      {/* Findings Breakdown & Modules Sidebar */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Findings List (2 cols) */}
        <div className="lg:col-span-2 glass-card p-6 border border-surface-800">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Shield className="h-5 w-5 text-brand-400" />
              Prioritized Security Findings ({findings.length})
            </h2>
          </div>

          {findings.length === 0 ? (
            <div className="text-center py-12 text-surface-500">
              <CheckCircle2 className="h-10 w-10 text-emerald-400/60 mx-auto mb-2" />
              <p>No security findings discovered yet for this target.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {findings.map((f) => {
                const conf = SEVERITY_CONFIG[f.severity] || SEVERITY_CONFIG.info
                const Icon = conf.icon
                return (
                  <div
                    key={f.id}
                    className={`p-4 rounded-xl border transition-all ${conf.color} hover:bg-surface-900/60`}
                  >
                    <div className="flex items-start gap-3">
                      <Icon className="h-5 w-5 flex-shrink-0 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-2 mb-1">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${conf.badge}`}>
                            {f.severity}
                          </span>
                          <span className="text-xs px-2 py-0.5 rounded-md bg-surface-800 text-surface-300 font-mono">
                            {f.module_name}
                          </span>
                          <h4 className="text-sm font-semibold text-white">{f.title}</h4>
                        </div>
                        <p className="text-xs text-surface-300 leading-relaxed">{f.description}</p>
                        {f.remediation && (
                          <div className="mt-2 text-xs bg-surface-950/70 p-2.5 rounded-lg border border-surface-800 text-surface-300">
                            <span className="font-semibold text-brand-300">💡 Remediation:</span> {f.remediation}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Sidebar Status (1 col) */}
        <div className="space-y-6">
          {/* Severity Distribution */}
          <div className="glass-card p-6 border border-surface-800">
            <h3 className="text-sm font-semibold text-white mb-4">Severity Distribution</h3>
            <div className="space-y-2.5">
              {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
                const conf = SEVERITY_CONFIG[sev]
                const count = findingCounts[sev] || 0
                const percent = findings.length > 0 ? Math.round((count / findings.length) * 100) : 0
                return (
                  <div key={sev} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="capitalize text-surface-300 font-medium">{conf.label}</span>
                      <span className="font-mono text-surface-400">{count} ({percent}%)</span>
                    </div>
                    <div className="w-full bg-surface-900 rounded-full h-1.5 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          sev === 'critical'
                            ? 'bg-red-500'
                            : sev === 'high'
                            ? 'bg-orange-500'
                            : sev === 'medium'
                            ? 'bg-amber-500'
                            : sev === 'low'
                            ? 'bg-blue-500'
                            : 'bg-surface-600'
                        }`}
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Module Jump Navigation */}
          <div className="glass-card p-6 border border-surface-800">
            <h3 className="text-sm font-semibold text-white mb-4">Recon Modules Status</h3>
            <div className="space-y-2">
              {results.map((r) => {
                const meta = MODULE_META[r.module_name] || { label: r.module_name, icon: '📦' }
                return (
                  <button
                    key={r.module_name}
                    onClick={() => setActiveTab(r.module_name)}
                    className="w-full flex items-center justify-between p-2.5 rounded-lg hover:bg-surface-800/80 transition-colors text-left"
                  >
                    <span className="text-xs text-surface-300 flex items-center gap-2">
                      <span>{meta.icon}</span>
                      <span className="font-medium text-white">{meta.label}</span>
                    </span>
                    <span className="flex items-center gap-1.5 text-xs text-surface-400">
                      {r.status === 'success' && <CheckCircle2 className="h-4 w-4 text-accent-green" />}
                      {r.status === 'running' && <Loader2 className="h-4 w-4 text-brand-400 animate-spin" />}
                      {r.status === 'error' && <XCircle className="h-4 w-4 text-red-400" />}
                      <ChevronRight className="h-3.5 w-3.5 text-surface-600" />
                    </span>
                  </button>
                )
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Topology Tab ────────────────────────────────────────────────────────────

function TopologyTab({ scanId, targetDomain }: { scanId: string; targetDomain: string }) {
  const [graphData, setGraphData] = useState<{ nodes: any[]; edges: any[] } | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    scansApi.getGraph(scanId)
      .then((data) => setGraphData(data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [scanId])

  if (loading) {
    return (
      <div className="glass-card p-12 text-center text-surface-400">
        <Loader2 className="h-8 w-8 animate-spin text-brand-500 mx-auto mb-2" />
        <p>Constructing infrastructure relationship graph...</p>
      </div>
    )
  }

  const nodes = graphData?.nodes || []

  return (
    <div className="glass-card p-6 border border-surface-800 space-y-6">
      <div className="flex items-center justify-between border-b border-surface-800 pb-4">
        <div>
          <h2 className="text-base font-semibold text-white">Target Infrastructure Topology</h2>
          <p className="text-xs text-surface-400 mt-1">
            Visual map linking root domain, resolved IP nodes, active subdomains, technologies, and cloud assets.
          </p>
        </div>
        <span className="text-xs px-3 py-1 rounded-full bg-brand-500/15 border border-brand-500/30 text-brand-400 font-mono">
          {nodes.length} Connected Nodes
        </span>
      </div>

      {/* Topology Nodes Grid View */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {nodes.map((node) => (
          <div
            key={node.id}
            className={`p-4 rounded-xl border transition-all ${
              node.type === 'target'
                ? 'bg-brand-950/30 border-brand-500/50 shadow-lg shadow-brand-500/10'
                : node.type === 'ip'
                ? 'bg-emerald-950/20 border-emerald-500/30'
                : node.type === 'subdomain'
                ? 'bg-blue-950/20 border-blue-500/30'
                : node.type === 'tech'
                ? 'bg-purple-950/20 border-purple-500/30'
                : 'bg-amber-950/20 border-amber-500/30'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-mono uppercase tracking-wider font-bold text-surface-400">
                {node.type}
              </span>
              <span className="h-2 w-2 rounded-full bg-brand-400 animate-pulse" />
            </div>
            <p className="text-sm font-semibold text-white truncate" title={node.data.label}>
              {node.data.label}
            </p>
            {node.data.isp && <p className="text-xs text-surface-400 mt-1 truncate">{node.data.isp}</p>}
            {node.data.provider && <p className="text-xs text-surface-400 mt-1 truncate">{node.data.provider}</p>}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Module Detail Tab Component ─────────────────────────────────────────────

function ModuleDetailTab({
  result,
  findings,
  subdomainSearch,
  setSubdomainSearch,
  handleCopy,
  copiedText,
}: {
  result: ModuleResultResponse
  findings: FindingResponse[]
  subdomainSearch: string
  setSubdomainSearch: (val: string) => void
  handleCopy: (val: string) => void
  copiedText: string | null
}) {
  const meta = MODULE_META[result.module_name] || { label: result.module_name, icon: '📦' }
  const data = result.data || {}

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Module Header Card */}
      <div className="glass-card p-6 border border-surface-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <span>{meta.icon}</span> {meta.label}
          </h2>
          <p className="text-xs text-surface-400 mt-1">
            Mode: <span className="uppercase text-surface-300 font-mono">{result.mode}</span> •
            Execution Duration: <span className="text-surface-300 font-mono">{result.duration_seconds?.toFixed(2) || '0.00'}s</span>
          </p>
        </div>
        <span
          className={`px-3 py-1 rounded-full text-xs font-semibold uppercase tracking-wider ${
            result.status === 'success'
              ? 'bg-accent-green/20 text-accent-green border border-accent-green/30'
              : result.status === 'error'
              ? 'bg-red-500/20 text-red-400 border border-red-500/30'
              : 'bg-brand-500/20 text-brand-400 border border-brand-500/30'
          }`}
        >
          {result.status}
        </span>
      </div>

      {/* Module Findings If Present */}
      {findings.length > 0 && (
        <div className="glass-card p-6 border border-surface-800 space-y-3">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-amber-400" />
            Module Findings ({findings.length})
          </h3>
          <div className="space-y-2.5">
            {findings.map((f) => {
              const conf = SEVERITY_CONFIG[f.severity] || SEVERITY_CONFIG.info
              return (
                <div key={f.id} className={`p-3.5 rounded-xl border ${conf.color}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${conf.badge}`}>
                      {f.severity}
                    </span>
                    <span className="text-sm font-semibold text-white">{f.title}</span>
                  </div>
                  <p className="text-xs text-surface-300 mt-1">{f.description}</p>
                  {f.remediation && (
                    <p className="text-xs text-surface-400 mt-2 font-mono">💡 {f.remediation}</p>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Specialized Rendering Based on Module Name */}
      {result.module_name === 'dns' && <DNSResultView data={data} handleCopy={handleCopy} copiedText={copiedText} />}
      {result.module_name === 'subdomains' && (
        <SubdomainsResultView
          data={data}
          subdomainSearch={subdomainSearch}
          setSubdomainSearch={setSubdomainSearch}
          handleCopy={handleCopy}
          copiedText={copiedText}
        />
      )}
      {result.module_name === 'ip_network' && <IPNetworkResultView data={data} />}
      {result.module_name === 'web_tech' && <WebTechResultView data={data} />}
      {result.module_name === 'ssl_tls' && <SSLResultView data={data} />}
      {result.module_name === 'content' && <ContentResultView data={data} />}
      {result.module_name === 'ports' && <PortsResultView data={data} />}
      {result.module_name === 'osint' && <OSINTResultView data={data} />}
      {result.module_name === 'cloud' && <CloudResultView data={data} />}
      {result.module_name === 'reputation' && <ReputationResultView data={data} />}

      {/* Raw JSON Inspector Accordion */}
      <details className="glass-card p-4 border border-surface-800 rounded-xl">
        <summary className="text-xs font-mono text-surface-400 cursor-pointer hover:text-surface-200">
          ▶ Inspect Raw JSON Output
        </summary>
        <div className="mt-3 bg-surface-950 p-4 rounded-lg overflow-x-auto border border-surface-800">
          <pre className="text-xs text-surface-300 font-mono whitespace-pre-wrap">
            {JSON.stringify(data, null, 2)}
          </pre>
        </div>
      </details>
    </div>
  )
}

// ── Specialized Module Views ────────────────────────────────────────────────

function DNSResultView({ data, handleCopy, copiedText }: { data: any; handleCopy: any; copiedText: any }) {
  const records = data.records || {}
  const whois = data.whois || {}
  const emailSec = data.email_security || {}
  const dnssec = data.dnssec || {}

  return (
    <div className="space-y-6">
      {/* Security Records Status Card */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* DNSSEC */}
        <div className="glass-card p-4 border border-surface-800">
          <p className="text-xs text-surface-400">DNSSEC Status</p>
          <div className="flex items-center gap-2 mt-2">
            {dnssec.enabled ? (
              <CheckCircle2 className="h-5 w-5 text-accent-green" />
            ) : (
              <XCircle className="h-5 w-5 text-red-400" />
            )}
            <span className="text-sm font-bold text-white capitalize">{dnssec.status || 'Unsigned'}</span>
          </div>
        </div>

        {/* SPF */}
        <div className="glass-card p-4 border border-surface-800">
          <p className="text-xs text-surface-400">SPF Email Authentication</p>
          <div className="flex items-center gap-2 mt-2">
            {emailSec.spf?.present ? (
              <CheckCircle2 className="h-5 w-5 text-accent-green" />
            ) : (
              <XCircle className="h-5 w-5 text-red-400" />
            )}
            <span className="text-sm font-bold text-white truncate">
              {emailSec.spf?.policy || (emailSec.spf?.present ? 'Present' : 'Missing')}
            </span>
          </div>
        </div>

        {/* DMARC */}
        <div className="glass-card p-4 border border-surface-800">
          <p className="text-xs text-surface-400">DMARC Policy</p>
          <div className="flex items-center gap-2 mt-2">
            {emailSec.dmarc?.present ? (
              <CheckCircle2 className="h-5 w-5 text-accent-green" />
            ) : (
              <XCircle className="h-5 w-5 text-red-400" />
            )}
            <span className="text-sm font-bold text-white uppercase">
              {emailSec.dmarc?.policy ? `p=${emailSec.dmarc.policy}` : 'Missing'}
            </span>
          </div>
        </div>
      </div>

      {/* DNS Records Grid */}
      <div className="glass-card p-6 border border-surface-800 space-y-4">
        <h3 className="text-sm font-semibold text-white">DNS Zone Records</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {Object.entries(records).map(([rtype, rvalues]: [string, any]) => {
            if (!Array.isArray(rvalues) || rvalues.length === 0) return null
            return (
              <div key={rtype} className="p-4 rounded-xl bg-surface-900/60 border border-surface-800">
                <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-brand-500/20 text-brand-300 border border-brand-500/30">
                  {rtype}
                </span>
                <div className="mt-2.5 space-y-1.5 max-h-40 overflow-y-auto">
                  {rvalues.map((v: any, idx: number) => {
                    const textVal = typeof v === 'object' ? JSON.stringify(v) : String(v)
                    return (
                      <div
                        key={idx}
                        className="flex items-center justify-between text-xs font-mono text-surface-200 bg-surface-950 p-2 rounded border border-surface-800/80 group"
                      >
                        <span className="truncate mr-2">{textVal}</span>
                        <button
                          onClick={() => handleCopy(textVal)}
                          className="text-surface-500 hover:text-white"
                          title="Copy record"
                        >
                          {copiedText === textVal ? <Check className="h-3.5 w-3.5 text-accent-green" /> : <Copy className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* WHOIS Card */}
      {whois.registrar && (
        <div className="glass-card p-6 border border-surface-800 space-y-3">
          <h3 className="text-sm font-semibold text-white">WHOIS Domain Registration</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div className="p-3 rounded-lg bg-surface-900/60 border border-surface-800">
              <span className="text-surface-400 block mb-1">Registrar</span>
              <span className="font-semibold text-white">{whois.registrar}</span>
            </div>
            <div className="p-3 rounded-lg bg-surface-900/60 border border-surface-800">
              <span className="text-surface-400 block mb-1">Created Date</span>
              <span className="font-semibold text-white">{whois.creation_date || 'N/A'}</span>
            </div>
            <div className="p-3 rounded-lg bg-surface-900/60 border border-surface-800">
              <span className="text-surface-400 block mb-1">Expiration Date</span>
              <span className="font-semibold text-white">{whois.expiration_date || 'N/A'}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function SubdomainsResultView({
  data,
  subdomainSearch,
  setSubdomainSearch,
  handleCopy,
  copiedText,
}: {
  data: any
  subdomainSearch: string
  setSubdomainSearch: (val: string) => void
  handleCopy: (val: string) => void
  copiedText: string | null
}) {
  const subdomains = (data.subdomains || []) as any[]
  const filtered = subdomains.filter((s) =>
    s.subdomain?.toLowerCase().includes(subdomainSearch.toLowerCase())
  )

  return (
    <div className="glass-card p-6 border border-surface-800 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-white">
            Active Subdomains ({filtered.length} of {subdomains.length})
          </h3>
          <p className="text-xs text-surface-400 mt-0.5">
            Discovered through Certificate Transparency (CT) logs and active DNS resolution.
          </p>
        </div>
        <div className="relative">
          <Search className="h-4 w-4 absolute left-3 top-2.5 text-surface-500" />
          <input
            type="text"
            placeholder="Filter subdomains..."
            value={subdomainSearch}
            onChange={(e) => setSubdomainSearch(e.target.value)}
            className="pl-9 pr-4 py-1.5 rounded-lg text-xs bg-surface-900 border border-surface-700 text-white placeholder-surface-500 focus:outline-none focus:border-brand-500"
          />
        </div>
      </div>

      <div className="divide-y divide-surface-800/80 border border-surface-800 rounded-xl overflow-hidden">
        {filtered.map((item, idx) => (
          <div key={idx} className="p-3.5 bg-surface-950/60 hover:bg-surface-900/80 transition-colors flex items-center justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-medium text-white truncate">{item.subdomain}</span>
                {item.is_root && (
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-brand-500/20 text-brand-400 font-mono">
                    root
                  </span>
                )}
              </div>
              {item.cnames?.length > 0 && (
                <p className="text-[11px] font-mono text-surface-400 mt-1 truncate">
                  ↳ CNAME: {item.cnames.join(', ')}
                </p>
              )}
            </div>

            <div className="flex items-center gap-2 flex-shrink-0">
              {item.ips?.map((ip: string) => (
                <span key={ip} className="text-[11px] font-mono px-2 py-0.5 rounded bg-surface-800 text-surface-300">
                  {ip}
                </span>
              ))}
              <button
                onClick={() => handleCopy(item.subdomain)}
                className="p-1 rounded text-surface-500 hover:text-white"
                title="Copy Subdomain"
              >
                {copiedText === item.subdomain ? (
                  <Check className="h-3.5 w-3.5 text-accent-green" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function IPNetworkResultView({ data }: { data: any }) {
  const networks = data.networks || []
  const cdns = data.detected_cdns || []

  return (
    <div className="space-y-6">
      {cdns.length > 0 && (
        <div className="p-4 rounded-xl bg-brand-950/20 border border-brand-500/30 flex items-center gap-3">
          <Shield className="h-5 w-5 text-brand-400 flex-shrink-0" />
          <div className="text-xs">
            <span className="font-semibold text-white">Edge WAF / CDN Protection Active:</span>{' '}
            <span className="text-brand-300">{cdns.join(', ')}</span>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {networks.map((net: any, idx: number) => (
          <div key={idx} className="glass-card p-5 border border-surface-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-base font-bold font-mono text-white">{net.ip}</span>
              <span className="text-xs px-2 py-0.5 rounded bg-surface-800 text-surface-300 font-mono">
                IPv{net.version}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-surface-500 block">Location</span>
                <span className="font-medium text-white">{net.city}, {net.country}</span>
              </div>
              <div>
                <span className="text-surface-500 block">ASN</span>
                <span className="font-mono text-brand-400">{net.as_name || `AS${net.asn}` || 'N/A'}</span>
              </div>
              <div>
                <span className="text-surface-500 block">ISP / Org</span>
                <span className="text-surface-300 truncate block">{net.org || net.isp || 'N/A'}</span>
              </div>
              <div>
                <span className="text-surface-500 block">Reverse DNS (PTR)</span>
                <span className="text-surface-300 font-mono truncate block">{net.ptr || 'None'}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function WebTechResultView({ data }: { data: any }) {
  const techs = data.technologies || []
  const headers = data.security_headers || {}

  return (
    <div className="space-y-6">
      {/* Detected Tech */}
      <div className="glass-card p-6 border border-surface-800 space-y-3">
        <h3 className="text-sm font-semibold text-white">Detected Technologies & Frameworks</h3>
        {techs.length === 0 ? (
          <p className="text-xs text-surface-500">No public tech stack signatures fingerprinted.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {techs.map((t: string) => (
              <span key={t} className="px-3 py-1 rounded-lg text-xs font-semibold bg-brand-500/15 border border-brand-500/30 text-brand-300">
                {t}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Security Headers Checklist */}
      <div className="glass-card p-6 border border-surface-800 space-y-4">
        <h3 className="text-sm font-semibold text-white">HTTP Security Headers Checklist</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {Object.entries(headers).map(([key, val]: [string, any]) => (
            <div
              key={key}
              className={`p-3 rounded-lg border flex items-center justify-between text-xs ${
                val.present
                  ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
                  : 'bg-red-950/20 border-red-500/30 text-red-300'
              }`}
            >
              <div className="flex items-center gap-2">
                {val.present ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
                <span className="font-semibold">{val.name}</span>
              </div>
              <span className="font-mono text-[10px] uppercase font-bold">
                {val.present ? 'Configured' : 'Missing'}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function SSLResultView({ data }: { data: any }) {
  const cert = data.certificate || {}
  const protocols = data.protocols || {}

  return (
    <div className="space-y-6">
      {cert.subject && (
        <div className="glass-card p-6 border border-surface-800 space-y-4">
          <h3 className="text-sm font-semibold text-white">Certificate Information</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div className="p-3 bg-surface-900/60 rounded-lg border border-surface-800">
              <span className="text-surface-500 block">Common Name</span>
              <span className="font-mono font-bold text-white">{cert.subject.commonName || 'N/A'}</span>
            </div>
            <div className="p-3 bg-surface-900/60 rounded-lg border border-surface-800">
              <span className="text-surface-500 block">Issuer</span>
              <span className="font-medium text-white">{cert.issuer.organizationName || cert.issuer.commonName || 'N/A'}</span>
            </div>
            <div className="p-3 bg-surface-900/60 rounded-lg border border-surface-800">
              <span className="text-surface-500 block">Days Remaining</span>
              <span className="font-bold text-emerald-400">{cert.days_until_expiration ?? 'N/A'} days</span>
            </div>
          </div>
        </div>
      )}

      {/* Protocols */}
      <div className="glass-card p-6 border border-surface-800 space-y-3">
        <h3 className="text-sm font-semibold text-white">TLS Protocol Support</h3>
        <div className="flex flex-wrap gap-3">
          {Object.entries(protocols).map(([proto, supported]: [string, any]) => (
            <div
              key={proto}
              className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-2 ${
                supported
                  ? proto.includes('1.0') || proto.includes('1.1')
                    ? 'bg-amber-950/20 border-amber-500/40 text-amber-300'
                    : 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                  : 'bg-surface-900 border-surface-800 text-surface-500 line-through'
              }`}
            >
              <span>{proto}</span>
              <span className="text-[10px] font-bold uppercase">{supported ? 'Supported' : 'Disabled'}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function ContentResultView({ data }: { data: any }) {
  const disallowed = data.disallowed_paths || []
  const comments = data.interesting_comments || []

  return (
    <div className="space-y-6">
      <div className="glass-card p-6 border border-surface-800 space-y-3">
        <h3 className="text-sm font-semibold text-white">Disallowed Robots.txt Paths ({disallowed.length})</h3>
        {disallowed.length === 0 ? (
          <p className="text-xs text-surface-500">No disallowed paths specified in robots.txt.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {disallowed.map((p: string, idx: number) => (
              <span key={idx} className="font-mono text-xs px-2.5 py-1 rounded bg-surface-900 text-surface-300 border border-surface-800">
                {p}
              </span>
            ))}
          </div>
        )}
      </div>

      {comments.length > 0 && (
        <div className="glass-card p-6 border border-surface-800 space-y-3">
          <h3 className="text-sm font-semibold text-white">Interesting HTML Comments</h3>
          <div className="space-y-2">
            {comments.map((c: string, idx: number) => (
              <div key={idx} className="p-2.5 rounded bg-surface-950 font-mono text-xs text-amber-300 border border-surface-800">
                &lt;!-- {c} --&gt;
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function PortsResultView({ data }: { data: any }) {
  const ports = data.ports || []

  return (
    <div className="glass-card p-6 border border-surface-800 space-y-4">
      <h3 className="text-sm font-semibold text-white">Discovered Open Ports ({ports.length})</h3>
      {ports.length === 0 ? (
        <p className="text-xs text-surface-500">No common infrastructure or management ports were detected open.</p>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {ports.map((p: any) => (
            <div key={p.port} className="p-3 rounded-xl bg-surface-900/60 border border-surface-800 text-center">
              <span className="text-lg font-mono font-bold text-white block">{p.port}</span>
              <span className="text-xs text-brand-400 font-medium">{p.service}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

const PLATFORM_ICONS: Record<string, string> = {
  gravatar: '🪪',
  duolingo: '🦉',
  github: '🐙',
  linkedin: '💼',
  google: '🔵',
  microsoft: '🟦',
  twitter: '🐦',
  tiktok: '🎵',
  flickr: '📷',
  etsy: '🛍️',
  medium: '✍️',
  reddit: '🟠',
}

const STATUS_STYLE: Record<string, string> = {
  found: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  detected: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  targeted: 'text-brand-400 bg-brand-500/10 border-brand-500/20',
  query_ready: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  not_detected: 'text-surface-500 bg-surface-800/50 border-surface-700/30',
}

function OSINTResultView({ data }: { data: any }) {
  const emails: string[] = data.emails || []
  const dorks: any[] = data.google_dorks || []
  const githubRecon: any[] = data.github_recon || []
  const profiles: any[] = data.behind_the_email || []
  const linkedinIntel: any = data.linkedin_intelligence || {}
  const companyName: string = data.company_name || data.target || ''
  const [selectedEmail, setSelectedEmail] = useState<number>(0)

  const activeProfile = profiles[selectedEmail]

  return (
    <div className="space-y-6">

      {/* ── Header Summary ── */}
      <div className="glass-card p-5 border border-surface-800 flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-brand-600/20 border border-brand-500/30 flex items-center justify-center text-lg">🕵️</div>
          <div>
            <h2 className="text-sm font-bold text-white">Behind the Email — Identity Intelligence</h2>
            <p className="text-xs text-surface-400 mt-0.5">
              {emails.length} corporate identities · {profiles.length} enriched profiles · Silent passive execution
            </p>
          </div>
        </div>
        <span className="ml-auto text-[10px] font-bold uppercase px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 tracking-wider">
          🔇 Silent Mode Active
        </span>
      </div>

      {/* ── Email Selector ── */}
      {emails.length > 0 && (
        <div className="glass-card p-5 border border-surface-800 space-y-3">
          <h3 className="text-sm font-semibold text-white">📧 Discovered Corporate Identities ({emails.length})</h3>
          <div className="flex flex-wrap gap-2">
            {emails.map((e: string, idx: number) => (
              <button
                key={e}
                onClick={() => setSelectedEmail(idx)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all border ${
                  selectedEmail === idx
                    ? 'bg-brand-600/30 border-brand-500/50 text-brand-300'
                    : 'bg-surface-900 border-surface-800 text-surface-300 hover:border-surface-700'
                }`}
              >
                {e}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ── Behind the Email Profile ── */}
      {activeProfile && (
        <>
          {/* Profile Enrichment */}
          <div className="glass-card p-6 border border-surface-800 space-y-4">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <span>👤</span> Profile Enrichment
              <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20 ml-1">
                LinkedIn & Professional Registers
              </span>
            </h3>
            <div className="flex items-start gap-5">
              {activeProfile.avatar_url && (
                <img
                  src={activeProfile.avatar_url}
                  alt="Avatar"
                  className="w-16 h-16 rounded-xl border border-surface-700 bg-surface-900 object-cover flex-shrink-0"
                  onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }}
                />
              )}
              <div className="grid grid-cols-2 gap-x-8 gap-y-2.5 flex-1">
                {[
                  ['Full Name', activeProfile.profile_enrichment?.full_name],
                  ['Inferred Role', activeProfile.profile_enrichment?.inferred_role],
                  ['Department', activeProfile.profile_enrichment?.department],
                  ['Company', activeProfile.profile_enrichment?.company],
                  ['Email', activeProfile.email],
                  ['Username', activeProfile.profile_enrichment?.username],
                ].filter(([,v]) => v).map(([label, value]) => (
                  <div key={label as string}>
                    <span className="text-[10px] uppercase tracking-wider text-surface-500 font-semibold block mb-0.5">{label}</span>
                    <span className="text-xs text-white font-medium">{value}</span>
                  </div>
                ))}
              </div>
            </div>
            {/* LinkedIn enrichment actions */}
            <div className="flex flex-wrap gap-2 pt-2 border-t border-surface-800">
              {activeProfile.profile_enrichment?.linkedin_search_url && (
                <a
                  href={activeProfile.profile_enrichment.linkedin_search_url}
                  target="_blank" rel="noopener noreferrer"
                  className="px-3 py-1.5 rounded-lg text-xs bg-blue-600/20 text-blue-400 border border-blue-500/30 hover:bg-blue-600/30 transition-colors flex items-center gap-1.5"
                >
                  💼 LinkedIn Search <ExternalLink className="h-3 w-3" />
                </a>
              )}
              {activeProfile.profile_enrichment?.linkedin_dork_url && (
                <a
                  href={activeProfile.profile_enrichment.linkedin_dork_url}
                  target="_blank" rel="noopener noreferrer"
                  className="px-3 py-1.5 rounded-lg text-xs bg-brand-600/20 text-brand-400 border border-brand-500/30 hover:bg-brand-600/30 transition-colors flex items-center gap-1.5"
                >
                  🔍 Google Dork <ExternalLink className="h-3 w-3" />
                </a>
              )}
              {activeProfile.profile_enrichment?.google_identity_url && (
                <a
                  href={activeProfile.profile_enrichment.google_identity_url}
                  target="_blank" rel="noopener noreferrer"
                  className="px-3 py-1.5 rounded-lg text-xs bg-orange-600/20 text-orange-400 border border-orange-500/30 hover:bg-orange-600/30 transition-colors flex items-center gap-1.5"
                >
                  🌐 Google Identity Search <ExternalLink className="h-3 w-3" />
                </a>
              )}
            </div>
          </div>

          {/* Social Account Discovery */}
          <div className="glass-card p-6 border border-surface-800 space-y-4">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <span>🌐</span> Social Account Discovery
              <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20 ml-1">
                12 Platforms Scanned
              </span>
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {(activeProfile.social_discovery || []).map((acc: any, idx: number) => {
                const statusStyle = STATUS_STYLE[acc.status] || STATUS_STYLE.not_detected
                const icon = PLATFORM_ICONS[acc.icon] || '🔗'
                return (
                  <div
                    key={idx}
                    className={`p-3 rounded-xl border flex items-start gap-3 transition-all ${statusStyle}`}
                  >
                    <span className="text-lg flex-shrink-0 mt-0.5">{icon}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2 mb-0.5">
                        <span className="text-xs font-semibold text-white">{acc.platform}</span>
                        <span className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded-full border ${statusStyle}`}>
                          {acc.status === 'found' || acc.status === 'detected' ? '✓ Found' :
                           acc.status === 'targeted' ? '⚡ Targeted' :
                           acc.status === 'query_ready' ? '🔍 Query' : '✗ None'}
                        </span>
                      </div>
                      <p className="text-[11px] text-current opacity-80 leading-tight">{acc.details}</p>
                      {acc.profile_url && (
                        <a
                          href={acc.profile_url}
                          target="_blank" rel="noopener noreferrer"
                          className="text-[10px] opacity-70 hover:opacity-100 underline underline-offset-2 mt-1 block truncate transition-opacity"
                        >
                          {acc.username || 'View Profile'} <ExternalLink className="inline h-2.5 w-2.5" />
                        </a>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Data Breach Checks */}
          {activeProfile.breach_checks && (
            <div className={`glass-card p-6 border space-y-4 ${
              activeProfile.breach_checks.pwned
                ? 'border-red-500/30 bg-red-950/10'
                : 'border-emerald-500/20 bg-emerald-950/10'
            }`}>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <span>🔓</span> Data Breach Intelligence
                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full border ml-1 ${
                  activeProfile.breach_checks.pwned
                    ? 'bg-red-500/20 text-red-400 border-red-500/30'
                    : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                }`}>
                  {activeProfile.breach_checks.pwned ? `⚠ ${activeProfile.breach_checks.breach_count} Breach(es) Detected` : '✓ Clean'}
                </span>
              </h3>

              {activeProfile.breach_checks.pwned ? (
                <div className="space-y-3">
                  <div className="flex flex-wrap gap-1.5 mb-3">
                    <span className="text-xs text-surface-400">Compromised data:</span>
                    {(activeProfile.breach_checks.compromised_data || []).map((d: string) => (
                      <span key={d} className="text-[10px] px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/20 font-medium">
                        {d}
                      </span>
                    ))}
                  </div>
                  {(activeProfile.breach_checks.breaches || []).map((b: any, idx: number) => (
                    <div key={idx} className="p-3 rounded-xl bg-surface-900/60 border border-surface-800 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-white">{b.name}</span>
                        <span className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded-full border ${
                          b.risk === 'critical' ? 'text-red-400 bg-red-500/10 border-red-500/20' :
                          b.risk === 'high' ? 'text-orange-400 bg-orange-500/10 border-orange-500/20' :
                          'text-amber-400 bg-amber-500/10 border-amber-500/20'
                        }`}>{b.risk} risk</span>
                      </div>
                      <div className="text-[10px] text-surface-400">
                        📅 {b.date} &nbsp;·&nbsp; {b.pwn_count?.toLocaleString()} accounts
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {(b.data_classes || []).map((c: string) => (
                          <span key={c} className="text-[9px] px-1.5 py-0.5 rounded bg-surface-800 text-surface-400 border border-surface-700">
                            {c}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-emerald-400/80">No breach records detected for this identity in the monitored databases.</p>
              )}

              <p className="text-[10px] text-surface-600">
                ℹ️ Source: {activeProfile.breach_checks.checked_database}
              </p>
            </div>
          )}

          {/* Silent Execution Badge */}
          {activeProfile.silent_execution && (
            <div className="flex items-center gap-3 px-4 py-3 rounded-xl border border-surface-700/50 bg-surface-900/40">
              <span className="text-base">🔇</span>
              <div>
                <span className="text-xs font-semibold text-surface-300">{activeProfile.silent_execution.description}</span>
                <span className="block text-[10px] text-surface-600 mt-0.5">
                  Mode: {activeProfile.silent_execution.mode} &nbsp;·&nbsp; Target alerted: {activeProfile.silent_execution.target_notified ? 'Yes' : 'No'}
                </span>
              </div>
            </div>
          )}
        </>
      )}

      {/* ── LinkedIn Corporate Intelligence ── */}
      {linkedinIntel?.dorks?.length > 0 && (
        <div className="glass-card p-6 border border-surface-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <span>💼</span> LinkedIn Corporate Intelligence
            </h3>
            {linkedinIntel.company_search_url && (
              <a
                href={linkedinIntel.company_search_url}
                target="_blank" rel="noopener noreferrer"
                className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
              >
                {linkedinIntel.company_name} on LinkedIn <ExternalLink className="h-3 w-3" />
              </a>
            )}
          </div>
          {linkedinIntel.detected_email_pattern && (
            <div className="px-3 py-2 rounded-lg bg-surface-900/60 border border-surface-800 text-xs font-mono text-brand-400">
              📧 Inferred email pattern: <strong>{linkedinIntel.detected_email_pattern}</strong>
            </div>
          )}
          <div className="space-y-2">
            {linkedinIntel.dorks.map((d: any, idx: number) => (
              <div key={idx} className="p-3.5 rounded-xl border border-surface-800 bg-surface-900/50 space-y-1.5">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <span className="text-xs font-semibold text-white block">{d.role_category}</span>
                    <span className="text-[11px] text-surface-400">{d.description}</span>
                  </div>
                  <a
                    href={d.url}
                    target="_blank" rel="noopener noreferrer"
                    className="px-2.5 py-1.5 rounded-lg text-xs bg-blue-600/20 text-blue-400 border border-blue-500/30 hover:bg-blue-600/30 transition-colors flex items-center gap-1 flex-shrink-0"
                  >
                    Search <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
                <code className="text-[10px] font-mono text-surface-500 block leading-relaxed">{d.dork}</code>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Google Dorks ── */}
      <div className="glass-card p-6 border border-surface-800 space-y-3">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <span>🔍</span> Targeted Google Dorks Reconnaissance
        </h3>
        <div className="space-y-2">
          {dorks.map((d: any, idx: number) => (
            <div key={idx} className="p-3 bg-surface-900/60 rounded-xl border border-surface-800 flex items-center justify-between gap-4">
              <div>
                <span className="text-xs font-semibold text-white block">{d.category}</span>
                <span className="text-xs font-mono text-surface-400">{d.dork}</span>
              </div>
              <a
                href={d.url}
                target="_blank"
                rel="noopener noreferrer"
                className="px-2.5 py-1.5 rounded-lg text-xs bg-brand-600/20 text-brand-400 border border-brand-500/30 hover:bg-brand-600/30 transition-colors flex items-center gap-1.5 flex-shrink-0"
              >
                Query Google <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          ))}
        </div>
      </div>

      {/* ── GitHub Recon ── */}
      {githubRecon.length > 0 && (
        <div className="glass-card p-6 border border-surface-800 space-y-3">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <span>🐙</span> GitHub Code Leak Reconnaissance
          </h3>
          <div className="space-y-2">
            {githubRecon.map((q: any, idx: number) => (
              <div key={idx} className="p-3 bg-surface-900/60 rounded-xl border border-surface-800 flex items-center justify-between gap-4">
                <div>
                  <span className="text-xs font-semibold text-white block">{q.description}</span>
                  <span className="text-xs font-mono text-surface-400">{q.query}</span>
                </div>
                <a
                  href={q.url}
                  target="_blank" rel="noopener noreferrer"
                  className="px-2.5 py-1.5 rounded-lg text-xs bg-surface-800 text-surface-300 border border-surface-700 hover:bg-surface-700 transition-colors flex items-center gap-1.5 flex-shrink-0"
                >
                  GitHub <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            ))}
          </div>
        </div>
      )}

    </div>
  )
}

function CloudResultView({ data }: { data: any }) {
  const buckets = data.buckets || []

  return (
    <div className="glass-card p-6 border border-surface-800 space-y-3">
      <h3 className="text-sm font-semibold text-white">Cloud Object Storage Buckets ({buckets.length})</h3>
      {buckets.length === 0 ? (
        <p className="text-xs text-surface-500">No associated public cloud storage buckets detected.</p>
      ) : (
        <div className="space-y-2">
          {buckets.map((b: any, idx: number) => (
            <div key={idx} className="p-3 bg-surface-900/60 rounded-xl border border-surface-800 flex items-center justify-between">
              <div>
                <span className="text-xs font-bold text-white font-mono block">{b.bucket_name}</span>
                <span className="text-xs text-surface-400">{b.provider}</span>
              </div>
              <span
                className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${
                  b.status === 'open_read'
                    ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                    : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                }`}
              >
                {b.status === 'open_read' ? 'Publicly Readable' : 'Protected'}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ReputationResultView({ data }: { data: any }) {
  const blacklists = data.blacklists || []

  return (
    <div className="glass-card p-6 border border-surface-800 space-y-3">
      <h3 className="text-sm font-semibold text-white">DNSBL Threat & Blacklist Feeds</h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
        {blacklists.map((b: any, idx: number) => (
          <div
            key={idx}
            className={`p-3 rounded-xl border text-center ${
              b.listed ? 'bg-red-950/20 border-red-500/40 text-red-300' : 'bg-surface-900/60 border-surface-800 text-surface-300'
            }`}
          >
            <span className="text-xs font-semibold block">{b.name}</span>
            <span className="text-[11px] font-mono mt-1 block">
              {b.listed ? '⚠️ Blacklisted' : '✅ Clean'}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
