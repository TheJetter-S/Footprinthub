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
  Users,
  Briefcase,
  Building2,
  Sparkles,
  UserCheck,
  MapPin,
  Calendar,
  Hash,
  Mail,
  ShieldAlert,
  AtSign,
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
  'twitter / x': '🐦',
  tiktok: '🎵',
  flickr: '📷',
  etsy: '🛍️',
  medium: '✍️',
  reddit: '🟠',
  facebook: '📘',
  instagram: '📸',
  youtube: '▶️',
  pinterest: '📌',
  discord: '💬',
  telegram: '✈️',
  crunchbase: '📊',
}

const STATUS_STYLE: Record<string, string> = {
  found: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  detected: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  targeted: 'text-brand-400 bg-brand-500/10 border-brand-500/20',
  query_ready: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  not_detected: 'text-surface-500 bg-surface-800/50 border-surface-700/30',
}

function buildFallbackInternetIntel(targetDomain: string, companyName: string) {
  const encDomain = encodeURIComponent(targetDomain || 'target')
  const encCompany = encodeURIComponent(companyName || targetDomain || 'company')
  return {
    domain: targetDomain,
    company_name: companyName,
    wayback_machine: {
      domain: targetDomain,
      available: true,
      total_snapshots: 0,
      archive_url: `https://web.archive.org/web/*/${targetDomain}`,
      message: 'Explore historical website snapshots on the Internet Archive',
    },
    infrastructure_intel: [
      { name: 'Shodan', category: 'Host & Port Recon', description: `Open ports, banners, and running services on ${targetDomain}`, url: `https://www.shodan.io/search?query=hostname:${encDomain}`, icon: '⚡' },
      { name: 'Censys Search', category: 'Host & Certificate Recon', description: `Internet-wide scanning data, certificates, and IPv4 hosts for ${targetDomain}`, url: `https://search.censys.io/search?q=${encDomain}`, icon: '🔍' },
      { name: 'BuiltWith', category: 'Technology Profiler', description: `Frameworks, analytics, CMS, and hosting infrastructure used by ${targetDomain}`, url: `https://builtwith.com/${encDomain}`, icon: '🛠️' },
      { name: 'SecurityTrails', category: 'DNS & History', description: `Historical DNS records, subdomains, and WHOIS changes for ${targetDomain}`, url: `https://securitytrails.com/domain/${encDomain}/dns`, icon: '📜' },
      { name: 'DNSDumpster', category: 'DNS Mapping', description: `DNS mapping, subdomains, and network visualizer for ${targetDomain}`, url: `https://dnsdumpster.com/`, icon: '🗺️' },
      { name: 'Netcraft Site Report', category: 'Hosting & Security', description: `Hosting provider, web server, uptime history, and risk rating for ${targetDomain}`, url: `https://sitereport.netcraft.com/?url=${encDomain}`, icon: '🛡️' },
      { name: 'crt.sh (Certificate Transparency)', category: 'SSL/TLS Recon', description: `All SSL/TLS certificates ever issued for ${targetDomain} (finds hidden subdomains)`, url: `https://crt.sh/?q=%25.${encDomain}`, icon: '🔐' },
      { name: 'ViewDNS.info', category: 'Reverse IP & Tools', description: `Reverse IP lookup, DNS record report, and IP history for ${targetDomain}`, url: `https://viewdns.info/reverseip/?host=${encDomain}&t=1`, icon: '🔎' },
    ],
    reputation_intel: [
      { name: 'Glassdoor', category: 'Employee Reviews', description: `Employee reviews, salaries, interview experiences, and company culture for ${companyName}`, url: `https://www.glassdoor.com/Search/results.htm?keyword=${encCompany}`, icon: '⭐' },
      { name: 'Trustpilot', category: 'Customer Reviews', description: `Customer trust score, reviews, and complaint history for ${companyName}`, url: `https://www.trustpilot.com/search?query=${encCompany}`, icon: '🏆' },
      { name: 'Better Business Bureau', category: 'Business Rating', description: `BBB accreditation status, customer complaints, and business rating`, url: `https://www.bbb.org/search?find_text=${encCompany}`, icon: '📋' },
      { name: 'Indeed', category: 'Employer Profile', description: `Company reviews, job postings, and salary data from employees and applicants`, url: `https://www.indeed.com/cmp/${encodeURIComponent((companyName || '').toLowerCase().replace(/\s+/g, '-'))}/reviews`, icon: '💼' },
      { name: 'G2', category: 'Software Reviews', description: `Product reviews, pricing, and competitive alternatives for ${companyName}'s software`, url: `https://www.g2.com/search?query=${encCompany}`, icon: '📊' },
    ],
    news_intel: [
      { name: 'Google News', category: 'News', description: `Latest news articles, press releases, and media mentions for ${companyName}`, url: `https://news.google.com/search?q=${encCompany}`, icon: '📰' },
      { name: 'TechCrunch', category: 'Tech News', description: `TechCrunch coverage, funding rounds, and acquisitions for ${companyName}`, url: `https://techcrunch.com/search/${encCompany}`, icon: '🚀' },
      { name: 'PitchBook', category: 'Venture Capital & M&A', description: `Venture funding, investors, valuation, and executive profiles for ${companyName}`, url: `https://pitchbook.com/profiles/search?q=${encCompany}`, icon: '💰' },
      { name: 'Product Hunt', category: 'Product Launches', description: `Product launches, user votes, reviews, and maker profiles for ${companyName}`, url: `https://www.producthunt.com/search?q=${encCompany}`, icon: '💡' },
    ],
    legal_intel: [
      { name: 'ICANN WHOIS', category: 'Domain Registration', description: `Domain registrar, creation/expiry dates, name servers, and registrant details`, url: `https://lookup.icann.org/en/lookup?name=${encDomain}`, icon: '📜' },
      { name: 'Google Transparency Report', category: 'Malware & Safe Browsing', description: `Google Safe Browsing status, malware warnings, and unsafe content flags`, url: `https://transparencyreport.google.com/safe-browsing/search?url=${encDomain}`, icon: '🛡️' },
      { name: 'URLScan.io', category: 'Automated Web Scan', description: `Automated web scan, screenshots, DOM analysis, and contacted IPs for ${targetDomain}`, url: `https://urlscan.io/search/#${encDomain}`, icon: '🔬' },
      { name: 'VirusTotal Domain Report', category: 'Security Reputation', description: `70+ antivirus and blocklist scanners evaluating ${targetDomain}`, url: `https://www.virustotal.com/gui/domain/${encDomain}`, icon: '🦠' },
    ],
    linkedin_deep_queries: [
      { name: 'Company Employees (Current)', description: `All current employees at ${companyName} on LinkedIn`, dork: `site:linkedin.com/in "${companyName}" "Present"`, url: `https://www.google.com/search?q=site:linkedin.com/in+"${encCompany}"+"Present"`, icon: '👥' },
      { name: 'Former Employees', description: `People who previously worked at ${companyName} — may reveal internal culture & stack`, dork: `site:linkedin.com/in "${companyName}" -"Present"`, url: `https://www.google.com/search?q=site:linkedin.com/in+"${encCompany}"+-"Present"`, icon: '🚶' },
      { name: 'Hiring Managers & Recruiters', description: `HR & recruiting contacts at ${companyName} — reveals org structure`, dork: `site:linkedin.com/in "${companyName}" ("Recruiter" OR "Talent Acquisition" OR "HR")`, url: `https://www.google.com/search?q=site:linkedin.com/in+"${encCompany}"+("Recruiter"+OR+"Talent+Acquisition"+OR+"HR")`, icon: '🎯' },
      { name: 'Engineering & DevOps Team', description: `Technical staff revealing technology stack and internal architecture`, dork: `site:linkedin.com/in "${companyName}" ("Engineer" OR "DevOps" OR "Developer" OR "Architect")`, url: `https://www.google.com/search?q=site:linkedin.com/in+"${encCompany}"+("Engineer"+OR+"DevOps"+OR+"Developer"+OR+"Architect")`, icon: '⚙️' },
      { name: 'Security & Compliance Team', description: `Security personnel revealing defense posture and compliance frameworks`, dork: `site:linkedin.com/in "${companyName}" ("Security" OR "CISO" OR "Compliance" OR "SOC" OR "Pentest")`, url: `https://www.google.com/search?q=site:linkedin.com/in+"${encCompany}"+("Security"+OR+"CISO"+OR+"Compliance"+OR+"SOC"+OR+"Pentest")`, icon: '🔐' },
      { name: 'Company Job Postings', description: `Active job postings revealing expansion areas, tech stack requirements, and team gaps`, dork: `site:linkedin.com/jobs "${companyName}"`, url: `https://www.google.com/search?q=site:linkedin.com/jobs+"${encCompany}"`, icon: '📋' },
    ],
    social_deep_queries: [
      { name: 'Twitter / X Mentions', description: `Public tweets and discussions mentioning ${companyName} or ${targetDomain}`, url: `https://x.com/search?q=${encCompany}+OR+${encDomain}&f=live`, icon: '🐦' },
      { name: 'Reddit Discussions', description: `Reddit discussions, community reviews, and insider info about ${companyName}`, url: `https://www.reddit.com/search/?q=${encCompany}&type=link&sort=new`, icon: '🟠' },
      { name: 'YouTube Content', description: `Video content, tutorials, and product walkthroughs for ${companyName}`, url: `https://www.youtube.com/results?search_query=${encCompany}`, icon: '▶️' },
      { name: 'Hacker News', description: `Tech community discussions and submissions about ${companyName} or ${targetDomain}`, url: `https://hn.algolia.com/?q=${encCompany}`, icon: '🔶' },
      { name: 'Stack Overflow', description: `Technical questions and developer discussions associated with ${targetDomain}`, url: `https://stackoverflow.com/search?q=${encCompany}`, icon: '📚' },
    ],
  }
}

function OSINTResultView({ data }: { data: any }) {
  const emails: string[] = data.emails || []
  const dorks: any[] = data.google_dorks || []
  const githubRecon: any[] = data.github_recon || []
  const profiles: any[] = data.behind_the_email || []
  const linkedinIntel: any = data.linkedin_intelligence || {}
  const companyMeta: any = data.company_metadata || {}
  const digitalFootprint: any = data.digital_footprint || {}
  const founders: any[] = data.founders || linkedinIntel.founders || []
  const employees: any[] = data.employees || linkedinIntel.employees || []
  const socialProfiles: any[] = data.website_social_profiles || digitalFootprint.all_social_profiles || []
  const githubIntel: any = data.github_intelligence || {}
  const companyName: string = data.company_name || companyMeta.name || data.target || ''
  const targetDomain: string = data.target || ''
  const internetIntel: any = (data.internet_intelligence && Object.keys(data.internet_intelligence).length > 0)
    ? data.internet_intelligence
    : buildFallbackInternetIntel(targetDomain, companyName)

  const [selectedEmail, setSelectedEmail] = useState<number>(0)
  const [activeTab, setActiveTab] = useState<'executive' | 'socials' | 'employees' | 'identities' | 'wayback' | 'recon_tools'>(
    founders.length > 0 ? 'executive' : socialProfiles.length > 0 ? 'socials' : 'employees'
  )
  const [employeeDepartment, setEmployeeDepartment] = useState<string>('All')
  const [employeeQuery, setEmployeeQuery] = useState<string>('')
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  const activeProfile = profiles[selectedEmail]

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  // Filter employees
  const filteredEmployees = employees.filter((emp: any) => {
    const matchesDept =
      employeeDepartment === 'All' || emp.department === employeeDepartment
    const matchesSearch =
      !employeeQuery ||
      (emp.name && emp.name.toLowerCase().includes(employeeQuery.toLowerCase())) ||
      (emp.title && emp.title.toLowerCase().includes(employeeQuery.toLowerCase())) ||
      (emp.email && emp.email.toLowerCase().includes(employeeQuery.toLowerCase()))
    return matchesDept && matchesSearch
  })

  // Group departments
  const departmentCounts = employees.reduce((acc: Record<string, number>, emp: any) => {
    const dept = emp.department || 'Operations & Business'
    acc[dept] = (acc[dept] || 0) + 1
    return acc
  }, {})

  return (
    <div className="space-y-6">

      {/* ── Intelligence Command Center Dossier Header ── */}
      <div className="relative overflow-hidden rounded-2xl border border-surface-700/60 bg-gradient-to-br from-surface-950 via-surface-900 to-surface-950 p-6 shadow-2xl backdrop-blur-xl">
        <div className="absolute -right-12 -top-12 h-64 w-64 rounded-full bg-cyan-500/5 blur-3xl pointer-events-none" />
        <div className="absolute -left-12 -bottom-12 h-64 w-64 rounded-full bg-brand-500/5 blur-3xl pointer-events-none" />

        <div className="relative z-10 space-y-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-brand-500/20 via-cyan-500/10 to-blue-500/20 border border-brand-500/30 text-2xl shadow-lg shadow-brand-950/50">
                🕵️
              </div>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-xl font-bold tracking-tight text-white">{companyName}</h2>
                  <span className="rounded-lg bg-surface-800/90 px-2.5 py-0.5 font-mono text-xs text-brand-300 border border-surface-700">
                    {targetDomain}
                  </span>
                  {companyMeta.json_ld_detected && (
                    <span className="rounded-md bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400 border border-emerald-500/20">
                      ✓ Schema.org Verified
                    </span>
                  )}
                </div>
                <p className="mt-1 text-xs text-surface-400 max-w-2xl leading-relaxed">
                  {companyMeta.description || 'Passive open-source intelligence harvested from public website structure, team registries, and verified digital footprints.'}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-[11px] font-semibold text-emerald-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Live OSINT Scraped
              </span>
            </div>
          </div>

          {/* Company Profile Metadata Chips */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-2">
            <div className="rounded-xl border border-surface-800/80 bg-surface-900/60 p-3">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 block mb-0.5">Industry & Sector</span>
              <span className="text-xs font-semibold text-white truncate block">
                {companyMeta.industry || 'Technology & Software'}
              </span>
            </div>
            <div className="rounded-xl border border-surface-800/80 bg-surface-900/60 p-3">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 block mb-0.5">Headquarters</span>
              <span className="text-xs font-semibold text-white truncate block flex items-center gap-1">
                <MapPin className="h-3 w-3 text-red-400 flex-shrink-0" />
                {companyMeta.headquarters || 'Public Digital Infrastructure'}
              </span>
            </div>
            <div className="rounded-xl border border-surface-800/80 bg-surface-900/60 p-3">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 block mb-0.5">Established</span>
              <span className="text-xs font-semibold text-white flex items-center gap-1">
                <Calendar className="h-3 w-3 text-brand-400 flex-shrink-0" />
                {companyMeta.founded_year || 'Verified Domain'}
              </span>
            </div>
            <div className="rounded-xl border border-surface-800/80 bg-surface-900/60 p-3">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 block mb-0.5">Estimated Team</span>
              <span className="text-xs font-semibold text-white flex items-center gap-1">
                <Users className="h-3 w-3 text-blue-400 flex-shrink-0" />
                {companyMeta.estimated_employees || `${employees.length || 1}+ Identified`}
              </span>
            </div>
          </div>

          {/* Quick Metrics KPI Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1 border-t border-surface-800/80">
            <button
              onClick={() => setActiveTab('executive')}
              className={`p-3 rounded-xl border text-left transition-all ${
                activeTab === 'executive'
                  ? 'bg-amber-500/10 border-amber-500/40 shadow-lg shadow-amber-950/20'
                  : 'bg-surface-900/40 border-surface-800 hover:border-surface-700'
              }`}
            >
              <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 block">Leadership & Owners</span>
              <div className="mt-1 flex items-center gap-1.5 text-lg font-bold text-amber-400">
                <span>👑</span> {founders.length}
              </div>
              <span className="text-[10px] text-surface-400 mt-0.5 block truncate">Scraped website personnel</span>
            </button>

            <button
              onClick={() => setActiveTab('socials')}
              className={`p-3 rounded-xl border text-left transition-all ${
                activeTab === 'socials'
                  ? 'bg-cyan-500/10 border-cyan-500/40 shadow-lg shadow-cyan-950/20'
                  : 'bg-surface-900/40 border-surface-800 hover:border-surface-700'
              }`}
            >
              <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 block">Website Socials</span>
              <div className="mt-1 flex items-center gap-1.5 text-lg font-bold text-cyan-400">
                <span>🌐</span> {socialProfiles.length}
              </div>
              <span className="text-[10px] text-surface-400 mt-0.5 block truncate">Official profiles found</span>
            </button>

            <button
              onClick={() => setActiveTab('employees')}
              className={`p-3 rounded-xl border text-left transition-all ${
                activeTab === 'employees'
                  ? 'bg-blue-500/10 border-blue-500/40 shadow-lg shadow-blue-950/20'
                  : 'bg-surface-900/40 border-surface-800 hover:border-surface-700'
              }`}
            >
              <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 block">Discovered Staff</span>
              <div className="mt-1 flex items-center gap-1.5 text-lg font-bold text-blue-400">
                <span>👥</span> {employees.length}
              </div>
              <span className="text-[10px] text-surface-400 mt-0.5 block truncate">Aggregated footprints</span>
            </button>

            <button
              onClick={() => setActiveTab('identities')}
              className={`p-3 rounded-xl border text-left transition-all ${
                activeTab === 'identities'
                  ? 'bg-brand-500/10 border-brand-500/40 shadow-lg shadow-brand-950/20'
                  : 'bg-surface-900/40 border-surface-800 hover:border-surface-700'
              }`}
            >
              <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 block">Corporate Identities</span>
              <div className="mt-1 flex items-center gap-1.5 text-lg font-bold text-brand-400">
                <span>📧</span> {emails.length}
              </div>
              <span className="text-[10px] text-surface-400 mt-0.5 block truncate">Behind the Email</span>
            </button>
          </div>

          {/* Streamlined Tab Switcher */}
          <div className="flex flex-wrap gap-2 pt-2 border-t border-surface-800">
            {[
              { id: 'executive', label: `Leadership & Owner (${founders.length})`, icon: '👑' },
              { id: 'socials', label: `Website Socials (${socialProfiles.length})`, icon: '🌐' },
              { id: 'employees', label: `Employee Directory (${employees.length})`, icon: '👥' },
              { id: 'identities', label: `Behind the Email (${emails.length})`, icon: '🕵️' },
              { id: 'wayback', label: 'Wayback Machine', icon: '🏛️' },
              { id: 'recon_tools', label: `Recon Tools & Dorks (${dorks.length + githubRecon.length})`, icon: '🛠️' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-semibold transition-all ${
                  activeTab === tab.id
                    ? 'bg-gradient-to-r from-brand-600 to-cyan-600 text-white shadow-md shadow-brand-950/50'
                    : 'bg-surface-900/80 text-surface-400 border border-surface-800 hover:border-surface-700 hover:text-white'
                }`}
              >
                <span>{tab.icon}</span>
                <span>{tab.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ── TAB 1: Verified Leadership & Owner Intelligence ── */}
      {activeTab === 'executive' && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 px-1">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>👑</span>
                <span>Discovered Website Leadership & Owner Intelligence</span>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  {founders.length} Scraped Profiles
                </span>
              </h3>
              <p className="text-xs text-surface-400 mt-0.5">
                Real individuals and key decision makers extracted directly from website HTML, LinkedIn profile links, and structured schema.
              </p>
            </div>
            {linkedinIntel.company_url && (
              <a
                href={linkedinIntel.company_url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-blue-600/20 text-blue-300 border border-blue-500/30 text-xs font-semibold hover:bg-blue-600/30 transition-all"
              >
                💼 Official LinkedIn Page <ExternalLink className="h-3 w-3" />
              </a>
            )}
          </div>

          {founders.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-surface-800 bg-surface-900/30 p-8 text-center space-y-3">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-surface-800 text-2xl text-surface-400">
                🔍
              </div>
              <div className="space-y-1">
                <h4 className="text-sm font-bold text-white">No Public Executive Profiles Declared in Website HTML</h4>
                <p className="text-xs text-surface-400 max-w-md mx-auto leading-relaxed">
                  The scanned public pages for <span className="text-brand-300 font-mono">{targetDomain}</span> do not explicitly list founder or owner names in their markup.
                </p>
              </div>
              <button
                onClick={() => setActiveTab('recon_tools')}
                className="inline-flex items-center gap-2 rounded-xl bg-brand-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-brand-900/40 hover:bg-brand-500 transition-all"
              >
                <span>Open Targeted LinkedIn Recon Dorks</span>
                <ExternalLink className="h-3.5 w-3.5" />
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {founders.map((founder: any, idx: number) => {
                const initials = founder.name
                  ? founder.name.split(' ').map((n: string) => n[0]).slice(0, 2).join('').toUpperCase()
                  : 'LE'
                const hasDirectLinkedIn = Boolean(founder.linkedin_url && founder.linkedin_url.includes('linkedin.com/in/'))
                const inferredEmail = founder.inferred_email || `${founder.name?.toLowerCase().replace(/\s+/g, '.')}@${targetDomain}`

                return (
                  <div
                    key={idx}
                    className="rounded-2xl border border-surface-800 bg-gradient-to-br from-surface-900/90 via-surface-900/60 to-surface-950/90 p-5 space-y-4 hover:border-amber-500/40 transition-all shadow-xl"
                  >
                    {/* Header: Photo + Name + Verified Source */}
                    <div className="flex items-start gap-4">
                      {founder.avatar_url ? (
                        <img
                          src={founder.avatar_url}
                          alt={founder.name}
                          className="h-14 w-14 rounded-2xl object-cover border border-amber-500/30 bg-surface-950 flex-shrink-0 shadow-md"
                          onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }}
                        />
                      ) : (
                        <div className="h-14 w-14 rounded-2xl bg-gradient-to-br from-amber-600/30 via-brand-600/20 to-surface-900 border border-amber-500/40 flex items-center justify-center font-bold text-base text-amber-300 flex-shrink-0 shadow-md">
                          {initials}
                        </div>
                      )}

                      <div className="min-w-0 flex-1 space-y-1">
                        <div className="flex flex-wrap items-center justify-between gap-1">
                          <h4 className="text-sm font-bold text-white tracking-tight truncate">{founder.name}</h4>
                          <span className="rounded-full bg-emerald-500/10 px-2 py-0.5 text-[9px] font-bold text-emerald-400 border border-emerald-500/20">
                            ✓ Verified Scraped
                          </span>
                        </div>
                        <p className="text-xs font-semibold text-amber-400 truncate">
                          {founder.title}
                        </p>
                        <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
                          <span className="rounded-md bg-surface-800 px-2 py-0.5 text-[9px] font-medium text-surface-300 border border-surface-700">
                            {founder.department || 'Executive Leadership'}
                          </span>
                          <span className="text-[10px] text-surface-500 truncate">
                            Source: {founder.source || 'Website Team Page'}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Bio snippet if available */}
                    {founder.bio && (
                      <p className="text-xs text-surface-300 bg-surface-950/50 p-3 rounded-xl border border-surface-800/80 leading-relaxed">
                        {founder.bio}
                      </p>
                    )}

                    {/* Inline Threat & Footprint Analysis Box */}
                    <div className="rounded-xl border border-surface-800 bg-surface-950/70 p-3.5 space-y-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-surface-400 flex items-center gap-1">
                          <ShieldAlert className="h-3 w-3 text-red-400" /> OSINT Risk Profile
                        </span>
                        <span className="text-[10px] font-semibold text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded-full">
                          High Exposure (BEC Target)
                        </span>
                      </div>

                      {/* Inferred Email with Copy */}
                      <div className="flex items-center justify-between gap-2 bg-surface-900/80 p-2 rounded-lg border border-surface-800 text-xs">
                        <div className="flex items-center gap-1.5 min-w-0">
                          <Mail className="h-3.5 w-3.5 text-brand-400 flex-shrink-0" />
                          <span className="text-surface-400 text-[11px]">Inferred Email:</span>
                          <span className="font-mono text-white text-[11px] truncate">{inferredEmail}</span>
                        </div>
                        <button
                          onClick={() => copyToClipboard(inferredEmail, `email-${idx}`)}
                          className="flex items-center gap-1 px-2 py-0.5 rounded bg-surface-800 hover:bg-surface-700 text-surface-300 hover:text-white text-[10px] transition-colors flex-shrink-0"
                        >
                          {copiedKey === `email-${idx}` ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                          <span>{copiedKey === `email-${idx}` ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>

                      {/* Direct LinkedIn Profile vs Search */}
                      <div className="flex items-center justify-between gap-2 pt-1 text-xs">
                        <span className="text-[11px] text-surface-400 flex items-center gap-1">
                          <span>💼</span> LinkedIn Identity:
                        </span>
                        {hasDirectLinkedIn ? (
                          <a
                            href={founder.linkedin_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 font-semibold text-blue-400 hover:text-blue-300 text-[11px] bg-blue-500/10 border border-blue-500/20 px-2.5 py-1 rounded-lg transition-colors"
                          >
                            <span>Direct Profile Found</span>
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        ) : (
                          <a
                            href={founder.linkedin_search_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-surface-400 hover:text-blue-300 text-[11px] transition-colors"
                          >
                            <span>Search Profile</span>
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* ── TAB 2: Official Website Social Media Profiles ── */}
      {activeTab === 'socials' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between px-1">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>🌐</span>
                <span>Official Social Media Channels Discovered on Website</span>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  {socialProfiles.length} Channels
                </span>
              </h3>
              <p className="text-xs text-surface-400 mt-0.5">
                Profiles explicitly published and linked in the HTML code of {targetDomain}.
              </p>
            </div>
          </div>

          {socialProfiles.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-surface-800 bg-surface-900/30 p-8 text-center text-xs text-surface-500">
              No official social media channels were detected in the crawled public website pages.
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3.5">
              {socialProfiles.map((p: any, idx: number) => {
                const icon = PLATFORM_ICONS[p.platform?.toLowerCase()] || p.icon || '🔗'
                const isLinkedIn = p.platform === 'LinkedIn'
                const isGitHub = p.platform === 'GitHub'

                return (
                  <div
                    key={idx}
                    className={`rounded-2xl border p-4 flex flex-col justify-between space-y-3 transition-all ${
                      isLinkedIn
                        ? 'border-blue-500/30 bg-gradient-to-br from-blue-950/20 to-surface-900/80 shadow-lg'
                        : isGitHub
                        ? 'border-purple-500/30 bg-gradient-to-br from-purple-950/20 to-surface-900/80'
                        : 'border-surface-800 bg-surface-900/70 hover:border-surface-700'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <span className="text-2xl">{icon}</span>
                        <div className="min-w-0">
                          <h4 className="text-xs font-bold text-white truncate">{p.platform}</h4>
                          <span className="text-[11px] font-mono text-brand-300 truncate block">
                            @{p.handle}
                          </span>
                        </div>
                      </div>
                      <span className="rounded-full bg-surface-800 px-2 py-0.5 text-[9px] font-bold uppercase text-surface-400 border border-surface-700 flex-shrink-0">
                        {p.type || 'profile'}
                      </span>
                    </div>

                    <div className="pt-2 border-t border-surface-800/80 flex items-center justify-between text-xs">
                      <button
                        onClick={() => copyToClipboard(p.url, `soc-${idx}`)}
                        className="flex items-center gap-1 text-[11px] text-surface-400 hover:text-white transition-colors"
                      >
                        {copiedKey === `soc-${idx}` ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                        <span>{copiedKey === `soc-${idx}` ? 'Copied' : 'Copy URL'}</span>
                      </button>

                      <a
                        href={p.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 font-semibold text-brand-400 hover:text-brand-300 text-[11px] transition-colors"
                      >
                        <span>Visit Channel</span>
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* ── TAB 3: Discovered Employee Directory ── */}
      {activeTab === 'employees' && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 px-1">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Users className="h-4 w-4 text-blue-400" />
                <span>Discovered Personnel & Employee Directory</span>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  {employees.length} Personnel
                </span>
              </h3>
              <p className="text-xs text-surface-400 mt-0.5">
                Staff identified across team pages, personal LinkedIn links, GitHub organization members, and corporate identities.
              </p>
            </div>
          </div>

          {/* Department Filter & Search Controls */}
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-surface-900/60 p-3 border border-surface-800">
            <div className="flex flex-wrap gap-1.5">
              {['All', 'Executive Leadership', 'Engineering & Tech', 'Cybersecurity & IT', 'Operations & Business'].map((dept) => {
                const count = dept === 'All' ? employees.length : (departmentCounts[dept] || 0)
                return (
                  <button
                    key={dept}
                    onClick={() => setEmployeeDepartment(dept)}
                    className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                      employeeDepartment === dept
                        ? 'bg-brand-600 text-white shadow-md shadow-brand-900/40'
                        : 'bg-surface-800/80 text-surface-400 hover:text-white border border-surface-700/60'
                    }`}
                  >
                    {dept} ({count})
                  </button>
                )
              })}
            </div>

            <div className="relative min-w-[220px] flex-1 sm:flex-initial">
              <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-surface-500" />
              <input
                type="text"
                placeholder="Search staff by name or role..."
                value={employeeQuery}
                onChange={(e) => setEmployeeQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs bg-surface-950 border border-surface-800 rounded-lg text-white placeholder-surface-500 focus:outline-none focus:border-brand-500"
              />
            </div>
          </div>

          {filteredEmployees.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-surface-800 bg-surface-900/30 p-8 text-center text-xs text-surface-500">
              No personnel matched the current filter criteria.
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3.5">
              {filteredEmployees.map((emp: any, idx: number) => {
                const initials = emp.name
                  ? emp.name.split(' ').map((n: string) => n[0]).slice(0, 2).join('').toUpperCase()
                  : 'EM'
                const isLeader = emp.department === 'Executive Leadership'
                const isSec = emp.department === 'Cybersecurity & IT'
                const empEmail = emp.inferred_email || emp.email || `${emp.name?.toLowerCase().replace(/\s+/g, '.')}@${targetDomain}`

                return (
                  <div
                    key={idx}
                    className="rounded-2xl border border-surface-800 bg-surface-900/70 p-4 flex flex-col justify-between space-y-3 hover:border-surface-700 transition-all shadow-md"
                  >
                    <div className="flex items-start gap-3">
                      {emp.avatar_url ? (
                        <img
                          src={emp.avatar_url}
                          alt={emp.name}
                          className="h-11 w-11 rounded-xl object-cover border border-surface-700 bg-surface-950 flex-shrink-0"
                          onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }}
                        />
                      ) : (
                        <div className={`h-11 w-11 rounded-xl border flex items-center justify-center font-bold text-xs flex-shrink-0 ${
                          isLeader
                            ? 'bg-amber-500/20 border-amber-500/30 text-amber-300'
                            : isSec
                            ? 'bg-red-500/20 border-red-500/30 text-red-300'
                            : 'bg-blue-500/20 border-blue-500/30 text-blue-300'
                        }`}>
                          {initials}
                        </div>
                      )}

                      <div className="min-w-0 flex-1">
                        <h4 className="text-xs font-bold text-white truncate">{emp.name}</h4>
                        <span className="text-[11px] text-surface-300 truncate block mt-0.5">
                          {emp.title}
                        </span>
                        <div className="flex items-center gap-1.5 mt-1">
                          <span className="rounded bg-surface-800 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-surface-400 border border-surface-700">
                            {emp.department}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Email Chip */}
                    <div className="flex items-center justify-between gap-2 rounded-lg bg-surface-950/80 px-2.5 py-1.5 border border-surface-800/80 text-[10px]">
                      <span className="font-mono text-brand-300 truncate">📧 {empEmail}</span>
                      <button
                        onClick={() => copyToClipboard(empEmail, `emp-email-${idx}`)}
                        className="text-surface-400 hover:text-white flex-shrink-0"
                      >
                        {copiedKey === `emp-email-${idx}` ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      </button>
                    </div>

                    <div className="pt-2 border-t border-surface-800/80 flex items-center justify-between text-[11px]">
                      <span className="text-[10px] text-surface-500 truncate max-w-[130px]">
                        {emp.source || 'Public Footprint'}
                      </span>
                      {emp.linkedin_url ? (
                        <a
                          href={emp.linkedin_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-semibold text-blue-400 hover:text-blue-300 inline-flex items-center gap-1"
                        >
                          <span>Profile</span>
                          <ExternalLink className="h-2.5 w-2.5" />
                        </a>
                      ) : (
                        <a
                          href={emp.linkedin_search_url || `https://www.linkedin.com/search/results/people/?keywords=${encodeURIComponent(emp.name + ' ' + companyName)}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-surface-400 hover:text-blue-300 inline-flex items-center gap-1"
                        >
                          <span>Search</span>
                          <ExternalLink className="h-2.5 w-2.5" />
                        </a>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* ── TAB 4: Corporate Identities (Behind the Email) ── */}
      {activeTab === 'identities' && (
        <div className="space-y-5">
          {/* Email Selector Chips */}
          {emails.length > 0 && (
            <div className="rounded-2xl border border-surface-800 bg-surface-900/60 p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>📧</span>
                  <span>Discovered Corporate Email Identities ({emails.length})</span>
                </h3>
                <span className="text-xs text-surface-400">Select identity to inspect enrichment & breach exposures</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {emails.map((e: string, idx: number) => (
                  <button
                    key={e}
                    onClick={() => setSelectedEmail(idx)}
                    className={`rounded-xl px-3.5 py-1.5 text-xs font-mono transition-all border ${
                      selectedEmail === idx
                        ? 'bg-brand-600/30 border-brand-500/60 text-brand-300 shadow-md shadow-brand-950/40'
                        : 'bg-surface-900 border-surface-800 text-surface-400 hover:text-white hover:border-surface-700'
                    }`}
                  >
                    {e}
                  </button>
                ))}
              </div>
            </div>
          )}

          {activeProfile && (
            <div className="space-y-4">
              {/* Profile Enrichment Card */}
              <div className="rounded-2xl border border-surface-800 bg-surface-900/70 p-6 space-y-4 shadow-lg">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <span>👤</span> Profile Enrichment & Verified Professional Registers
                  </h4>
                  <span className="rounded-full bg-blue-500/10 px-2.5 py-0.5 text-[10px] font-semibold text-blue-400 border border-blue-500/20">
                    Behind the Email Engine
                  </span>
                </div>

                <div className="flex items-start gap-4">
                  {activeProfile.avatar_url && (
                    <img
                      src={activeProfile.avatar_url}
                      alt="Avatar"
                      className="h-16 w-16 rounded-2xl border border-surface-700 bg-surface-950 object-cover flex-shrink-0"
                      onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }}
                    />
                  )}
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-3 flex-1">
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
                        <span className="text-xs font-semibold text-white">{value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Data Breach Check Card */}
              {activeProfile.breach_checks && (
                <div className={`rounded-2xl border p-6 space-y-3 ${
                  activeProfile.breach_checks.pwned
                    ? 'border-red-500/40 bg-gradient-to-br from-red-950/20 via-surface-900 to-surface-950 shadow-xl'
                    : 'border-emerald-500/30 bg-gradient-to-br from-emerald-950/20 via-surface-900 to-surface-950'
                }`}>
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-bold text-white flex items-center gap-2">
                      <ShieldAlert className={`h-4 w-4 ${activeProfile.breach_checks.pwned ? 'text-red-400' : 'text-emerald-400'}`} />
                      <span>Historical Data Breach Intelligence</span>
                    </h4>
                    <span className={`rounded-full px-3 py-0.5 text-xs font-bold border ${
                      activeProfile.breach_checks.pwned
                        ? 'bg-red-500/20 text-red-400 border-red-500/30'
                        : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                    }`}>
                      {activeProfile.breach_checks.pwned
                        ? `⚠️ ${activeProfile.breach_checks.breach_count} Breach Exposure(s)`
                        : '✓ No Breaches Detected'}
                    </span>
                  </div>

                  {activeProfile.breach_checks.pwned ? (
                    <div className="space-y-3 pt-2">
                      <div className="flex flex-wrap gap-1.5 items-center">
                        <span className="text-xs text-surface-400">Compromised attributes:</span>
                        {(activeProfile.breach_checks.compromised_data || []).map((d: string) => (
                          <span key={d} className="rounded-full bg-red-500/10 px-2 py-0.5 text-[10px] font-semibold text-red-400 border border-red-500/20">
                            {d}
                          </span>
                        ))}
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
                        {(activeProfile.breach_checks.breaches || []).map((b: any, bIdx: number) => (
                          <div key={bIdx} className="rounded-xl border border-surface-800 bg-surface-950/80 p-3 space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-bold text-white">{b.name}</span>
                              <span className="text-[9px] font-bold uppercase text-red-400 bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded">
                                {b.risk} risk
                              </span>
                            </div>
                            <p className="text-[10px] text-surface-400">📅 {b.date} · {b.pwn_count?.toLocaleString()} accounts</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-emerald-400/90">
                      No compromised passwords or breach credentials were found for this identity in public leak indexes.
                    </p>
                  )}
                </div>
              )}

              {/* Social Discovery (12 Platforms) */}
              <div className="rounded-2xl border border-surface-800 bg-surface-900/60 p-6 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <span>🌐</span> Multi-Platform Social Footprint Scan
                  </h4>
                  <span className="text-xs text-surface-500">12 Platforms Analyzed</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5 pt-1">
                  {(activeProfile.social_discovery || []).map((acc: any, idx: number) => {
                    const statusStyle = STATUS_STYLE[acc.status] || STATUS_STYLE.not_detected
                    const icon = PLATFORM_ICONS[acc.icon] || '🔗'

                    return (
                      <div
                        key={idx}
                        className={`rounded-xl border p-3 flex items-start gap-3 transition-all ${statusStyle}`}
                      >
                        <span className="text-lg flex-shrink-0 mt-0.5">{icon}</span>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-1 mb-0.5">
                            <span className="text-xs font-bold text-white truncate">{acc.platform}</span>
                            <span className={`text-[8px] uppercase font-bold px-1.5 py-0.5 rounded-full border ${statusStyle}`}>
                              {acc.status === 'found' || acc.status === 'detected' ? '✓ Found' : '—'}
                            </span>
                          </div>
                          <p className="text-[10px] opacity-80 truncate">{acc.details}</p>
                          {acc.profile_url && (
                            <a
                              href={acc.profile_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-[10px] text-brand-300 hover:underline mt-1 block truncate"
                            >
                              View Profile <ExternalLink className="inline h-2 w-2" />
                            </a>
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── TAB 5: Wayback Machine & Historical Footprint ── */}
      {activeTab === 'wayback' && (
        <div className="space-y-4">
          <div className="rounded-2xl border border-surface-800 bg-surface-900/70 p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>🏛️</span>
                <span>Wayback Machine — Internet Archive Historical Timeline</span>
              </h3>
              {internetIntel.wayback_machine?.archive_url && (
                <a
                  href={internetIntel.wayback_machine.archive_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-blue-600/20 text-blue-300 border border-blue-500/30 text-xs font-semibold hover:bg-blue-600/30 transition-all"
                >
                  Browse Full Archive <ExternalLink className="h-3 w-3" />
                </a>
              )}
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="rounded-xl border border-surface-800 bg-surface-950/70 p-3">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 block mb-0.5">Archive Status</span>
                <span className={`text-sm font-bold ${internetIntel.wayback_machine?.available ? 'text-emerald-400' : 'text-surface-500'}`}>
                  {internetIntel.wayback_machine?.available ? '✓ History Found' : 'No Snapshots'}
                </span>
              </div>
              <div className="rounded-xl border border-surface-800 bg-surface-950/70 p-3">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 block mb-0.5">Total Snapshots</span>
                <span className="text-sm font-bold text-white">{internetIntel.wayback_machine?.total_snapshots || 0}</span>
              </div>
              <div className="rounded-xl border border-surface-800 bg-surface-950/70 p-3">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 block mb-0.5">Estimated Age</span>
                <span className="text-sm font-bold text-brand-400">{internetIntel.domain_age_estimate || 'Active'}</span>
              </div>
              <div className="rounded-xl border border-surface-800 bg-surface-950/70 p-3">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-surface-500 block mb-0.5">First Recorded</span>
                <span className="text-sm font-bold text-white">{internetIntel.wayback_machine?.oldest_snapshot?.year || '—'}</span>
              </div>
            </div>

            {internetIntel.wayback_machine?.notable_years && internetIntel.wayback_machine.notable_years.length > 0 && (
              <div className="flex items-center gap-2 flex-wrap pt-2">
                <span className="text-[11px] font-semibold text-surface-400 uppercase">Archived Snapshots:</span>
                {internetIntel.wayback_machine.notable_years.map((year: string) => (
                  <a
                    key={year}
                    href={`https://web.archive.org/web/${year}/${targetDomain}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="rounded-lg bg-surface-800 px-2.5 py-1 text-xs text-surface-300 border border-surface-700 hover:text-white hover:border-surface-600 transition-colors"
                  >
                    {year}
                  </a>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── TAB 6: Reconnaissance Tools & Targeted Dorks ── */}
      {activeTab === 'recon_tools' && (
        <div className="space-y-6">
          {/* LinkedIn Targeted Employee Enumeration Dorks */}
          <div className="rounded-2xl border border-surface-800 bg-surface-900/70 p-6 space-y-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>💼</span>
                <span>LinkedIn Corporate Intelligence & Role Enumeration Dorks</span>
              </h3>
              <p className="text-xs text-surface-400 mt-0.5">
                Targeted search queries for uncovering executive leadership, engineering teams, and job posting disclosures.
              </p>
            </div>

            <div className="space-y-2.5">
              {(linkedinIntel.dorks || []).map((d: any, idx: number) => (
                <div
                  key={idx}
                  className="rounded-xl border border-surface-800 bg-surface-950/70 p-3.5 space-y-2 hover:border-surface-700 transition-all"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <span className="text-xs font-bold text-white block">{d.role_category}</span>
                      <span className="text-[11px] text-surface-400">{d.description}</span>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <button
                        onClick={() => copyToClipboard(d.dork, `li-dork-${idx}`)}
                        className="flex items-center gap-1 rounded-lg bg-surface-800 px-2.5 py-1 text-xs text-surface-300 hover:text-white border border-surface-700 transition-colors"
                      >
                        {copiedKey === `li-dork-${idx}` ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                        <span>{copiedKey === `li-dork-${idx}` ? 'Copied' : 'Copy Query'}</span>
                      </button>
                      <a
                        href={d.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 rounded-lg bg-blue-600/20 px-2.5 py-1 text-xs font-semibold text-blue-300 border border-blue-500/30 hover:bg-blue-600/30 transition-all"
                      >
                        <span>Search</span> <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                  <code className="block rounded-lg bg-surface-900/80 p-2 font-mono text-[10px] text-surface-400 border border-surface-800 overflow-x-auto">
                    {d.dork}
                  </code>
                </div>
              ))}
            </div>
          </div>

          {/* Google Dorks */}
          <div className="rounded-2xl border border-surface-800 bg-surface-900/70 p-6 space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span>🔍</span> Targeted Google Dorks Reconnaissance
            </h3>
            <div className="space-y-2">
              {dorks.map((d: any, idx: number) => (
                <div key={idx} className="rounded-xl border border-surface-800 bg-surface-950/70 p-3.5 flex items-center justify-between gap-4">
                  <div className="min-w-0">
                    <span className="text-xs font-bold text-white block">{d.category}</span>
                    <span className="font-mono text-[11px] text-surface-400 truncate block mt-0.5">{d.dork}</span>
                  </div>
                  <a
                    href={d.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 rounded-lg bg-brand-600/20 px-3 py-1.5 text-xs font-semibold text-brand-300 border border-brand-500/30 hover:bg-brand-600/30 transition-all flex-shrink-0"
                  >
                    <span>Execute</span> <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              ))}
            </div>
          </div>

          {/* GitHub Secret Leaks */}
          {githubRecon.length > 0 && (
            <div className="rounded-2xl border border-surface-800 bg-surface-900/70 p-6 space-y-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>🐙</span> GitHub Code & Secrets Exposure Reconnaissance
              </h3>
              <div className="space-y-2">
                {githubRecon.map((q: any, idx: number) => (
                  <div key={idx} className="rounded-xl border border-surface-800 bg-surface-950/70 p-3.5 flex items-center justify-between gap-4">
                    <div className="min-w-0">
                      <span className="text-xs font-bold text-white block">{q.description}</span>
                      <span className="font-mono text-[11px] text-surface-400 truncate block mt-0.5">{q.query}</span>
                    </div>
                    <a
                      href={q.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 rounded-lg bg-surface-800 px-3 py-1.5 text-xs font-semibold text-surface-300 border border-surface-700 hover:text-white transition-all flex-shrink-0"
                    >
                      <span>GitHub</span> <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Public Corporate Registers & Technical Lookups */}
          {internetIntel.infrastructure_intel && internetIntel.infrastructure_intel.length > 0 && (
            <div className="rounded-2xl border border-surface-800 bg-surface-900/70 p-6 space-y-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>🌐</span> Public Corporate Registers & Internet Intelligence Lookups
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
                {internetIntel.infrastructure_intel.slice(0, 8).map((item: any, idx: number) => (
                  <a
                    key={idx}
                    href={item.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="rounded-xl border border-surface-800 bg-surface-950/60 p-3 hover:border-surface-700 hover:bg-surface-950 transition-all flex items-start gap-2.5 group"
                  >
                    <span className="text-lg flex-shrink-0 mt-0.5">{item.icon}</span>
                    <div className="min-w-0 flex-1">
                      <span className="text-xs font-bold text-white group-hover:text-brand-300 transition-colors block truncate">
                        {item.name}
                      </span>
                      <span className="text-[10px] text-surface-500 block truncate">{item.category}</span>
                    </div>
                    <ExternalLink className="h-3 w-3 text-surface-600 group-hover:text-white flex-shrink-0 transition-colors mt-0.5" />
                  </a>
                ))}
              </div>
            </div>
          )}
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
