// =============================================================================
// FootprintHub — History Page
// =============================================================================

import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  Globe,
  Clock,
  Shield,
  ChevronRight,
  Loader2,
  Trash2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
} from 'lucide-react'
import { scansApi, ScanResponse } from '../api/client'

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)

  useEffect(() => {
    loadScans()
  }, [page])

  const loadScans = async () => {
    setLoading(true)
    try {
      const data = await scansApi.list(page, 20)
      setScans(data.scans)
      setTotal(data.total)
    } catch {
      // Handle silently
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (scanId: string) => {
    if (!confirm('Are you sure you want to delete this scan?')) return
    try {
      await scansApi.delete(scanId)
      setScans(scans.filter((s) => s.id !== scanId))
    } catch {
      // Handle silently
    }
  }

  const totalPages = Math.ceil(total / 20)

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 animate-fade-in">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-surface-100">Scan History</h1>
          <p className="text-surface-400 text-sm mt-1">
            {total} scan{total !== 1 ? 's' : ''} recorded
          </p>
        </div>
        <Link
          to="/"
          className="px-4 py-2 rounded-lg bg-brand-600 text-white text-sm font-medium hover:bg-brand-500 transition-all"
        >
          New Scan
        </Link>
      </div>

      {loading ? (
        <div className="flex justify-center py-20">
          <Loader2 className="h-8 w-8 text-brand-500 animate-spin" />
        </div>
      ) : scans.length === 0 ? (
        <div className="text-center py-20 glass-card rounded-xl">
          <Globe className="h-12 w-12 text-surface-600 mx-auto mb-4" />
          <p className="text-surface-400 text-lg">No scans yet</p>
          <p className="text-surface-500 text-sm mt-1">
            Start your first scan from the home page.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {scans.map((scan) => (
            <Link
              key={scan.id}
              to={`/scan/${scan.id}`}
              className="block glass-card p-5 hover:bg-surface-800/30 transition-all duration-200 group glow-hover"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4 min-w-0">
                  <div className="p-2.5 rounded-lg bg-brand-500/10 border border-brand-500/20 flex-shrink-0">
                    <Globe className="h-5 w-5 text-brand-400" />
                  </div>
                  <div className="min-w-0">
                    <p className="font-semibold text-surface-100 font-mono truncate">
                      {scan.domain}
                    </p>
                    <div className="flex items-center gap-3 mt-1 text-xs text-surface-500">
                      <span className="flex items-center gap-1">
                        <Shield className="h-3 w-3" />
                        {scan.profile}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {new Date(scan.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {/* Risk Score */}
                  {scan.risk_score !== null && (
                    <span
                      className={`text-lg font-bold font-mono ${
                        scan.risk_score >= 76
                          ? 'text-red-400'
                          : scan.risk_score >= 51
                          ? 'text-orange-400'
                          : scan.risk_score >= 21
                          ? 'text-amber-400'
                          : 'text-accent-green'
                      }`}
                    >
                      {scan.risk_score}
                    </span>
                  )}
                  {/* Status */}
                  <span
                    className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium ${
                      scan.status === 'completed'
                        ? 'bg-accent-green/15 text-accent-green'
                        : scan.status === 'running'
                        ? 'bg-brand-500/15 text-brand-400'
                        : 'bg-red-500/15 text-red-400'
                    }`}
                  >
                    {scan.status === 'completed' && <CheckCircle2 className="h-3 w-3" />}
                    {scan.status === 'running' && <Loader2 className="h-3 w-3 animate-spin" />}
                    {scan.status === 'failed' && <XCircle className="h-3 w-3" />}
                    {scan.status}
                  </span>
                  <button
                    onClick={(e) => {
                      e.preventDefault()
                      handleDelete(scan.id)
                    }}
                    className="p-1.5 rounded-lg text-surface-600 hover:text-red-400 hover:bg-red-500/10 transition-all opacity-0 group-hover:opacity-100"
                    title="Delete scan"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                  <ChevronRight className="h-5 w-5 text-surface-600 group-hover:text-surface-400 transition-colors" />
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2 mt-8">
          {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => (
            <button
              key={p}
              onClick={() => setPage(p)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                p === page
                  ? 'bg-brand-600 text-white'
                  : 'text-surface-400 hover:bg-surface-800'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
