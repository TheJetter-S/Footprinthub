// =============================================================================
// FootprintHub — Public Read-Only Tokenized Report View
// =============================================================================

import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { Shield, AlertTriangle, CheckCircle, ExternalLink, Award } from 'lucide-react'
import { sharesApi } from '../api/client'

export default function PublicReportPage() {
  const { token } = useParams<{ token: string }>()
  const [report, setReport] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (token) {
      loadReport(token)
    }
  }, [token])

  const loadReport = async (t: string) => {
    setLoading(true)
    setError(null)
    try {
      const data = await sharesApi.getPublic(t)
      setReport(data)
    } catch (e: any) {
      setError(e.message || 'Report not found, expired, or revoked.')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center text-zinc-400 font-mono text-sm">
        Loading verified reconnaissance report...
      </div>
    )
  }

  if (error || !report) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-zinc-900 border border-zinc-800 rounded-xl p-6 text-center space-y-3">
          <AlertTriangle className="w-10 h-10 text-amber-500 mx-auto" />
          <h2 className="text-lg font-semibold text-zinc-100">Unable to View Report</h2>
          <p className="text-xs text-zinc-400">{error || 'This report link is invalid, revoked, or has expired.'}</p>
        </div>
      </div>
    )
  }

  const branding = report.branding || {}
  const exec = report.executive_summary || {}
  const grade = exec.security_grade || 'C'
  const score = report.risk_score || 0
  const findings = report.findings || []

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-4 sm:p-8">
      <div className="max-w-5xl mx-auto space-y-6">
        {/* Custom White-Label Header */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-zinc-800 pb-4">
          <div className="flex items-center gap-3">
            {branding.logo_url ? (
              <img src={branding.logo_url} alt="Logo" className="h-9 w-auto object-contain rounded" />
            ) : (
              <img src="/footprinthub-icon.svg" alt="FootprintHub" className="w-9 h-9 object-contain" />
            )}
            <div>
              <h1 className="text-lg font-bold text-zinc-100">{branding.company_name || 'FootprintHub Security'}</h1>
              <p className="text-xs text-zinc-400">Verified Perimeter Reconnaissance & Assessment</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono bg-zinc-900 border border-zinc-800 px-3 py-1.5 rounded-lg">
            <span className="text-zinc-400">Target:</span>
            <span className="font-semibold text-zinc-100">{report.domain}</span>
            <span className="text-zinc-600">|</span>
            <span className="text-indigo-400 uppercase">{report.profile} Mode</span>
          </div>
        </div>

        {/* Executive Summary Card */}
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6 space-y-4">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
            <div>
              <span className="text-xs uppercase tracking-wider text-zinc-400 font-mono">Executive Security Briefing</span>
              <h2 className="text-xl font-bold text-zinc-50 mt-0.5">Overall Security Posture: {exec.risk_posture}</h2>
            </div>
            <div className="flex items-center gap-3">
              <div className="px-4 py-2 bg-zinc-950 border border-zinc-800 rounded-lg text-center">
                <span className="block text-[10px] text-zinc-500 uppercase font-mono">Security Grade</span>
                <span className="text-2xl font-black text-indigo-400">{grade}</span>
              </div>
              <div className="px-4 py-2 bg-zinc-950 border border-zinc-800 rounded-lg text-center">
                <span className="block text-[10px] text-zinc-500 uppercase font-mono">Risk Score</span>
                <span className="text-2xl font-black text-zinc-100">{score}<span className="text-xs text-zinc-500">/100</span></span>
              </div>
            </div>
          </div>

          <p className="text-sm text-zinc-300 leading-relaxed bg-zinc-950/60 p-4 rounded-lg border border-zinc-800/80">
            {exec.executive_narrative}
          </p>

          {/* Top 5 Fixes */}
          {exec.top_prioritized_fixes && exec.top_prioritized_fixes.length > 0 && (
            <div className="space-y-2 pt-2">
              <h3 className="text-xs font-semibold uppercase text-zinc-400 font-mono">Prioritized Leadership Actions</h3>
              <div className="space-y-2">
                {exec.top_prioritized_fixes.map((tf: any, i: number) => (
                  <div key={i} className="p-3 bg-zinc-950/70 border border-zinc-800 rounded-lg flex flex-col sm:flex-row justify-between gap-3 text-xs">
                    <div>
                      <span className={`inline-block px-2 py-0.5 rounded font-bold uppercase mr-2 ${
                        tf.severity === 'critical' ? 'bg-red-950 text-red-400 border border-red-800' :
                        tf.severity === 'high' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                        'bg-zinc-800 text-zinc-300'
                      }`}>
                        {tf.severity}
                      </span>
                      <strong className="text-zinc-200">{tf.title}</strong>
                      <p className="text-zinc-400 mt-1">{tf.business_impact}</p>
                    </div>
                    <div className="sm:max-w-xs text-zinc-300 bg-zinc-900/60 p-2 rounded border border-zinc-800 text-[11px] self-start sm:self-center">
                      <strong className="text-indigo-400 block mb-0.5">Remediation:</strong>
                      {tf.remediation_action}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Findings Catalog */}
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-zinc-800 flex justify-between items-center">
            <h3 className="text-sm font-semibold text-zinc-200">Cataloged Security Findings ({findings.length})</h3>
            <span className="text-xs text-zinc-500 font-mono">Filtered View</span>
          </div>
          <div className="divide-y divide-zinc-800">
            {findings.map((f: any) => (
              <div key={f.id} className="p-5 space-y-2 hover:bg-zinc-800/20 transition-colors">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase font-mono ${
                    f.severity === 'critical' ? 'bg-red-950 text-red-400 border border-red-800' :
                    f.severity === 'high' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                    f.severity === 'medium' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                    'bg-zinc-800 text-zinc-300'
                  }`}>
                    {f.severity}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-zinc-800 text-zinc-400">
                    Confidence: {f.confidence}
                  </span>
                  <span className="text-xs text-zinc-500 font-mono">Module: {f.module_name}</span>
                  <h4 className="font-semibold text-sm text-zinc-100 flex-1">{f.title}</h4>
                </div>
                <p className="text-xs text-zinc-300 leading-relaxed">{f.description}</p>
                {f.evidence && (
                  <div className="bg-black/40 border border-zinc-800/80 rounded px-2.5 py-1.5 font-mono text-[11px] text-zinc-400">
                    <span className="text-zinc-500">Evidence:</span> {f.evidence}
                  </div>
                )}
                {f.remediation && (
                  <div className="text-xs text-indigo-300 bg-indigo-950/30 border border-indigo-900/40 rounded p-2">
                    <strong>Recommended Fix:</strong> {f.remediation}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="text-center text-xs text-zinc-500 py-6 border-t border-zinc-800">
          <p>{branding.footer_text || 'Confidential Reconnaissance & Security Assessment Report'}</p>
        </div>
      </div>
    </div>
  )
}

