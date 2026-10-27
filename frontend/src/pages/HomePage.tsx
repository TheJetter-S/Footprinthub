// =============================================================================
// FootprintHub — Home Page (Matches Requested UI Design)
// =============================================================================

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2, AlertCircle } from 'lucide-react'
import { scansApi, ApiError } from '../api/client'

export default function HomePage() {
  const navigate = useNavigate()
  const [domain, setDomain] = useState('')
  const [profile, setProfile] = useState<'passive' | 'standard' | 'full'>('passive')
  const [authorized, setAuthorized] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault()
    const cleanDomain = domain.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '')
    
    if (!cleanDomain) {
      setError('Please enter a target domain name.')
      return
    }

    if (!authorized) {
      setError('You must confirm authorization before scanning.')
      return
    }

    setError('')
    setLoading(true)

    try {
      const scan = await scansApi.create(cleanDomain, profile, authorized)
      navigate(`/scan/${scan.id}`)
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
      } else {
        setError('Failed to start scan. Please verify target and backend connection.')
      }
    } finally {
      setLoading(false)
    }
  }

  // Display target in sample preview
  const displayTarget = domain.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '') || 'example.com'

  return (
    <main className="flex-grow max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full pt-16 pb-24">
      {/* Hero Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 items-start">
        {/* Left Column */}
        <div className="lg:col-span-7 flex flex-col items-start pt-4">
          <span className="inline-flex items-center gap-2 rounded-full border border-indigo-500/20 bg-indigo-500/10 px-3 py-1 text-xs font-medium text-indigo-400 uppercase tracking-widest mb-6">
            For authorized security assessments
          </span>

          <h1 className="text-4xl sm:text-5xl md:text-6xl font-extrabold tracking-tight text-zinc-50 leading-[1.1]">
            Map your external <br className="hidden sm:block" />
            attack surface in one scan.
          </h1>

          <p className="mt-6 text-lg max-w-2xl leading-relaxed text-zinc-400">
            Enter a domain and FootprintHub gathers DNS, subdomains, certificates, web technologies, exposed services and public intelligence into a single prioritized report.
          </p>

          {/* Action Area */}
          <form
            onSubmit={handleStartScan}
            className="w-full max-w-2xl mt-10 p-1.5 rounded-xl border border-zinc-800/80 bg-zinc-900/50 backdrop-blur shadow-sm shadow-black/50"
          >
            {/* Input Bar */}
            <div className="flex items-center w-full gap-2 mb-4 p-1">
              <div className="relative flex-grow flex items-center bg-zinc-950/50 border border-zinc-800 rounded-lg overflow-hidden focus-within:border-indigo-500/50 focus-within:ring-1 focus-within:ring-indigo-500/50 transition-all">
                <span className="pl-4 text-zinc-500 text-sm font-mono select-none">https://</span>
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => {
                    setDomain(e.target.value)
                    if (error) setError('')
                  }}
                  placeholder="example.com"
                  className="w-full bg-transparent text-zinc-50 text-sm py-3 px-2 outline-none placeholder-zinc-600 font-mono"
                  disabled={loading}
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium py-3 px-6 rounded-lg text-sm transition-all whitespace-nowrap active:scale-95 shadow-lg shadow-indigo-900/20 flex items-center gap-2"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Scanning...</span>
                  </>
                ) : (
                  <span>Start scan</span>
                )}
              </button>
            </div>

            {/* Error Message */}
            {error && (
              <div className="mx-1 mb-3 p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Scan Options */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-1">
              {/* Passive (Recommended) */}
              <div
                onClick={() => setProfile('passive')}
                className={`relative rounded-lg p-4 cursor-pointer transition-all ${
                  profile === 'passive'
                    ? 'border border-indigo-500/50 bg-indigo-500/5 hover:bg-indigo-500/10'
                    : 'border border-zinc-800/80 bg-zinc-950/50 hover:border-zinc-700 hover:bg-zinc-900'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span
                    className={`text-sm ${
                      profile === 'passive' ? 'font-semibold text-zinc-50' : 'font-medium text-zinc-300'
                    }`}
                  >
                    Passive
                  </span>
                  <span className="text-[10px] font-medium bg-indigo-500/20 text-indigo-400 px-1.5 py-0.5 rounded">
                    Recommended
                  </span>
                </div>
                <p className={`text-xs ${profile === 'passive' ? 'text-zinc-400' : 'text-zinc-500'}`}>
                  Public sources only. No contact with the target.
                </p>
              </div>

              {/* Standard */}
              <div
                onClick={() => setProfile('standard')}
                className={`relative rounded-lg p-4 cursor-pointer transition-all ${
                  profile === 'standard'
                    ? 'border border-indigo-500/50 bg-indigo-500/5 hover:bg-indigo-500/10'
                    : 'border border-zinc-800/80 bg-zinc-950/50 hover:border-zinc-700 hover:bg-zinc-900'
                }`}
              >
                <div className="mb-1">
                  <span
                    className={`text-sm ${
                      profile === 'standard' ? 'font-semibold text-zinc-50' : 'font-medium text-zinc-300'
                    }`}
                  >
                    Standard
                  </span>
                </div>
                <p className={`text-xs ${profile === 'standard' ? 'text-zinc-400' : 'text-zinc-500'}`}>
                  Passive plus light HTTP GET/HEAD checks.
                </p>
              </div>

              {/* Full */}
              <div
                onClick={() => setProfile('full')}
                className={`relative rounded-lg p-4 cursor-pointer transition-all ${
                  profile === 'full'
                    ? 'border border-indigo-500/50 bg-indigo-500/5 hover:bg-indigo-500/10'
                    : 'border border-zinc-800/80 bg-zinc-950/50 hover:border-zinc-700 hover:bg-zinc-900'
                }`}
              >
                <div className="mb-1">
                  <span
                    className={`text-sm ${
                      profile === 'full' ? 'font-semibold text-zinc-50' : 'font-medium text-zinc-300'
                    }`}
                  >
                    Full
                  </span>
                </div>
                <p className={`text-xs ${profile === 'full' ? 'text-zinc-400' : 'text-zinc-500'}`}>
                  Adds port scanning and deeper active checks.
                </p>
              </div>
            </div>
          </form>

          {/* Authorization Checkbox */}
          <label className="mt-4 flex items-start gap-2.5 max-w-xl pl-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              className="mt-0.5 h-3.5 w-3.5 rounded border-zinc-700 bg-zinc-900 text-indigo-600 focus:ring-indigo-500 focus:ring-offset-0 cursor-pointer"
            />
            <span className="text-[11px] text-zinc-500 hover:text-zinc-400 transition-colors leading-relaxed">
              I own this domain or have written permission to assess it. This confirmation is logged with my IP address and timestamp.
            </span>
          </label>
        </div>

        {/* Right Column (Widget) */}
        <div className="lg:col-span-5 relative mt-8 lg:mt-0">
          {/* Decorative glow behind card */}
          <div className="absolute -inset-0.5 bg-gradient-to-br from-indigo-500/20 to-zinc-900/0 rounded-2xl blur-xl opacity-50 pointer-events-none" />

          <div className="relative rounded-2xl border border-zinc-800 bg-[#121214] p-6 lg:p-8 shadow-2xl shadow-black/80">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xs font-semibold text-zinc-400 tracking-wider uppercase">
                Sample Report &middot; Illustrative
              </h3>
              <span className="text-xs font-mono text-zinc-500 truncate max-w-[180px]">
                {displayTarget}
              </span>
            </div>

            <div className="flex items-end gap-3">
              <span className="text-6xl font-bold tracking-tighter text-amber-500 leading-none">
                62
              </span>
              <span className="text-sm text-zinc-500 font-medium mb-1.5">
                / 100 risk score
              </span>
            </div>

            {/* Progress Bar */}
            <div className="w-full h-1.5 bg-zinc-800/80 rounded-full mt-6 overflow-hidden">
              <div className="h-full bg-amber-500 rounded-full w-[62%]" />
            </div>

            {/* Findings List */}
            <div className="mt-8 flex flex-col">
              <div className="flex items-center justify-between py-3.5 border-b border-zinc-800/60">
                <span className="text-sm font-medium text-zinc-300">
                  Missing HSTS header
                </span>
                <span className="text-xs font-medium text-amber-400 bg-amber-400/10 px-2 py-0.5 rounded border border-amber-400/20">
                  Medium
                </span>
              </div>
              <div className="flex items-center justify-between py-3.5 border-b border-zinc-800/60">
                <span className="text-sm font-medium text-zinc-300">
                  TLS 1.0 still enabled
                </span>
                <span className="text-xs font-medium text-red-400 bg-red-400/10 px-2 py-0.5 rounded border border-red-400/20">
                  High
                </span>
              </div>
              <div className="flex items-center justify-between py-3.5 border-b border-zinc-800/60">
                <span className="text-sm font-medium text-zinc-300">
                  DMARC policy set to none
                </span>
                <span className="text-xs font-medium text-amber-400 bg-amber-400/10 px-2 py-0.5 rounded border border-amber-400/20">
                  Medium
                </span>
              </div>
              <div className="flex items-center justify-between py-3.5">
                <span className="text-sm font-medium text-zinc-300">
                  Certificate valid, 62 days left
                </span>
                <span className="text-xs font-medium text-indigo-400 bg-indigo-400/10 px-2 py-0.5 rounded border border-indigo-400/20">
                  Info
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <div className="mt-32">
        <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-zinc-50">
          Ten reconnaissance modules
        </h2>
        <p className="mt-2 text-sm text-zinc-400">
          Each module is labeled passive or active, so you always know what touches the target.
        </p>

        <div className="mt-10 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {/* Card 1: DNS */}
          <div className="group bg-[#121214] border border-zinc-800/80 rounded-xl p-5 hover:bg-zinc-900 transition-all hover:border-zinc-700">
            <svg
              className="w-6 h-6 text-indigo-400 mb-4 group-hover:scale-110 transition-transform"
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="12" cy="12" r="10" />
              <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
              <path d="M2 12h20" />
            </svg>
            <h3 className="text-sm font-semibold text-zinc-100">DNS</h3>
            <p className="mt-2 text-xs text-zinc-500 leading-relaxed">
              Records, WHOIS, SPF/DKIM/DMARC, zone transfer
            </p>
          </div>

          {/* Card 2: Subdomains */}
          <div className="group bg-[#121214] border border-zinc-800/80 rounded-xl p-5 hover:bg-zinc-900 transition-all hover:border-zinc-700">
            <svg
              className="w-6 h-6 text-indigo-400 mb-4 group-hover:scale-110 transition-transform"
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M18 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-3.9a2 2 0 0 1-1.69-.9L10.8 2.1A2 2 0 0 0 9.11 1.2H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12Z" />
              <path d="M14 14h-4v-4" />
              <path d="M10 14h-2" />
            </svg>
            <h3 className="text-sm font-semibold text-zinc-100">Subdomains</h3>
            <p className="mt-2 text-xs text-zinc-500 leading-relaxed">
              Certificate logs, passive DNS, takeover checks
            </p>
          </div>

          {/* Card 3: IP & Network */}
          <div className="group bg-[#121214] border border-zinc-800/80 rounded-xl p-5 hover:bg-zinc-900 transition-all hover:border-zinc-700">
            <svg
              className="w-6 h-6 text-indigo-400 mb-4 group-hover:scale-110 transition-transform"
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
              <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
              <line x1="6" y1="6" x2="6.01" y2="6" />
              <line x1="6" y1="18" x2="6.01" y2="18" />
            </svg>
            <h3 className="text-sm font-semibold text-zinc-100">IP & Network</h3>
            <p className="mt-2 text-xs text-zinc-500 leading-relaxed">
              ASN, hosting, CIDR ranges, CDN and WAF
            </p>
          </div>

          {/* Card 4: Web Tech */}
          <div className="group bg-[#121214] border border-zinc-800/80 rounded-xl p-5 hover:bg-zinc-900 transition-all hover:border-zinc-700">
            <svg
              className="w-6 h-6 text-indigo-400 mb-4 group-hover:scale-110 transition-transform"
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <polyline points="16 18 22 12 16 6" />
              <polyline points="8 6 2 12 8 18" />
            </svg>
            <h3 className="text-sm font-semibold text-zinc-100">Web Tech</h3>
            <p className="mt-2 text-xs text-zinc-500 leading-relaxed">
              Frameworks, CMS, headers, cookie flags
            </p>
          </div>

          {/* Card 5: SSL/TLS */}
          <div className="group bg-[#121214] border border-zinc-800/80 rounded-xl p-5 hover:bg-zinc-900 transition-all hover:border-zinc-700">
            <svg
              className="w-6 h-6 text-indigo-400 mb-4 group-hover:scale-110 transition-transform"
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            <h3 className="text-sm font-semibold text-zinc-100">SSL/TLS</h3>
            <p className="mt-2 text-xs text-zinc-500 leading-relaxed">
              Certificates, protocols, cipher strength
            </p>
          </div>

          {/* Card 6: Content */}
          <div className="group bg-[#121214] border border-zinc-800/80 rounded-xl p-5 hover:bg-zinc-900 transition-all hover:border-zinc-700">
            <svg
              className="w-6 h-6 text-indigo-400 mb-4 group-hover:scale-110 transition-transform"
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="16" y1="13" x2="8" y2="13" />
              <line x1="16" y1="17" x2="8" y2="17" />
              <line x1="10" y1="9" x2="8" y2="9" />
            </svg>
            <h3 className="text-sm font-semibold text-zinc-100">Content</h3>
            <p className="mt-2 text-xs text-zinc-500 leading-relaxed">
              robots.txt, sitemaps, exposed paths, history
            </p>
          </div>

          {/* Card 7: Ports */}
          <div className="group bg-[#121214] border border-zinc-800/80 rounded-xl p-5 hover:bg-zinc-900 transition-all hover:border-zinc-700">
            <svg
              className="w-6 h-6 text-indigo-400 mb-4 group-hover:scale-110 transition-transform"
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22v-4" />
              <path d="M12 8V4" />
              <path d="M22 12h-4" />
              <path d="M8 12H4" />
              <circle cx="12" cy="12" r="4" />
            </svg>
            <h3 className="text-sm font-semibold text-zinc-100">Ports</h3>
            <p className="mt-2 text-xs text-zinc-500 leading-relaxed">
              Service banners and CVE matching
            </p>
          </div>

          {/* Card 8: OSINT */}
          <div className="group bg-[#121214] border border-zinc-800/80 rounded-xl p-5 hover:bg-zinc-900 transition-all hover:border-zinc-700">
            <svg
              className="w-6 h-6 text-indigo-400 mb-4 group-hover:scale-110 transition-transform"
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            <h3 className="text-sm font-semibold text-zinc-100">OSINT</h3>
            <p className="mt-2 text-xs text-zinc-500 leading-relaxed">
              Public emails, breach exposure, code leaks
            </p>
          </div>

          {/* Card 9: Cloud */}
          <div className="group bg-[#121214] border border-zinc-800/80 rounded-xl p-5 hover:bg-zinc-900 transition-all hover:border-zinc-700">
            <svg
              className="w-6 h-6 text-indigo-400 mb-4 group-hover:scale-110 transition-transform"
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" />
            </svg>
            <h3 className="text-sm font-semibold text-zinc-100">Cloud</h3>
            <p className="mt-2 text-xs text-zinc-500 leading-relaxed">
              Public storage bucket exposure
            </p>
          </div>

          {/* Card 10: Reputation */}
          <div className="group bg-[#121214] border border-zinc-800/80 rounded-xl p-5 hover:bg-zinc-900 transition-all hover:border-zinc-700">
            <svg
              className="w-6 h-6 text-indigo-400 mb-4 group-hover:scale-110 transition-transform"
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
            <h3 className="text-sm font-semibold text-zinc-100">Reputation</h3>
            <p className="mt-2 text-xs text-zinc-500 leading-relaxed">
              Blocklists and threat intelligence
            </p>
          </div>
        </div>
      </div>
    </main>
  )
}
