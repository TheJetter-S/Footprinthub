// =============================================================================
// FootprintHub — Home Page (Scan Form)
// =============================================================================

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Globe,
  Loader2,
  CheckSquare,
  Square,
  Info,
  Zap,
  Radar,
  Lock,
} from 'lucide-react'
import { scansApi, ApiError } from '../api/client'

const PROFILES = [
  {
    id: 'passive',
    name: 'Passive',
    icon: Shield,
    description: 'OSINT only — no direct interaction with the target.',
    color: 'text-accent-green',
    border: 'border-accent-green/30',
    bg: 'bg-accent-green/5',
    recommended: true,
  },
  {
    id: 'standard',
    name: 'Standard',
    icon: Zap,
    description: 'Passive + minimal active checks (HTTP GET/HEAD).',
    color: 'text-brand-400',
    border: 'border-brand-400/30',
    bg: 'bg-brand-400/5',
  },
  {
    id: 'full',
    name: 'Full',
    icon: Radar,
    description: 'All checks including port scanning and brute force.',
    color: 'text-amber-400',
    border: 'border-amber-400/30',
    bg: 'bg-amber-400/5',
  },
]

export default function HomePage() {
  const navigate = useNavigate()
  const [domain, setDomain] = useState('')
  const [profile, setProfile] = useState('passive')
  const [authorized, setAuthorized] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!authorized) {
      setError('You must confirm authorization before scanning.')
      return
    }
    setError('')
    setLoading(true)

    try {
      const scan = await scansApi.create(domain, profile, authorized)
      navigate(`/scan/${scan.id}`)
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
      } else {
        setError('Failed to start scan. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-[calc(100vh-4rem)] flex flex-col items-center justify-center px-4 py-16">
      {/* Hero Section */}
      <div className="text-center mb-12 animate-fade-in">
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-brand-500/10 border border-brand-500/20 text-brand-400 text-sm font-medium mb-6">
          <Lock className="h-3.5 w-3.5" />
          Authorized Security Assessments Only
        </div>
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight mb-4">
          <span className="gradient-text">Discover Your</span>
          <br />
          <span className="text-surface-100">Digital Footprint</span>
        </h1>
        <p className="text-lg text-surface-400 max-w-2xl mx-auto text-balance">
          Enter a domain to perform comprehensive reconnaissance across DNS,
          subdomains, SSL, web technologies, OSINT, and more — all in one dashboard.
        </p>
      </div>

      {/* Scan Form */}
      <div className="w-full max-w-2xl animate-slide-up">
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Domain Input */}
          <div className="relative group">
            <div className="absolute inset-0 bg-gradient-to-r from-brand-500/20 via-accent-purple/20 to-accent-cyan/20 rounded-2xl blur-xl opacity-0 group-focus-within:opacity-100 transition-opacity duration-500" />
            <div className="relative glass-card p-2 flex items-center gap-2">
              <Globe className="h-5 w-5 text-surface-500 ml-4 flex-shrink-0" />
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="Enter a domain (e.g., example.com)"
                required
                className="flex-1 px-2 py-3 bg-transparent text-lg text-surface-100 placeholder-surface-500 focus:outline-none font-mono"
              />
              <button
                type="submit"
                disabled={loading || !domain || !authorized}
                className="flex items-center gap-2 px-6 py-3 rounded-xl bg-brand-600 text-white font-semibold hover:bg-brand-500 disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200 glow-hover"
              >
                {loading ? (
                  <Loader2 className="h-5 w-5 animate-spin" />
                ) : (
                  <>
                    <Search className="h-5 w-5" />
                    Scan
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm animate-slide-up">
              {error}
            </div>
          )}

          {/* Scan Profile Selector */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {PROFILES.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => setProfile(p.id)}
                className={`relative p-4 rounded-xl border text-left transition-all duration-200 ${
                  profile === p.id
                    ? `${p.bg} ${p.border} ring-1 ring-${p.color.replace('text-', '')}/20`
                    : 'border-surface-800 hover:border-surface-700 bg-surface-900/30'
                }`}
              >
                {p.recommended && (
                  <span className="absolute -top-2.5 right-3 px-2 py-0.5 rounded-full bg-accent-green/15 border border-accent-green/30 text-accent-green text-[10px] font-semibold uppercase">
                    Recommended
                  </span>
                )}
                <p.icon className={`h-5 w-5 mb-2 ${profile === p.id ? p.color : 'text-surface-500'}`} />
                <p className={`font-semibold text-sm ${profile === p.id ? 'text-surface-100' : 'text-surface-300'}`}>
                  {p.name}
                </p>
                <p className="text-xs text-surface-500 mt-1">{p.description}</p>
              </button>
            ))}
          </div>

          {/* Authorization Checkbox */}
          <div
            className={`p-4 rounded-xl border transition-all duration-200 ${
              authorized
                ? 'bg-accent-green/5 border-accent-green/30'
                : 'bg-surface-900/30 border-surface-800'
            }`}
          >
            <label className="flex items-start gap-3 cursor-pointer">
              <button
                type="button"
                onClick={() => setAuthorized(!authorized)}
                className="mt-0.5 flex-shrink-0"
              >
                {authorized ? (
                  <CheckSquare className="h-5 w-5 text-accent-green" />
                ) : (
                  <Square className="h-5 w-5 text-surface-500" />
                )}
              </button>
              <div>
                <p className="text-sm font-medium text-surface-200">
                  I confirm that I own this domain or have explicit written permission to perform this security assessment.
                </p>
                <p className="text-xs text-surface-500 mt-1 flex items-center gap-1">
                  <Info className="h-3 w-3" />
                  This confirmation is logged with your IP address and timestamp.
                </p>
              </div>
            </label>
          </div>
        </form>
      </div>

      {/* Module Overview */}
      <div className="mt-16 w-full max-w-4xl animate-fade-in">
        <p className="text-center text-sm font-medium text-surface-500 uppercase tracking-wider mb-6">
          10 Reconnaissance Modules
        </p>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[
            { name: 'DNS', icon: '🌐' },
            { name: 'Subdomains', icon: '🔍' },
            { name: 'IP & Network', icon: '📡' },
            { name: 'Web Tech', icon: '⚙️' },
            { name: 'SSL/TLS', icon: '🔒' },
            { name: 'Content', icon: '📄' },
            { name: 'Ports', icon: '🚪' },
            { name: 'OSINT', icon: '🕵️' },
            { name: 'Cloud', icon: '☁️' },
            { name: 'Reputation', icon: '⭐' },
          ].map((mod) => (
            <div
              key={mod.name}
              className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-surface-900/40 border border-surface-800/50 text-sm text-surface-300"
            >
              <span>{mod.icon}</span>
              <span>{mod.name}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
