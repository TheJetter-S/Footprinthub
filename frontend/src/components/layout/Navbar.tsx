// =============================================================================
// FootprintHub — Navbar Component (Matches User Design)
// =============================================================================

import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Menu, X, LogOut } from 'lucide-react'

interface NavbarProps {
  isAuthenticated: boolean
  darkMode?: boolean
  onToggleTheme?: () => void
  onLogout: () => void
}

export default function Navbar({
  isAuthenticated,
  onLogout,
}: NavbarProps) {
  const location = useLocation()
  const navigate = useNavigate()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const isActive = (path: string) => location.pathname === path

  return (
    <header className="border-b border-zinc-800/60 bg-zinc-950/80 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Logo */}
        <Link to="/" className="flex items-center gap-2 cursor-pointer group">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="text-indigo-500 group-hover:text-indigo-400 transition-colors"
          >
            <path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z" />
            <path d="M5 3v4" />
            <path d="M19 17v4" />
            <path d="M3 5h4" />
            <path d="M17 19h4" />
          </svg>
          <span className="text-zinc-50 font-semibold tracking-tight text-lg">
            FootprintHub
          </span>
        </Link>

        {/* Desktop Navigation */}
        <div className="flex items-center gap-6">
          <nav className="hidden md:flex gap-6 text-sm font-medium">
            <Link
              to="/"
              className={`transition-colors ${
                isActive('/') ? 'text-zinc-50 font-semibold' : 'text-zinc-400 hover:text-zinc-50'
              }`}
            >
              Scans
            </Link>
            <Link
              to="/history"
              className={`transition-colors ${
                isActive('/history') ? 'text-zinc-50 font-semibold' : 'text-zinc-400 hover:text-zinc-50'
              }`}
            >
              History
            </Link>
            <Link
              to="/history"
              className={`transition-colors ${
                location.pathname.startsWith('/scan/') ? 'text-zinc-50 font-semibold' : 'text-zinc-400 hover:text-zinc-50'
              }`}
            >
              Reports
            </Link>
            <Link
              to="/terms"
              className={`transition-colors ${
                isActive('/terms') ? 'text-zinc-50 font-semibold' : 'text-zinc-400 hover:text-zinc-50'
              }`}
            >
              Docs
            </Link>
          </nav>

          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/')}
              className="bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium py-2 px-4 rounded-md transition-all shadow-sm shadow-indigo-900/20 active:scale-95"
            >
              New scan
            </button>

            {isAuthenticated ? (
              <button
                onClick={onLogout}
                title="Sign out"
                className="hidden md:flex items-center gap-1.5 text-xs text-zinc-500 hover:text-red-400 py-1.5 px-2.5 rounded hover:bg-zinc-900 transition-colors"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Logout</span>
              </button>
            ) : (
              <Link
                to="/login"
                className="text-xs font-medium text-zinc-400 hover:text-zinc-200 transition-colors"
              >
                Sign In
              </Link>
            )}

            {/* Mobile menu toggle */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-2 text-zinc-400 hover:text-zinc-100"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Navigation Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-zinc-800/80 bg-zinc-950 px-4 py-3 space-y-2">
          <Link
            to="/"
            onClick={() => setMobileMenuOpen(false)}
            className="block py-2 text-sm text-zinc-300 hover:text-white"
          >
            Scans
          </Link>
          <Link
            to="/history"
            onClick={() => setMobileMenuOpen(false)}
            className="block py-2 text-sm text-zinc-300 hover:text-white"
          >
            History
          </Link>
          <Link
            to="/history"
            onClick={() => setMobileMenuOpen(false)}
            className="block py-2 text-sm text-zinc-300 hover:text-white"
          >
            Reports
          </Link>
          <Link
            to="/terms"
            onClick={() => setMobileMenuOpen(false)}
            className="block py-2 text-sm text-zinc-300 hover:text-white"
          >
            Docs
          </Link>
          {isAuthenticated && (
            <button
              onClick={() => {
                onLogout()
                setMobileMenuOpen(false)
              }}
              className="block w-full text-left py-2 text-sm text-red-400 hover:text-red-300"
            >
              Sign out
            </button>
          )}
        </div>
      )}
    </header>
  )
}
