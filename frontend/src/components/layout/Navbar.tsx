// =============================================================================
// FootprintHub — Navbar Component
// =============================================================================

import { Link, useLocation } from 'react-router-dom'
import {
  Shield,
  History,
  LogOut,
  Sun,
  Moon,
  Menu,
  X,
} from 'lucide-react'
import { useState } from 'react'

interface NavbarProps {
  isAuthenticated: boolean
  darkMode: boolean
  onToggleTheme: () => void
  onLogout: () => void
}

export default function Navbar({
  isAuthenticated,
  darkMode,
  onToggleTheme,
  onLogout,
}: NavbarProps) {
  const location = useLocation()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const isActive = (path: string) => location.pathname === path

  return (
    <nav className="sticky top-0 z-50 glass-card border-b border-surface-800/50 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-2.5 group">
            <div className="relative">
              <Shield className="h-8 w-8 text-brand-500 group-hover:text-brand-400 transition-colors" />
              <div className="absolute inset-0 bg-brand-500/20 rounded-full blur-lg group-hover:bg-brand-400/30 transition-all" />
            </div>
            <span className="text-xl font-bold gradient-text">
              FootprintHub
            </span>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center gap-1">
            {isAuthenticated && (
              <>
                <Link
                  to="/"
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                    isActive('/')
                      ? 'bg-brand-500/15 text-brand-400'
                      : 'text-surface-400 hover:text-surface-100 hover:bg-surface-800/50'
                  }`}
                >
                  New Scan
                </Link>
                <Link
                  to="/history"
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 flex items-center gap-1.5 ${
                    isActive('/history')
                      ? 'bg-brand-500/15 text-brand-400'
                      : 'text-surface-400 hover:text-surface-100 hover:bg-surface-800/50'
                  }`}
                >
                  <History className="h-4 w-4" />
                  History
                </Link>
              </>
            )}

            <div className="w-px h-6 bg-surface-800 mx-2" />

            {/* Theme Toggle */}
            <button
              onClick={onToggleTheme}
              className="p-2 rounded-lg text-surface-400 hover:text-surface-100 hover:bg-surface-800/50 transition-all"
              title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {darkMode ? (
                <Sun className="h-5 w-5" />
              ) : (
                <Moon className="h-5 w-5" />
              )}
            </button>

            {/* Auth Actions */}
            {isAuthenticated ? (
              <button
                onClick={onLogout}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium text-surface-400 hover:text-red-400 hover:bg-red-500/10 transition-all"
              >
                <LogOut className="h-4 w-4" />
                Logout
              </button>
            ) : (
              <Link
                to="/login"
                className="px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-500 transition-all"
              >
                Sign In
              </Link>
            )}
          </div>

          {/* Mobile menu button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 rounded-lg text-surface-400 hover:text-surface-100"
          >
            {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
          </button>
        </div>

        {/* Mobile Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden py-4 space-y-2 animate-slide-up">
            {isAuthenticated && (
              <>
                <Link
                  to="/"
                  onClick={() => setMobileMenuOpen(false)}
                  className="block px-4 py-2 rounded-lg text-sm font-medium text-surface-300 hover:bg-surface-800/50"
                >
                  New Scan
                </Link>
                <Link
                  to="/history"
                  onClick={() => setMobileMenuOpen(false)}
                  className="block px-4 py-2 rounded-lg text-sm font-medium text-surface-300 hover:bg-surface-800/50"
                >
                  History
                </Link>
              </>
            )}
            <button
              onClick={onToggleTheme}
              className="w-full text-left px-4 py-2 rounded-lg text-sm font-medium text-surface-300 hover:bg-surface-800/50"
            >
              {darkMode ? '☀️ Light Mode' : '🌙 Dark Mode'}
            </button>
            {isAuthenticated ? (
              <button
                onClick={() => { onLogout(); setMobileMenuOpen(false) }}
                className="w-full text-left px-4 py-2 rounded-lg text-sm font-medium text-red-400 hover:bg-red-500/10"
              >
                Logout
              </button>
            ) : (
              <Link
                to="/login"
                onClick={() => setMobileMenuOpen(false)}
                className="block px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white text-center"
              >
                Sign In
              </Link>
            )}
          </div>
        )}
      </div>
    </nav>
  )
}
