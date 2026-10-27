// =============================================================================
// FootprintHub — Footer Component (Matches User Design)
// =============================================================================

import { Link } from 'react-router-dom'

export default function Footer() {
  return (
    <footer className="border-t border-zinc-800/60 mt-auto bg-zinc-950/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex flex-col md:flex-row items-center justify-between gap-4">
        <p className="text-xs text-zinc-500">
          FootprintHub &middot; Use only on systems you are authorized to test.
        </p>
        <div className="flex items-center gap-4 text-xs font-medium text-zinc-500">
          <Link to="/terms" className="hover:text-zinc-300 transition-colors">
            Terms of use
          </Link>
          <Link to="/terms" className="hover:text-zinc-300 transition-colors">
            Privacy
          </Link>
        </div>
      </div>
    </footer>
  )
}
