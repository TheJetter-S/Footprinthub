// =============================================================================
// FootprintHub — Terms of Use Page
// =============================================================================

import { Link } from 'react-router-dom'
import { Shield, ArrowLeft } from 'lucide-react'

export default function TermsPage() {
  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-12 animate-fade-in">
      <Link
        to="/"
        className="inline-flex items-center gap-1.5 text-sm text-surface-400 hover:text-surface-200 mb-8 transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Home
      </Link>

      <div className="glass-card p-8 sm:p-12">
        <div className="flex items-center gap-3 mb-8">
          <Shield className="h-8 w-8 text-brand-500" />
          <h1 className="text-2xl font-bold text-surface-100">Terms of Use</h1>
        </div>

        <div className="prose prose-invert prose-sm max-w-none space-y-6 text-surface-300">
          <section>
            <h2 className="text-lg font-semibold text-surface-100">1. Authorized Use Only</h2>
            <p>
              FootprintHub is a security assessment tool designed <strong>exclusively</strong> for
              authorized security testing and reconnaissance. By using this platform, you agree
              that you will <strong>only scan domains that you own or have explicit written
              permission to test</strong>.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-surface-100">2. Prohibited Activities</h2>
            <p>The following activities are strictly prohibited:</p>
            <ul className="list-disc list-inside space-y-1 ml-2">
              <li>Scanning domains without authorization</li>
              <li>Using the tool for malicious purposes or unauthorized access</li>
              <li>Attempting to exploit vulnerabilities discovered through this tool</li>
              <li>Denial-of-service attacks or brute-force credential attacks</li>
              <li>Circumventing rate limits or security controls</li>
              <li>Scraping or automated bulk scanning without permission</li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-surface-100">3. Logging & Accountability</h2>
            <p>
              All scan requests are logged with your user account, IP address, and timestamp.
              The authorization confirmation you provide before each scan constitutes a digital
              attestation that you are authorized to perform the assessment. These logs may be
              provided to law enforcement if illegal activity is detected.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-surface-100">4. Disclaimer</h2>
            <p>
              FootprintHub is provided "as is" without warranty of any kind. The developers are
              not responsible for any damages resulting from the use or misuse of this tool.
              Results are for informational purposes only and should be validated by qualified
              security professionals.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-surface-100">5. Data Handling</h2>
            <p>
              Scan results are stored encrypted and are accessible only to the authenticated user
              who initiated the scan. API keys provided by users are encrypted at rest. We do not
              sell or share scan data with third parties.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-surface-100">6. Compliance</h2>
            <p>
              Users are responsible for ensuring their use of FootprintHub complies with all
              applicable local, state, federal, and international laws, including but not limited
              to the Computer Fraud and Abuse Act (CFAA), GDPR, and equivalent legislation in
              their jurisdiction.
            </p>
          </section>

          <div className="pt-6 border-t border-surface-800">
            <p className="text-xs text-surface-500">
              Last updated: October 2026. By using FootprintHub, you acknowledge and agree to
              these terms.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
