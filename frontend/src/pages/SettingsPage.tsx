// =============================================================================
// FootprintHub — Settings & Automation Page
// =============================================================================

import { useState, useEffect } from 'react'
import {
  Bell,
  Clock,
  Key,
  Palette,
  Shield,
  Plus,
  Trash2,
  Play,
  Copy,
  Check,
  AlertCircle,
} from 'lucide-react'
import {
  schedulesApi,
  apiKeysApi,
  whiteLabelApi,
} from '../api/client'

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<'schedules' | 'apikeys' | 'whitelabel' | 'datasources'>('schedules')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Schedules state
  const [schedules, setSchedules] = useState<any[]>([])
  const [newDomain, setNewDomain] = useState('')
  const [newProfile, setNewProfile] = useState('passive')
  const [newFrequency, setNewFrequency] = useState('daily')
  const [newEmail, setNewEmail] = useState('')
  const [newSlack, setNewSlack] = useState('')
  const [newGenericWebhook, setNewGenericWebhook] = useState('')
  const [newNotifyOn, setNewNotifyOn] = useState('changes_only')

  // API Keys state
  const [apiKeys, setApiKeys] = useState<any[]>([])
  const [newKeyName, setNewKeyName] = useState('')
  const [generatedKey, setGeneratedKey] = useState<string | null>(null)
  const [copiedKey, setCopiedKey] = useState(false)

  // White-Label state
  const [companyName, setCompanyName] = useState('FootprintHub Security')
  const [logoUrl, setLogoUrl] = useState('')
  const [accentColor, setAccentColor] = useState('#2563eb')
  const [footerText, setFooterText] = useState('Confidential Reconnaissance & Security Assessment Report')

  useEffect(() => {
    loadAll()
  }, [])

  const loadAll = async () => {
    setLoading(true)
    setError(null)
    try {
      const [schedRes, keysRes, wlRes] = await Promise.allSettled([
        schedulesApi.list(),
        apiKeysApi.list(),
        whiteLabelApi.get(),
      ])
      if (schedRes.status === 'fulfilled') setSchedules(schedRes.value)
      if (keysRes.status === 'fulfilled') setApiKeys(keysRes.value)
      if (wlRes.status === 'fulfilled') {
        setCompanyName(wlRes.value.company_name || 'FootprintHub Security')
        setLogoUrl(wlRes.value.logo_url || '')
        setAccentColor(wlRes.value.accent_color || '#2563eb')
        setFooterText(wlRes.value.footer_text || 'Confidential Reconnaissance & Security Assessment Report')
      }
    } catch (e: any) {
      setError(e.message || 'Failed to load settings')
    } finally {
      setLoading(false)
    }
  }

  const handleCreateSchedule = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newDomain.trim()) return
    setError(null)
    try {
      await schedulesApi.create({
        domain: newDomain.trim(),
        profile: newProfile,
        frequency: newFrequency,
        notification_email: newEmail.trim() || undefined,
        slack_webhook_url: newSlack.trim() || undefined,
        generic_webhook_url: newGenericWebhook.trim() || undefined,
        notify_on: newNotifyOn,
      })
      setSuccess(`Scheduled monitoring added for ${newDomain}`)
      setNewDomain('')
      setNewSlack('')
      setNewGenericWebhook('')
      const updated = await schedulesApi.list()
      setSchedules(updated)
    } catch (e: any) {
      setError(e.message || 'Failed to create schedule')
    }
  }

  const handleDeleteSchedule = async (id: string) => {
    try {
      await schedulesApi.delete(id)
      setSchedules((prev) => prev.filter((s) => s.id !== id))
      setSuccess('Schedule removed')
    } catch (e: any) {
      setError(e.message || 'Failed to delete schedule')
    }
  }

  const handleTriggerSchedule = async (id: string) => {
    try {
      const res = await schedulesApi.trigger(id)
      setSuccess(`Check completed for ${res.domain}: ${res.delta_summary}`)
    } catch (e: any) {
      setError(e.message || 'Trigger failed')
    }
  }

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newKeyName.trim()) return
    setError(null)
    try {
      const res = await apiKeysApi.create(newKeyName.trim())
      setGeneratedKey(res.raw_api_key)
      setNewKeyName('')
      const updated = await apiKeysApi.list()
      setApiKeys(updated)
    } catch (e: any) {
      setError(e.message || 'Failed to create API key')
    }
  }

  const handleRevokeApiKey = async (id: string) => {
    try {
      await apiKeysApi.revoke(id)
      setApiKeys((prev) => prev.filter((k) => k.id !== id))
      setSuccess('API key revoked')
    } catch (e: any) {
      setError(e.message || 'Failed to revoke API key')
    }
  }

  const handleSaveWhiteLabel = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    try {
      await whiteLabelApi.update({
        company_name: companyName.trim(),
        logo_url: logoUrl.trim() || undefined,
        accent_color: accentColor.trim(),
        footer_text: footerText.trim(),
      })
      setSuccess('White-label branding saved successfully')
    } catch (e: any) {
      setError(e.message || 'Failed to save white-label branding')
    }
  }

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-zinc-100 flex items-center gap-2">
          <Shield className="w-6 h-6 text-indigo-500" />
          Settings & Platform Automation
        </h1>
        <p className="text-sm text-zinc-400 mt-1">
          Manage scheduled domain monitoring, SSRF-guarded alerting webhooks, programmatic API keys, and custom white-label reports.
        </p>
      </div>

      {/* Notifications / Alerts */}
      {error && (
        <div className="p-3 bg-red-950/60 border border-red-800/80 rounded-lg text-red-200 text-sm flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}
      {success && (
        <div className="p-3 bg-emerald-950/60 border border-emerald-800/80 rounded-lg text-emerald-200 text-sm flex items-center gap-2">
          <Check className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{success}</span>
        </div>
      )}

      {/* Nav Tabs */}
      <div className="flex border-b border-zinc-800 gap-2">
        <button
          onClick={() => setActiveTab('schedules')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'schedules'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <Clock className="w-4 h-4" />
          Monitoring Schedules ({schedules.length})
        </button>
        <button
          onClick={() => setActiveTab('apikeys')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'apikeys'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <Key className="w-4 h-4" />
          API Keys & CLI ({apiKeys.length})
        </button>
        <button
          onClick={() => setActiveTab('whitelabel')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'whitelabel'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <Palette className="w-4 h-4" />
          White-Label Branding
        </button>
        <button
          onClick={() => setActiveTab('datasources')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'datasources'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <Bell className="w-4 h-4" />
          Data Sources & Intelligence
        </button>
      </div>

      {/* Tab 1: Scheduled Monitoring */}
      {activeTab === 'schedules' && (
        <div className="space-y-6">
          {/* New Schedule Card */}
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 space-y-4">
            <h2 className="text-base font-semibold text-zinc-100 flex items-center gap-2">
              <Plus className="w-4 h-4 text-indigo-400" />
              Schedule Domain Perimeter Monitoring
            </h2>
            <form onSubmit={handleCreateSchedule} className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1">Target Domain</label>
                <input
                  type="text"
                  placeholder="example.com"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1">Profile Mode</label>
                <select
                  value={newProfile}
                  onChange={(e) => setNewProfile(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="passive">Passive (Zero contact, safe)</option>
                  <option value="standard">Standard (Web, SSL, Tech)</option>
                  <option value="full">Full (Active ports & DNS)</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1">Frequency</label>
                <select
                  value={newFrequency}
                  onChange={(e) => setNewFrequency(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="daily">Daily Monitoring</option>
                  <option value="weekly">Weekly Assessment</option>
                  <option value="monthly">Monthly Check</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1">Slack Webhook URL (SSRF Guarded)</label>
                <input
                  type="url"
                  placeholder="https://hooks.slack.com/services/..."
                  value={newSlack}
                  onChange={(e) => setNewSlack(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1">Generic Webhook URL</label>
                <input
                  type="url"
                  placeholder="https://api.yourdomain.com/recon-alerts"
                  value={newGenericWebhook}
                  onChange={(e) => setNewGenericWebhook(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1">Alert Condition</label>
                <select
                  value={newNotifyOn}
                  onChange={(e) => setNewNotifyOn(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="changes_only">Alert only when changes are detected</option>
                  <option value="high_risk_only">Alert only on High/Critical risk</option>
                  <option value="always">Always notify on every scan</option>
                </select>
              </div>
              <div className="md:col-span-3 flex justify-end">
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors"
                >
                  Activate Monitoring Schedule
                </button>
              </div>
            </form>
          </div>

          {/* Existing Schedules Table */}
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-zinc-800">
              <h3 className="text-sm font-semibold text-zinc-200">Active Monitoring Schedules ({schedules.length})</h3>
            </div>
            {schedules.length === 0 ? (
              <div className="p-8 text-center text-zinc-500 text-sm">
                No recurring schedules configured. Register a domain above to monitor for new subdomains, opened ports, and expiring certificates.
              </div>
            ) : (
              <table className="w-full text-left text-xs text-zinc-300">
                <thead className="bg-zinc-950/60 text-zinc-400 border-b border-zinc-800 uppercase font-mono">
                  <tr>
                    <th className="py-3 px-4">Domain</th>
                    <th className="py-3 px-4">Frequency</th>
                    <th className="py-3 px-4">Profile</th>
                    <th className="py-3 px-4">Channels</th>
                    <th className="py-3 px-4">Next Run</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60 font-mono">
                  {schedules.map((s) => (
                    <tr key={s.id} className="hover:bg-zinc-800/30">
                      <td className="py-3 px-4 font-semibold text-zinc-100">{s.domain}</td>
                      <td className="py-3 px-4 uppercase text-indigo-400">{s.frequency}</td>
                      <td className="py-3 px-4 capitalize">{s.profile}</td>
                      <td className="py-3 px-4 text-zinc-400">
                        {s.email_alert && '📧 '}
                        {s.slack_configured && '💬 Slack '}
                        {s.generic_webhook_configured && '🔗 Webhook'}
                      </td>
                      <td className="py-3 px-4 text-zinc-400">
                        {s.next_run_at ? new Date(s.next_run_at).toLocaleDateString() : 'Pending'}
                      </td>
                      <td className="py-3 px-4 text-right space-x-2">
                        <button
                          onClick={() => handleTriggerSchedule(s.id)}
                          title="Trigger check now"
                          className="p-1 text-zinc-400 hover:text-emerald-400 transition-colors"
                        >
                          <Play className="w-4 h-4 inline" />
                        </button>
                        <button
                          onClick={() => handleDeleteSchedule(s.id)}
                          title="Delete schedule"
                          className="p-1 text-zinc-400 hover:text-red-400 transition-colors"
                        >
                          <Trash2 className="w-4 h-4 inline" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: API Keys & CLI */}
      {activeTab === 'apikeys' && (
        <div className="space-y-6">
          {/* Generated Key Modal / Callout */}
          {generatedKey && (
            <div className="p-4 bg-emerald-950/70 border border-emerald-700 rounded-xl space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-emerald-300 font-semibold text-sm">🎉 New API Key Generated</span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(generatedKey)
                    setCopiedKey(true)
                    setTimeout(() => setCopiedKey(false), 2000)
                  }}
                  className="px-2 py-1 bg-emerald-800 hover:bg-emerald-700 text-white rounded text-xs flex items-center gap-1"
                >
                  {copiedKey ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  {copiedKey ? 'Copied' : 'Copy Key'}
                </button>
              </div>
              <p className="text-xs text-emerald-200">
                Store this key immediately. For security, raw API keys are never shown again after this dialog closes.
              </p>
              <div className="bg-black/60 p-2 rounded font-mono text-xs text-emerald-100 break-all border border-emerald-900">
                {generatedKey}
              </div>
            </div>
          )}

          {/* Create Key Card */}
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 space-y-4">
            <h2 className="text-base font-semibold text-zinc-100 flex items-center gap-2">
              <Key className="w-4 h-4 text-indigo-400" />
              Generate Public API Key
            </h2>
            <form onSubmit={handleCreateApiKey} className="flex gap-3">
              <input
                type="text"
                placeholder="Key label (e.g. CI/CD Pipeline or CLI Automation)"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500"
                required
              />
              <button
                type="submit"
                className="bg-indigo-600 hover:bg-indigo-500 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors"
              >
                Create Key
              </button>
            </form>
          </div>

          {/* CLI Instructions Card */}
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 space-y-2">
            <h3 className="text-sm font-semibold text-zinc-200">Command Line Interface (CLI) Usage</h3>
            <p className="text-xs text-zinc-400">
              Run automated assessments directly from your terminal or CI/CD pipelines:
            </p>
            <div className="bg-zinc-950 p-3 rounded-lg border border-zinc-800 font-mono text-xs text-zinc-300 space-y-1">
              <div><span className="text-emerald-400">$</span> python footprinthub.py scan example.com --profile passive --format json</div>
              <div><span className="text-emerald-400">$</span> python footprinthub.py report &lt;SCAN_ID&gt; --key fph_live_...</div>
              <div><span className="text-emerald-400">$</span> python footprinthub.py delta &lt;SCAN_ID&gt;</div>
            </div>
          </div>

          {/* Keys Table */}
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-zinc-800">
              <h3 className="text-sm font-semibold text-zinc-200">Active API Keys</h3>
            </div>
            {apiKeys.length === 0 ? (
              <div className="p-8 text-center text-zinc-500 text-sm">
                No active API keys found. Create a key above to enable CLI scanning.
              </div>
            ) : (
              <table className="w-full text-left text-xs text-zinc-300">
                <thead className="bg-zinc-950/60 text-zinc-400 border-b border-zinc-800 uppercase font-mono">
                  <tr>
                    <th className="py-3 px-4">Name</th>
                    <th className="py-3 px-4">Prefix</th>
                    <th className="py-3 px-4">Scopes</th>
                    <th className="py-3 px-4">Created</th>
                    <th className="py-3 px-4">Last Used</th>
                    <th className="py-3 px-4 text-right">Revoke</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60 font-mono">
                  {apiKeys.map((k) => (
                    <tr key={k.id} className="hover:bg-zinc-800/30">
                      <td className="py-3 px-4 font-semibold text-zinc-100">{k.name}</td>
                      <td className="py-3 px-4 text-indigo-400">{k.prefix}...</td>
                      <td className="py-3 px-4 text-zinc-400">{k.scopes}</td>
                      <td className="py-3 px-4 text-zinc-400">{new Date(k.created_at).toLocaleDateString()}</td>
                      <td className="py-3 px-4 text-zinc-400">{k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : 'Never'}</td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleRevokeApiKey(k.id)}
                          className="p-1 text-zinc-400 hover:text-red-400 transition-colors"
                          title="Revoke key"
                        >
                          <Trash2 className="w-4 h-4 inline" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: White-Label Branding */}
      {activeTab === 'whitelabel' && (
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 space-y-4">
          <div>
            <h2 className="text-base font-semibold text-zinc-100 flex items-center gap-2">
              <Palette className="w-4 h-4 text-indigo-400" />
              White-Label Report & Share Branding
            </h2>
            <p className="text-xs text-zinc-400 mt-1">
              Customize the company title, primary color, and footer printed on public tokenized links and exported PDF dossiers.
            </p>
          </div>
          <form onSubmit={handleSaveWhiteLabel} className="space-y-4 max-w-2xl">
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1">Company / Organization Name</label>
              <input
                type="text"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500"
                required
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1">Logo URL (Optional)</label>
              <input
                type="url"
                placeholder="https://example.com/logo.png"
                value={logoUrl}
                onChange={(e) => setLogoUrl(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1">Accent Hex Color</label>
              <div className="flex gap-2 items-center">
                <input
                  type="color"
                  value={accentColor}
                  onChange={(e) => setAccentColor(e.target.value)}
                  className="w-10 h-10 rounded border border-zinc-700 bg-transparent cursor-pointer"
                />
                <input
                  type="text"
                  value={accentColor}
                  onChange={(e) => setAccentColor(e.target.value)}
                  className="w-32 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm font-mono text-zinc-200 focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1">Footer Disclaimer Text</label>
              <input
                type="text"
                value={footerText}
                onChange={(e) => setFooterText(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-indigo-500"
                required
              />
            </div>
            <div>
              <button
                type="submit"
                className="bg-indigo-600 hover:bg-indigo-500 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors"
              >
                Save White-Label Settings
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Tab 4: Data Sources & Intelligence */}
      {activeTab === 'datasources' && (
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 space-y-4">
          <h2 className="text-base font-semibold text-zinc-100 flex items-center gap-2">
            <Bell className="w-4 h-4 text-indigo-400" />
            Intelligence Feeds & Optional API Keys
          </h2>
          <p className="text-xs text-zinc-400">
            FootprintHub functions with 100% free open feeds by default. Supplying optional API keys enriches passive exposure intelligence.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg space-y-1">
              <div className="flex justify-between items-center">
                <span className="font-semibold text-zinc-200">Shodan InternetDB</span>
                <span className="text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded">Active (No key required)</span>
              </div>
              <p className="text-zinc-500 text-[11px]">Zero-socket open ports, CVEs, and CPE intelligence.</p>
            </div>
            <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg space-y-1">
              <div className="flex justify-between items-center">
                <span className="font-semibold text-zinc-200">CISA KEV & FIRST EPSS</span>
                <span className="text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded">Active (Daily cached)</span>
              </div>
              <p className="text-zinc-500 text-[11px]">Known exploited vulnerabilities and EPSS percentile scoring.</p>
            </div>
            <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg space-y-1">
              <div className="flex justify-between items-center">
                <span className="font-semibold text-zinc-200">AlienVault OTX & crt.sh</span>
                <span className="text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded">Active (Zero key)</span>
              </div>
              <p className="text-zinc-500 text-[11px]">Passive DNS churn, Certificate Transparency history, and subdomains.</p>
            </div>
            <div className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg space-y-1">
              <div className="flex justify-between items-center">
                <span className="font-semibold text-zinc-200">Censys & VirusTotal</span>
                <span className="text-zinc-400 bg-zinc-800 px-2 py-0.5 rounded">Optional (.env configured)</span>
              </div>
              <p className="text-zinc-500 text-[11px]">Deep passive SSL certificates and malware threat lookup.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

