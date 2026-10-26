// =============================================================================
// FootprintHub — API Client
// =============================================================================

const API_BASE = '/api/v1'

interface RequestOptions {
  method?: string
  body?: unknown
  headers?: Record<string, string>
}

/**
 * Base fetch wrapper with JWT auth and error handling.
 */
async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const token = localStorage.getItem('access_token')
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options.headers,
  }

  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  })

  if (response.status === 401) {
    // Try to refresh the token
    const refreshed = await tryRefreshToken()
    if (refreshed) {
      // Retry the request with new token
      headers['Authorization'] = `Bearer ${localStorage.getItem('access_token')}`
      const retryResponse = await fetch(`${API_BASE}${endpoint}`, {
        method: options.method || 'GET',
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
      })
      if (!retryResponse.ok) {
        throw new ApiError(retryResponse.status, await retryResponse.text())
      }
      return retryResponse.json()
    }
    // Refresh failed — redirect to login
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    window.location.href = '/login'
    throw new ApiError(401, 'Session expired')
  }

  if (!response.ok) {
    let errorDetail = response.statusText
    try {
      const errorBody = await response.json()
      if (typeof errorBody?.detail === 'string') {
        errorDetail = errorBody.detail
      } else if (Array.isArray(errorBody?.detail)) {
        errorDetail = errorBody.detail.map((e: { msg?: string }) => e.msg || '').filter(Boolean).join(', ') || response.statusText
      } else if (errorBody?.message) {
        errorDetail = errorBody.message
      }
    } catch {
      if (response.status >= 500) {
        errorDetail = 'Backend server is unreachable. Please ensure the FastAPI backend is running on port 8000.'
      }
    }
    throw new ApiError(response.status, errorDetail)
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return undefined as T
  }

  return response.json()
}

async function tryRefreshToken(): Promise<boolean> {
  const refreshToken = localStorage.getItem('refresh_token')
  if (!refreshToken) return false

  try {
    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
    if (!response.ok) return false

    const data = await response.json()
    localStorage.setItem('access_token', data.access_token)
    localStorage.setItem('refresh_token', data.refresh_token)
    return true
  } catch {
    return false
  }
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

// ── Auth API ────────────────────────────────────────────────────────────────

export const authApi = {
  register: (email: string, password: string, fullName?: string) =>
    request<{ access_token: string; refresh_token: string }>('/auth/register', {
      method: 'POST',
      body: { email, password, full_name: fullName },
    }),

  login: (email: string, password: string) =>
    request<{ access_token: string; refresh_token: string }>('/auth/login', {
      method: 'POST',
      body: { email, password },
    }),

  getMe: () => request<{ id: string; email: string; full_name: string | null }>('/auth/me'),
}

// ── Scans API ───────────────────────────────────────────────────────────────

export interface ScanResponse {
  id: string
  domain: string
  profile: string
  status: string
  risk_score: number | null
  authorization_confirmed: boolean
  created_at: string
  completed_at: string | null
  error_message: string | null
}

export interface ModuleResultResponse {
  id: string
  module_name: string
  mode: string
  status: string
  data: Record<string, unknown>
  error_message: string | null
  duration_seconds: number | null
  created_at: string
}

export interface FindingResponse {
  id: string
  module_name: string
  severity: string
  title: string
  description: string
  remediation: string | null
  created_at: string
}

export const scansApi = {
  create: (domain: string, profile: string, authorizationConfirmed: boolean) =>
    request<ScanResponse>('/scans/', {
      method: 'POST',
      body: { domain, profile, authorization_confirmed: authorizationConfirmed },
    }),

  list: (page = 1, perPage = 20) =>
    request<{ scans: ScanResponse[]; total: number; page: number; per_page: number }>(
      `/scans/?page=${page}&per_page=${perPage}`
    ),

  get: (scanId: string) => request<ScanResponse>(`/scans/${scanId}`),

  getResults: (scanId: string) =>
    request<ModuleResultResponse[]>(`/scans/${scanId}/results`),

  getModuleResult: (scanId: string, moduleName: string) =>
    request<ModuleResultResponse>(`/scans/${scanId}/results/${moduleName}`),

  getFindings: (scanId: string) =>
    request<FindingResponse[]>(`/scans/${scanId}/findings`),

  delete: (scanId: string) =>
    request<void>(`/scans/${scanId}`, { method: 'DELETE' }),

  getGraph: (scanId: string) =>
    request<{ nodes: any[]; edges: any[] }>(`/scans/${scanId}/graph`),

  compare: (scan1Id: string, scan2Id: string) =>
    request<any>(`/scans/analytics/compare?scan1_id=${scan1Id}&scan2_id=${scan2Id}`),

  getExportUrl: (scanId: string, format: 'pdf' | 'json' | 'csv') => {
    const token = localStorage.getItem('access_token')
    return `${API_BASE}/scans/${scanId}/export?format=${format}${token ? `&token=${token}` : ''}`
  },
}

export default request
