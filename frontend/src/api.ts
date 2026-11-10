export type JsonRecord = Record<string, unknown>

const API_ROOT = import.meta.env.VITE_API_BASE ?? '/api'
const TOKEN_KEY = 'sauyt_soc_access_token'

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message)
  }
}

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null): void {
  if (token) sessionStorage.setItem(TOKEN_KEY, token)
  else sessionStorage.removeItem(TOKEN_KEY)
}

function errorMessage(body: unknown, status: number): string {
  const data = asRecord(body)
  const detail = data.detail ?? data.message ?? data.error
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map(item => valueText(asRecord(item).msg ?? item)).join('; ')
  return `Сервер вернул ошибку ${status}`
}

export async function api<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const token = getToken()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  let response: Response
  try {
    response = await fetch(`${API_ROOT}${path}`, { ...options, headers })
  } catch {
    throw new ApiError('Нет связи с API. Проверьте состояние backend и повторите попытку.', 0)
  }
  const text = await response.text()
  let body: unknown = null
  if (text) {
    try { body = JSON.parse(text) } catch { body = text }
  }
  if (!response.ok) {
    if (response.status === 401 && token) {
      setToken(null)
      window.dispatchEvent(new Event('soc-auth-expired'))
    }
    throw new ApiError(errorMessage(body, response.status), response.status)
  }
  return body as T
}

export async function download(path: string, fallbackName: string): Promise<void> {
  const headers = new Headers()
  const token = getToken()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  let response: Response
  try {
    response = await fetch(`${API_ROOT}${path}`, { headers })
  } catch {
    throw new ApiError('Не удалось скачать отчёт: нет связи с API.', 0)
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new ApiError(errorMessage(body, response.status), response.status)
  }
  const disposition = response.headers.get('Content-Disposition')
  const matched = disposition?.match(/filename\*?=(?:UTF-8'')?["']?([^"';]+)/i)
  const filename = matched ? decodeURIComponent(matched[1]) : fallbackName
  const url = URL.createObjectURL(await response.blob())
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function asRecord(value: unknown): JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as JsonRecord : {}
}

export function records(value: unknown, ...keys: string[]): JsonRecord[] {
  if (Array.isArray(value)) return value.map(asRecord)
  const data = asRecord(value)
  for (const key of [...keys, 'items', 'results', 'data']) {
    if (Array.isArray(data[key])) return (data[key] as unknown[]).map(asRecord)
  }
  return []
}

export function valueText(value: unknown, fallback = '—'): string {
  if (value === null || value === undefined || value === '') return fallback
  if (typeof value === 'string' || typeof value === 'number') return String(value)
  if (typeof value === 'boolean') return value ? 'Да' : 'Нет'
  return fallback
}

export function first(data: JsonRecord, ...keys: string[]): unknown {
  for (const key of keys) if (data[key] !== undefined && data[key] !== null) return data[key]
  return undefined
}

export function dateValue(value: unknown): number | null {
  if (typeof value !== 'string' || !value) return null
  // SQLite returns UTC timestamps without an offset; interpret them as UTC.
  const normalized = /(?:Z|[+-]\d{2}:\d{2})$/i.test(value) ? value : `${value}Z`
  const timestamp = new Date(normalized).getTime()
  return Number.isNaN(timestamp) ? null : timestamp
}

export function dateText(value: unknown, timeZone?: string): string {
  const timestamp = dateValue(value)
  if (timestamp === null) return typeof value === 'string' && value ? value : '—'
  const date = new Date(timestamp)
  return new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'short', ...(timeZone ? { timeZone } : {}) }).format(date)
}

export function body(data: JsonRecord): string {
  return JSON.stringify(data)
}
