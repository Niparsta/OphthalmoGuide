export const API_BASE = import.meta.env.DEV ? 'http://localhost:5190' : ''

export function apiUrl(endpoint: string) {
  return `${API_BASE}${endpoint}`
}
