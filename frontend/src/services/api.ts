export const API_BASE = ''

export function apiUrl(endpoint: string) {
  return `${API_BASE}${endpoint}`
}
