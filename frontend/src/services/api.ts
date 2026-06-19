const isDev = import.meta.env.DEV

export const API_BASE = isDev
  ? ''
  : (() => {
      const { protocol, hostname } = window.location
      return `${protocol}//api.${hostname}`
    })()

export function apiUrl(endpoint: string) {
  return `${API_BASE}${endpoint}`
}
