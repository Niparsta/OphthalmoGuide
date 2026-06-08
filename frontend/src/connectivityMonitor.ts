import { apiUrl } from './services/api'

const LIGHT_PROBE_URL = `${window.location.origin}/favicon.svg`
const DEEP_PROBE_URL = apiUrl('/health/')
const PROBE_TIMEOUT_MS = 5000
const RETRY_DELAY_MS = 2_000
const FAILURE_THRESHOLD = 2

const POLL_HEALTHY_MS = 30_000
const DEEP_PROBE_HEALTHY_MS = 90_000
const POLL_NETWORK_ISSUE_MS = 8_000
const POLL_BACKEND_ISSUE_MS = 30_000

type Issue = 'network' | 'backend' | null

export interface ConnectivityMonitor {
  stop: () => void
}

export function createConnectivityMonitor(
  onStatusChange: (online: boolean) => void,
): ConnectivityMonitor {
  let healthy = navigator.onLine
  let issue: Issue = null
  let lastDeepAt = 0
  let consecutiveFailures = 0
  let pollTimer: ReturnType<typeof setInterval> | null = null
  let retryTimer: ReturnType<typeof setTimeout> | null = null
  let probing = false

  function setHealthy(next: boolean) {
    if (healthy === next) return
    healthy = next
    consecutiveFailures = 0
    if (next) issue = null
    onStatusChange(next)
    schedulePolling()
  }

  async function request(url: string, method: 'GET' | 'HEAD'): Promise<boolean> {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS)

    try {
      const response = await fetch(url, {
        method,
        cache: 'no-store',
        signal: controller.signal,
      })
      return response.ok
    } catch {
      return false
    } finally {
      clearTimeout(timeout)
    }
  }

  function scheduleRetry() {
    if (retryTimer) clearTimeout(retryTimer)
    retryTimer = setTimeout(() => void evaluateConnectivity(), RETRY_DELAY_MS)
  }

  function markUnhealthy(nextIssue: Issue) {
    issue = nextIssue
    setHealthy(false)
  }

  async function evaluateConnectivity(forceDeep = false) {
    if (document.hidden || probing) return
    probing = true

    try {
      if (!navigator.onLine) {
        consecutiveFailures = 0
        markUnhealthy('network')
        return
      }

      const now = Date.now()

      if (issue !== 'backend') {
        const lightOk = await request(LIGHT_PROBE_URL, 'HEAD')
        if (!lightOk) {
          if (healthy && ++consecutiveFailures < FAILURE_THRESHOLD) {
            issue = 'network'
            scheduleRetry()
            return
          }
          consecutiveFailures = 0
          markUnhealthy('network')
          return
        }
      }

      consecutiveFailures = 0

      const deepInterval = healthy ? DEEP_PROBE_HEALTHY_MS : POLL_BACKEND_ISSUE_MS
      const deepDue = forceDeep || now - lastDeepAt >= deepInterval
      if (!deepDue) return

      const deepOk = await request(DEEP_PROBE_URL, 'GET')
      lastDeepAt = now

      if (deepOk) {
        issue = null
        setHealthy(true)
        return
      }

      if (healthy && ++consecutiveFailures < FAILURE_THRESHOLD) {
        issue = 'backend'
        scheduleRetry()
        return
      }

      consecutiveFailures = 0
      markUnhealthy('backend')
    } finally {
      probing = false
    }
  }

  function schedulePolling() {
    if (document.hidden) return
    if (pollTimer) clearInterval(pollTimer)

    const interval = healthy
      ? POLL_HEALTHY_MS
      : issue === 'backend'
        ? POLL_BACKEND_ISSUE_MS
        : POLL_NETWORK_ISSUE_MS

    pollTimer = setInterval(() => void evaluateConnectivity(), interval)
  }

  function onBrowserOffline() {
    if (retryTimer) clearTimeout(retryTimer)
    consecutiveFailures = 0
    markUnhealthy('network')
  }

  function onBrowserOnline() {
    consecutiveFailures = 0
    void evaluateConnectivity(true)
  }

  function onVisibilityChange() {
    if (document.hidden) {
      if (pollTimer) clearInterval(pollTimer)
      pollTimer = null
      return
    }

    const deepStale = Date.now() - lastDeepAt >= DEEP_PROBE_HEALTHY_MS
    void evaluateConnectivity(deepStale)
    schedulePolling()
  }

  window.addEventListener('offline', onBrowserOffline)
  window.addEventListener('online', onBrowserOnline)
  document.addEventListener('visibilitychange', onVisibilityChange)

  void evaluateConnectivity(true)
  schedulePolling()

  return {
    stop() {
      if (pollTimer) clearInterval(pollTimer)
      if (retryTimer) clearTimeout(retryTimer)
      window.removeEventListener('offline', onBrowserOffline)
      window.removeEventListener('online', onBrowserOnline)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    },
  }
}
