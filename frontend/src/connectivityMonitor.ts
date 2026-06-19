import { apiUrl } from './services/api'

const LIGHT_URL = `${window.location.origin}/favicon.svg`
const DEEP_URL = apiUrl('/health')
const PROBE_TIMEOUT_MS = 5000

const LIGHT_NORMAL_MS = 30_000
const LIGHT_RECOVERY_MS = 8_000
const LIGHT_LOAD_RETRY_MS = 5_000

const DEEP_NORMAL_MS = 90_000
const DEEP_RECOVERY_MS = 30_000
const DEEP_LOAD_RETRY_MS = 10_000

type LayerMode = 'normal' | 'recovering'

export interface ConnectivityMonitor {
  stop: () => void
}

export function createConnectivityMonitor(
  onStatusChange: (online: boolean) => void,
): ConnectivityMonitor {
  let healthy = navigator.onLine
  let lightMode: LayerMode = 'normal'
  let deepMode: LayerMode = 'normal'
  let lastLightAt = 0
  let lastDeepAt = 0
  let pollTimer: ReturnType<typeof setTimeout> | null = null
  let lightLoadRetryTimer: ReturnType<typeof setTimeout> | null = null
  let deepLoadRetryTimer: ReturnType<typeof setTimeout> | null = null
  let running = false

  function lightInterval() {
    return lightMode === 'normal' ? LIGHT_NORMAL_MS : LIGHT_RECOVERY_MS
  }

  function deepInterval() {
    return deepMode === 'normal' ? DEEP_NORMAL_MS : DEEP_RECOVERY_MS
  }

  function syncHealthy() {
    const next = lightMode === 'normal' && deepMode === 'normal'
    if (healthy === next) return
    healthy = next
    onStatusChange(next)
  }

  function enterRecovery(layer: 'light' | 'deep') {
    if (layer === 'light') lightMode = 'recovering'
    else deepMode = 'recovering'
    syncHealthy()
  }

  function enterNormal(layer: 'light' | 'deep') {
    if (layer === 'light') lightMode = 'normal'
    else deepMode = 'normal'
    syncHealthy()
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

  async function probeLight(): Promise<boolean> {
    lastLightAt = Date.now()
    return request(LIGHT_URL, 'HEAD')
  }

  async function probeDeep(): Promise<boolean> {
    lastDeepAt = Date.now()
    return request(DEEP_URL, 'GET')
  }

  function isLightDue(): boolean {
    return Date.now() - lastLightAt >= lightInterval()
  }

  function isDeepDue(): boolean {
    return Date.now() - lastDeepAt >= deepInterval()
  }

  function clearLoadRetries() {
    if (lightLoadRetryTimer) clearTimeout(lightLoadRetryTimer)
    if (deepLoadRetryTimer) clearTimeout(deepLoadRetryTimer)
    lightLoadRetryTimer = null
    deepLoadRetryTimer = null
  }

  function schedulePoll() {
    if (document.hidden) return
    if (pollTimer) clearTimeout(pollTimer)

    const now = Date.now()
    const lightWait = Math.max(0, lightInterval() - (now - lastLightAt))
    const deepWait = Math.max(0, deepInterval() - (now - lastDeepAt))
    const delay = Math.min(lightWait, deepWait)

    pollTimer = setTimeout(() => void tick(), delay <= 0 ? 0 : delay)
  }

  function stopPoll() {
    if (pollTimer) clearTimeout(pollTimer)
    pollTimer = null
  }

  async function runLightStartup() {
    const lightOk = await probeLight()
    if (lightOk) {
      enterNormal('light')
      return
    }

    lightLoadRetryTimer = setTimeout(async () => {
      lightLoadRetryTimer = null
      const retryOk = await probeLight()
      if (retryOk) enterNormal('light')
      else enterRecovery('light')
      schedulePoll()
    }, LIGHT_LOAD_RETRY_MS)
  }

  async function runDeepStartup() {
    const deepOk = await probeDeep()
    if (deepOk) {
      enterNormal('deep')
      return
    }

    deepLoadRetryTimer = setTimeout(async () => {
      deepLoadRetryTimer = null
      const retryOk = await probeDeep()
      if (retryOk) enterNormal('deep')
      else enterRecovery('deep')
      schedulePoll()
    }, DEEP_LOAD_RETRY_MS)
  }

  async function runStartup() {
    if (document.hidden) return

    if (!navigator.onLine) {
      enterRecovery('light')
      enterRecovery('deep')
      schedulePoll()
      return
    }

    await Promise.all([runLightStartup(), runDeepStartup()])
    schedulePoll()
  }

  async function checkLight() {
    const lightOk = await probeLight()
    if (lightOk) enterNormal('light')
    else enterRecovery('light')
  }

  async function checkDeep() {
    const deepOk = await probeDeep()
    if (deepOk) enterNormal('deep')
    else enterRecovery('deep')
  }

  async function tick() {
    if (document.hidden || running) return
    running = true

    try {
      if (!navigator.onLine) {
        enterRecovery('light')
        enterRecovery('deep')
        return
      }

      const checks: Promise<void>[] = []
      if (isLightDue()) checks.push(checkLight())
      if (isDeepDue()) checks.push(checkDeep())
      await Promise.all(checks)
    } finally {
      running = false
      schedulePoll()
    }
  }

  function onBrowserOffline() {
    clearLoadRetries()
    enterRecovery('light')
    enterRecovery('deep')
    schedulePoll()
  }

  function onBrowserOnline() {
    clearLoadRetries()
    void runStartup()
  }

  function onVisibilityChange() {
    if (document.hidden) {
      stopPoll()
      return
    }

    void tick()
    schedulePoll()
  }

  window.addEventListener('offline', onBrowserOffline)
  window.addEventListener('online', onBrowserOnline)
  document.addEventListener('visibilitychange', onVisibilityChange)

  void runStartup()

  return {
    stop() {
      stopPoll()
      clearLoadRetries()
      window.removeEventListener('offline', onBrowserOffline)
      window.removeEventListener('online', onBrowserOnline)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    },
  }
}
