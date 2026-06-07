export function isAdminShellPath(): boolean {
  const path = window.location.pathname
  return path === '/admin' || path === '/admin/'
}

/** Не даём открыть /admin из bfcache или без живого frontend. */
export async function guardAdminShellBeforeMount(): Promise<void> {
  if (!isAdminShellPath()) return

  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      window.location.reload()
    }
  })

  const probeUrl = import.meta.env.DEV
    ? `${window.location.origin}/@vite/client`
    : `${window.location.origin}/favicon.svg`

  try {
    const response = await fetch(probeUrl, { method: 'GET', cache: 'no-store' })
    if (!response.ok) {
      throw new Error('shell-unavailable')
    }
  } catch {
    const root = document.getElementById('app')
    if (root) {
      root.innerHTML = `
        <div style="min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:2rem;font-family:system-ui,sans-serif;background:#f6f8fa;color:#0f172a;">
          <div style="max-width:420px;text-align:center;">
            <h1 style="margin:0 0 0.75rem;font-size:1.35rem;color:#ef4444;">Сервер недоступен</h1>
            <p style="margin:0;font-size:0.95rem;line-height:1.55;color:#64748b;">
              Панель управления не загружена. Запустите frontend и обновите страницу (F5).
            </p>
          </div>
        </div>
      `
    }
    throw new Error('admin-shell-unavailable')
  }
}
