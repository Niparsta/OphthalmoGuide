<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch, nextTick } from 'vue'
import { Notivue, Notifications, push, darkTheme, lightTheme } from 'notivue'
import AppBrand from './components/AppBrand.vue'
import ConfirmModal from './components/ConfirmModal.vue'
import { API_BASE, apiUrl } from './services/api'
import forbiddenHtml from '../public/403.html?raw' // HMR touch
import unauthorizedHtml from '../public/401.html?raw'
import { createConnectivityMonitor, type ConnectivityMonitor } from './connectivityMonitor'

const isDark = ref(false)
let mediaQuery: MediaQueryList | null = null

const isOnline = ref(navigator.onLine)
const showRestoredBanner = ref(false)
let restoredTimeout: ReturnType<typeof setTimeout> | null = null
let connectivityMonitor: ConnectivityMonitor | null = null

function handleConnectivityChange(online: boolean) {
  if (online && !isOnline.value) {
    showRestoredBanner.value = true
    if (restoredTimeout) clearTimeout(restoredTimeout)
    restoredTimeout = setTimeout(() => {
      showRestoredBanner.value = false
    }, 3000)
  } else if (!online) {
    showRestoredBanner.value = false
  }
  isOnline.value = online
}

const updateTheme = (e: MediaQueryListEvent | MediaQueryList) => {
  isDark.value = e.matches
}

// Types based on C# models
interface DiseaseMatch {
  disease: string
  threatLevel: number
  matchingSymptomsCount: number
  totalDiseaseSymptomsCount: number
  matchPercentage: number
  userSymptomsCoverage: number
  matchedSymptoms: string[]
  allDiseaseSymptoms?: string[]
}

interface AnalyzeResponse {
  success: boolean
  extractedSymptoms: string[]
  assumedSymptoms?: string[]
  suggestedDiseases?: string[]
  results: DiseaseMatch[]
  historyRecordId?: string
  error?: string
  ollamaRawResponse?: string
}

interface DiseaseSymptom {
  name: string
  redFlag: boolean
}

interface DiseaseRecord {
  name: string
  threatLevel: number
  symptoms: DiseaseSymptom[]
}

function isSymptomSelected(disease: DiseaseRecord, symptom: string): boolean {
  return disease.symptoms?.some(s => s.name === symptom) ?? false
}

function isSymptomRedFlag(disease: DiseaseRecord, symptom: string): boolean {
  return disease.symptoms?.find(s => s.name === symptom)?.redFlag ?? false
}

function toggleSymptomRedFlag(symptom: string) {
  if (!selectedDisease.value) return
  const entry = selectedDisease.value.symptoms.find(s => s.name === symptom)
  if (entry) {
    entry.redFlag = !entry.redFlag
    updateSelectedDiseaseInList()
  }
}

interface SessionHistoryRecord {
  id: string
  sessionId?: string
  timestamp: string
  complaintText: string
  detectedSymptoms: string[]
  assumedSymptoms?: string[]
  results: DiseaseMatch[]
}



interface ToastMessage {
  id: number
  message: string
  type: 'success' | 'error' | 'warning' | 'info'
}

const sessionId = ref('')

// Access Control
const isAdmin = ref(false)
const isAdminUnauthorized = ref(false)
const onAdminRoute = ref(false)
const adminBootstrapLoading = ref(false)
const adminBootstrapFailed = ref(false)
const authConfig = ref<{ enabled: boolean; authority: string; clientId: string; redirectUri?: string } | null>(null)
const OAUTH_REDIRECT_URI_KEY = 'oauth_redirect_uri'
let adminSessionCheckInterval: ReturnType<typeof setInterval> | null = null
let adminSessionCheckInFlight = false

function isAdminPath(): boolean {
  const path = window.location.pathname
  return path === '/admin' || path === '/admin/'
}

function isOAuthCallbackPending(): boolean {
  const params = new URLSearchParams(window.location.search)
  return params.get('state') === 'admin' && !!params.get('code')
}

/** Завершает админ-сессию и возвращает на главную без автоматического OAuth (ломает цикл SSO). */
function exitAdminAfterSessionLoss(message: string) {
  clearAdminSession()
  if (isAdminPath()) {
    window.history.replaceState({}, document.title, '/')
  }
  activeTab.value = 'diagnostics'
  showNotification(message, 'warning')
}

function showForbiddenPage() {
  isAdmin.value = false
  document.open()
  document.write(forbiddenHtml)
  document.close()
}

function showUnauthorizedPage() {
  isAdmin.value = false
  document.open()
  document.write(unauthorizedHtml)
  document.close()
}

const authentikUserPortalUrl = computed(() => {
  if (!authConfig.value || !authConfig.value.authority) return '#'
  const authorityBase = authAuthorityBase(authConfig.value.authority)
  return `${authorityBase}/if/user/`
})

const activeTab = ref<'diagnostics' | 'knowledge' | 'history'>('diagnostics')

// Diagnostics Form & Validation State
const complaintText = ref('')
const isAnalyzing = ref(false)
const analysisResult = ref<AnalyzeResponse | null>(null)
const expandedDiseaseIndex = ref<number | null>(null)
const submissionError = ref('')
const textareaRef = ref<HTMLTextAreaElement | null>(null)

let analysisAbortController: AbortController | null = null

function abortActiveAnalysis() {
  if (analysisAbortController) {
    analysisAbortController.abort()
    analysisAbortController = null
  }
  isAnalyzing.value = false
}

function clearComplaintText() {
  complaintText.value = ''
  submissionError.value = ''
  nextTick(() => {
    if (textareaRef.value) {
      textareaRef.value.style.height = ''
    }
  })
}

function resetToNewAnalysis() {
  abortActiveAnalysis()
  clearComplaintText()
  analysisResult.value = null
  expandedDiseaseIndex.value = null
  loadedRecordId.value = null
  stopSynthesizing()
}

function toggleDiseaseExpand(index: number) {
  if (expandedDiseaseIndex.value === index) {
    expandedDiseaseIndex.value = null
  } else {
    expandedDiseaseIndex.value = index
  }
}

const DIFFERENTIAL_RELATIVE_THRESHOLD = 0.3
const DIFFERENTIAL_MAX_ITEMS = 5

const filteredResults = computed(() => {
  if (!analysisResult.value || !analysisResult.value.results.length) return []
  return [...analysisResult.value.results]
    .filter(r => r.matchPercentage > 0)
    .sort((a, b) => b.matchPercentage - a.matchPercentage)
    .slice(0, 5)
})

// Relative confidence (0-100) of a candidate compared to the strongest match in the list.
function relativeConfidence(match: DiseaseMatch) {
  const top = filteredResults.value[0]
  if (!top || top.matchPercentage <= 0) return 0
  return Math.round((match.matchPercentage / top.matchPercentage) * 100)
}

function formatDifferentialWeight(match: DiseaseMatch): string {
  return (relativeConfidence(match) / 100).toFixed(2)
}

function priorityClass(match: DiseaseMatch) {
  const c = relativeConfidence(match)
  if (c >= 80) return 'priority-high'
  if (c >= 60) return 'priority-medium'
  return 'priority-low'
}

// Relative confidence (0-100) of a candidate compared to the strongest match in the list of a history record.
function relativeConfidenceForRecord(record: SessionHistoryRecord, match: DiseaseMatch) {
  if (!record.results || !record.results.length) return 0
  const sorted = [...record.results]
    .filter(r => r.matchPercentage > 0)
    .sort((a, b) => b.matchPercentage - a.matchPercentage)
  if (!sorted.length) return 0
  const top = sorted[0]
  if (!top || top.matchPercentage <= 0) return 0
  return Math.round((match.matchPercentage / top.matchPercentage) * 100)
}

function formatDifferentialWeightForRecord(record: SessionHistoryRecord, match: DiseaseMatch): string {
  return (relativeConfidenceForRecord(record, match) / 100).toFixed(2)
}

function priorityClassForRecord(record: SessionHistoryRecord, match: DiseaseMatch) {
  const c = relativeConfidenceForRecord(record, match)
  if (c >= 80) return 'priority-high'
  if (c >= 60) return 'priority-medium'
  return 'priority-low'
}

function hasAnyOutputSymptoms(): boolean {
  if (!analysisResult.value) return false
  const extracted = analysisResult.value.extractedSymptoms.length
  const assumed = analysisResult.value.assumedSymptoms?.length ?? 0
  return extracted + assumed > 0
}

function shouldShowClinicalMapping(match: DiseaseMatch): boolean {
  if (!hasAnyOutputSymptoms()) return false
  return (match.allDiseaseSymptoms?.length ?? 0) > 0
}

function resizeTextarea() {
  const ta = textareaRef.value
  if (!ta) return
  ta.style.height = 'auto'
  ta.style.height = `${ta.scrollHeight}px`
}

async function copySessionId(id: string) {
  if (!id) return
  try {
    await navigator.clipboard.writeText(id)
    showNotification('ID сессии скопирован', 'success')
  } catch {
    showNotification('Не удалось скопировать ID сессии', 'error')
  }
}

function showNotification(message: string, type: 'success' | 'error' | 'warning' | 'info' = 'info') {
  if (type === 'success') {
    push.success(message)
  } else if (type === 'error') {
    push.error(message)
  } else if (type === 'warning') {
    push.warning(message)
  } else {
    push.info(message)
  }
}

function showSafeError(baseMessage: string) {
  showNotification(baseMessage, 'error')
}

// Custom Confirm Modal System
const confirmModal = ref<{
  open: boolean
  title: string
  message: string
  confirmText?: string
  onConfirm: () => void
}>({
  open: false,
  title: '',
  message: '',
  onConfirm: () => {}
})

function showConfirm(title: string, message: string, onConfirm: () => void, confirmText = 'Подтвердить') {
  confirmModal.value = {
    open: true,
    title,
    message,
    confirmText,
    onConfirm: () => {
      confirmModal.value.open = false
      onConfirm()
    }
  }
}

// SaluteSpeech STT State
const isRecording = ref(false)
const recordingDuration = ref(0)
const speechRecognizing = ref(false)
let recordingTimer: any = null

// Web Audio API WAV Recorder State
let audioCtx: AudioContext | null = null
let scriptProcessor: ScriptProcessorNode | null = null
let micSource: MediaStreamAudioSourceNode | null = null
let activeStream: MediaStream | null = null
let leftChannel: Float32Array[] = []
let recordingSampleRate = 44100

// SaluteSpeech API TTS State
const isSynthesizing = ref(false)
const playingAudioUrl = ref<string | null>(null)
const audioElement = ref<HTMLAudioElement | null>(null)
const autoPlayTts = ref(false) // Auto speak readout when diagnostic completes
const ttsCache = new Map<string, string>() // Cache: speechText -> objectUrl

// History Session Storage
const history = ref<SessionHistoryRecord[]>([])
const adminHistory = ref<SessionHistoryRecord[]>([])
const loadingHistory = ref(false)
const adminHistorySearch = ref('')
const historyViewMode = ref<'tiles' | 'table'>('table')
const tableFilterDate = ref('')
const tableFilterSessionId = ref('')
const tableFilterComplaint = ref('')
const tableFilterSymptom = ref('')
const tableFilterDisease = ref('')

const expandedHistoryDiseases = ref<Record<string, boolean>>({})
const loadedRecordId = ref<string | null>(null)
const selectedHistoryIds = ref<string[]>([])
function toggleHistoryDiseaseExpand(recordId: string, diseaseName: string) {
  const key = `${recordId}_${diseaseName}`
  expandedHistoryDiseases.value[key] = !expandedHistoryDiseases.value[key]
}

function clearTableFilters() {
  tableFilterDate.value = ''
  tableFilterSessionId.value = ''
  tableFilterComplaint.value = ''
  tableFilterSymptom.value = ''
  tableFilterDisease.value = ''
}

// Admin history period filter (datetime-local strings, local time, second precision)
function toLocalInputValue(date: Date) {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}
const historyFrom = ref(toLocalInputValue(new Date(Date.now() - 24 * 60 * 60 * 1000)))
const historyTo = ref(toLocalInputValue(new Date()))

// Knowledge Base Config State (Admin only)
const symptoms = ref<string[]>([])
const diseases = ref<DiseaseRecord[]>([])
const originalSymptoms = ref<string[]>([])
const originalDiseases = ref<DiseaseRecord[]>([])
const loadingKnowledge = ref(false)
const knowledgeLoadFailed = ref(false)
const savingKnowledge = ref(false)
const searchQuery = ref('')
const symptomSearchQuery = ref('')
const selectedDisease = ref<DiseaseRecord | null>(null)
const newSymptomName = ref('')
const newDiseaseName = ref('')

const sidebarActiveTab = ref<'diseases' | 'symptoms'>('diseases')
const knowledgeSearchQuery = ref('')
const newItemName = ref('')

const editingDiseaseName = ref<string | null>(null)
const editingSymptomName = ref<string | null>(null)
const tempEditName = ref('')

// Quick Test Templates
const complaintPresets = [
  {
    title: 'Конъюнктивит',
    text: 'У пациента уже два дня красные глаза, сильный зуд век и слезотечение. По утрам ресницы склеиваются желтоватыми выделениями, есть ощущение песка в глазах.'
  },
  {
    title: 'Катаракта',
    text: 'Жалобы на постепенное ухудшение зрения вдаль и вблизи. Перед глазами стоит пелена и легкий туман. При чтении текста требуется очень яркое освещение. Боли нет.'
  },
  {
    title: 'Глаукома',
    text: 'Резкая боль в левом глазу, отдающая в головную боль и висок. Вокруг лампочек видны радужные гало. Поле зрения сузилось по краям. Легкая тошнота.'
  },
  {
    title: 'Отслойка сетчатки',
    text: 'Внезапно появились вспышки света в правом глазу и резко увеличилось число плавающих темных мушек. Сегодня утром возникла темная тень, словно занавеска, закрывающая часть поля зрения.'
  }
]

// Character counts for live validation borders
const charCount = computed(() => complaintText.value.length)
const borderStateClass = computed(() => {
  if (submissionError.value) return 'border-error'
  if (charCount.value === 0) return ''
  return charCount.value < 15 ? 'border-validating' : 'border-success'
})

// Load authentication configuration
async function fetchConfig() {
  const currentHost = window.location.hostname
  const isHttps = window.location.protocol === 'https:'
  
  const enabled = import.meta.env.VITE_AUTHENTIK_ENABLED !== 'false'
  const clientId = import.meta.env.VITE_AUTHENTIK_CLIENT_ID || 'ophthalmoguide'

  authConfig.value = {
    enabled: enabled,
    clientId: clientId,
    authority: isHttps 
      ? `https://${currentHost}:9443/application/o/ophthalmoguide/` 
      : `http://${currentHost}:9000/application/o/ophthalmoguide/`,
    redirectUri: `${window.location.origin}/`
  }
}

function authAuthorityBase(authority: string): string {
  return authority.split('/application/o/')[0] || authority
}

function getOAuthRedirectUri(): string {
  const configured = authConfig.value?.redirectUri
  if (configured) {
    return configured.endsWith('/') ? configured : `${configured}/`
  }
  return `${window.location.origin}/`
}

// Build the Authentik full-logout URL.
function buildAuthentikLogoutUrl(): string | null {
  if (!authConfig.value?.authority) return null
  const base = authAuthorityBase(authConfig.value.authority)
  const params = new URLSearchParams({ next: `${window.location.origin}/` })
  return `${base}/flows/-/default/invalidation/?${params.toString()}`
}

function getCookie(name: string): string | null {
  const nameEQ = name + "="
  const ca = document.cookie.split(';')
  for (const item of ca) {
    const c = item.trim()
    if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length)
  }
  return null
}

function setCookie(name: string, value: string, maxAgeSeconds?: number) {
  let cookieString = `${name}=${value}; Path=/; SameSite=Lax; Secure`
  if (typeof maxAgeSeconds === 'number') {
    cookieString += `; Max-Age=${maxAgeSeconds}`
  }
  document.cookie = cookieString
}

function deleteCookie(name: string) {
  document.cookie = `${name}=; Path=/; SameSite=Lax; Secure; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0`
}

function getTokenMaxAge(token: string): number {
  try {
    const base64Url = token.split('.')[1]
    if (!base64Url) return 3600
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
    const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
    }).join(''))
    const payload = JSON.parse(jsonPayload)
    if (!payload.exp) return 3600
    const remaining = Math.floor(payload.exp - Date.now() / 1000)
    return remaining > 0 ? remaining : 0
  } catch {
    return 3600
  }
}

function isTokenExpired(token: string): boolean {
  try {
    const base64Url = token.split('.')[1]
    if (!base64Url) return true
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
    const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
    }).join(''))
    const payload = JSON.parse(jsonPayload)
    if (!payload.exp) return false
    return Date.now() / 1000 >= payload.exp - 10
  } catch {
    return true
  }
}

let isRefreshingPromise: Promise<boolean> | null = null

async function refreshAdminToken(): Promise<boolean> {
  const refreshToken = getCookie('admin_refresh_token')
  if (!refreshToken) {
    return false
  }

  if (isRefreshingPromise) {
    return isRefreshingPromise
  }

  isRefreshingPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken })
      })

      if (res.ok) {
        const data = await res.json()
        if (data.access_token) {
          setCookie('admin_token', data.access_token)
          if (data.refresh_token) {
            setCookie('admin_refresh_token', data.refresh_token)
          }
          return true
        }
      }
    } catch (e) {
      console.error('[OIDC] Failed to refresh token:', e)
    }
    
    clearAdminSession()
    return false
  })()

  try {
    return await isRefreshingPromise
  } finally {
    isRefreshingPromise = null
  }
}

async function redirectToAuthentik() {
  if (!authConfig.value) {
    await fetchConfig()
  }
  if (authConfig.value?.enabled) {
    const redirectUri = getOAuthRedirectUri()
    sessionStorage.setItem(OAUTH_REDIRECT_URI_KEY, redirectUri)
    const authorityBase = authAuthorityBase(authConfig.value.authority)
    const params = new URLSearchParams({
      client_id: authConfig.value.clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid profile email offline_access',
      state: 'admin',
    })
    window.location.assign(`${authorityBase}/application/o/authorize/?${params.toString()}`)
  }
}

function clearAdminSession() {
  deleteCookie('admin_token')
  deleteCookie('admin_refresh_token')
  isAdmin.value = false
  isAdminUnauthorized.value = false
  adminBootstrapLoading.value = false
  adminBootstrapFailed.value = false
}

async function bootstrapAdminPanel(): Promise<boolean> {
  adminBootstrapLoading.value = true
  adminBootstrapFailed.value = false
  try {
    const ok = await loadKnowledgeData()
    if (!ok) {
      adminBootstrapFailed.value = true
    }
    return ok
  } finally {
    adminBootstrapLoading.value = false
  }
}

async function enterDemoAdminMode() {
  isAdmin.value = false
  isAdminUnauthorized.value = false
  const ok = await bootstrapAdminPanel()
  if (ok) {
    isAdmin.value = true
    onAdminRoute.value = true
    if (activeTab.value === 'diagnostics') {
      activeTab.value = 'knowledge'
    }
  }
}

async function retryAdminBootstrap() {
  await checkAdminRoute({ userInitiated: true })
}

// Handle returning from Authentik Auth redirection
async function handleAuthentikCallback() {
  const urlParams = new URLSearchParams(window.location.search)
  const oauthError = urlParams.get('error')
  if (oauthError) {
    showNotification('Не удалось войти. Попробуйте ещё раз.', 'error')
    window.history.replaceState({}, document.title, window.location.pathname)
    sessionStorage.removeItem(OAUTH_REDIRECT_URI_KEY)
    return
  }

  const code = urlParams.get('code')
  const state = urlParams.get('state')

  if (!code) return

  // Старый просроченный токен не должен мешать обмену authorization code.
  deleteCookie('admin_token')
  deleteCookie('admin_refresh_token')

  if (state !== 'admin') {
    showNotification('Не удалось войти. Попробуйте ещё раз.', 'error')
    window.history.replaceState({}, document.title, window.location.pathname)
    return
  }

  try {
    const redirectUri = sessionStorage.getItem(OAUTH_REDIRECT_URI_KEY) || getOAuthRedirectUri()
    const res = await fetch(`${API_BASE}/api/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, redirectUri })
    })
    if (res.ok) {
      const data = await res.json()
      if (data.access_token) {
        setCookie('admin_token', data.access_token)
        if (data.refresh_token) {
          setCookie('admin_refresh_token', data.refresh_token)
        }
        sessionStorage.removeItem(OAUTH_REDIRECT_URI_KEY)
        window.location.replace(`${window.location.origin}/admin/`)
        return
      }
    }

    window.history.replaceState({}, document.title, window.location.pathname)
    showNotification('Не удалось войти. Попробуйте ещё раз.', 'error')
  } catch {
    window.history.replaceState({}, document.title, window.location.pathname)
    showNotification('Не удалось войти. Попробуйте ещё раз.', 'error')
  } finally {
    sessionStorage.removeItem(OAUTH_REDIRECT_URI_KEY)
  }
}

// Log out locally: blacklist token on backend + clear session, but keep active SSO session in Authentik
async function logoutAdmin() {
  if (!authConfig.value) {
    await fetchConfig()
  }

  const token = getCookie('admin_token')
  const refreshToken = getCookie('admin_refresh_token')

  if (token) {
    try {
      await fetch(`${API_BASE}/api/auth/logout`, {
        method: 'POST',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ refreshToken })
      })
    } catch {
      // logout notification to backend is best-effort
    }
  }

  clearAdminSession()
  sessionStorage.removeItem(OAUTH_REDIRECT_URI_KEY)
  sessionStorage.setItem('logged_out_notification', 'true')
  window.location.href = '/'
}

/** Лёгкая проверка сессии без перезагрузки базы знаний и без сброса UI. */
async function validateAdminSessionOnly() {
  if (!isAdmin.value || !isAdminPath() || isOAuthCallbackPending()) return

  let token = getCookie('admin_token')
  if (!token || isTokenExpired(token)) {
    const ok = await refreshAdminToken()
    if (ok) {
      token = getCookie('admin_token')
    } else {
      exitAdminAfterSessionLoss('Сессия истекла – авторизуйтесь повторно')
      return
    }
  }

  try {
    const res = await fetch(`${API_BASE}/api/admin/session`, {
      headers: { Authorization: `Bearer ${token}` }
    })
    if (!res.ok) {
      if (res.status === 403) {
        showForbiddenPage()
      } else if (res.status === 401) {
        showUnauthorizedPage()
      } else {
        exitAdminAfterSessionLoss('Сессия истекла – авторизуйтесь повторно')
      }
    }
  } catch {
	  
  }
}

// Listen for Admin Path Access
function navigateToAdmin(e: Event) {
  if (adminBootstrapLoading.value) {
    e.preventDefault()
    return
  }
  e.preventDefault()
  window.history.pushState({}, '', '/admin/')
  void checkAdminRoute({ userInitiated: true })
}

async function checkAdminRoute(options: { userInitiated?: boolean } = {}) {
  if (adminSessionCheckInFlight) return
  adminSessionCheckInFlight = true
  
  const isCurrentlyAdminPath = isAdminPath()
  if (!isCurrentlyAdminPath) {
    onAdminRoute.value = false
  }

  try {
    const path = window.location.pathname
    const urlParams = new URLSearchParams(window.location.search)
    const code = urlParams.get('code')

    if (path === '/admin' || path === '/admin/') {
      if (adminBootstrapFailed.value && !options.userInitiated) {
        onAdminRoute.value = true
        return
      }

      isAdmin.value = false
      if (options.userInitiated) {
        adminBootstrapFailed.value = false
      }

      // OAuth callback обрабатывается в handleAuthentikCallback (даже если в storage ещё старый токен).
      if (isOAuthCallbackPending()) {
        onAdminRoute.value = true
        return
      }

      const token = getCookie('admin_token')
      if (!token) {
        if (code) {
          onAdminRoute.value = true
          return // Let handleAuthentikCallback handle it
        }

        if (urlParams.get('login') === 'true') {
          if (!authConfig.value) {
            await fetchConfig()
          }
          if (authConfig.value?.enabled) {
            redirectToAuthentik()
          } else {
            await enterDemoAdminMode()
          }
          return
        }

        onAdminRoute.value = true
        showUnauthorizedPage()
        return
      }
      
      let activeToken = token
      if (isTokenExpired(token)) {
        const ok = await refreshAdminToken()
        if (ok) {
          activeToken = getCookie('admin_token') || ''
        } else {
          clearAdminSession()
          onAdminRoute.value = true
          showUnauthorizedPage()
          return
        }
      }
      
      // Validate token against a lightweight AdminOnly endpoint
      try {
        adminBootstrapLoading.value = true
        const res = await fetch(`${API_BASE}/api/admin/session`, {
          headers: {
            'Authorization': `Bearer ${activeToken}`
          }
        })
        if (!res.ok) {
          onAdminRoute.value = true
          if (res.status === 403) {
            showForbiddenPage()
          } else if (res.status === 401) {
            clearAdminSession()
            showUnauthorizedPage()
          } else {
            exitAdminAfterSessionLoss('Сессия истекла – авторизуйтесь повторно')
          }
          return
        }
      } catch {
        onAdminRoute.value = true
        adminBootstrapFailed.value = true
        return
      } finally {
        adminBootstrapLoading.value = false
      }
      
      isAdminUnauthorized.value = false
      const ok = await bootstrapAdminPanel()
      if (ok) {
        isAdmin.value = true
        onAdminRoute.value = true
        if (activeTab.value === 'diagnostics') {
          activeTab.value = 'knowledge'
        }
      } else {
        onAdminRoute.value = true
        adminBootstrapFailed.value = true
      }
    } else {
      isAdmin.value = false
      isAdminUnauthorized.value = false
      adminBootstrapFailed.value = false
      adminBootstrapLoading.value = false
      activeTab.value = 'diagnostics'
      onAdminRoute.value = false
    }
  } finally {
    adminSessionCheckInFlight = false
  }
}

function initSession() {
  let id = localStorage.getItem('ophthalmoguide_session_id')
  if (!id) {
    id = 'sess_' + (window.crypto && window.crypto.randomUUID ? window.crypto.randomUUID() : Math.random().toString(36).substring(2, 15) + '_' + Date.now())
    localStorage.setItem('ophthalmoguide_session_id', id)
  }
  sessionId.value = id
}

// Global API Fetch helper with headers
async function apiFetch(endpoint: string, options: Omit<RequestInit, 'body'> & { body?: any } = {}) {
  let token = getCookie('admin_token')
  
  if (token && (isAdmin.value || isAdminUnauthorized.value || isAdminPath())) {
    if (isTokenExpired(token)) {
      const ok = await refreshAdminToken()
      if (ok) {
        token = getCookie('admin_token')
      } else {
        showUnauthorizedPage()
        throw new Error('session_expired')
      }
    }
  }

  const headers: Record<string, string> = {
    'Session-Id': sessionId.value,
    ...(options.headers as Record<string, string> || {})
  }
  // Просроченный admin_token не отправляем на публичные API – иначе JWT middleware может отклонить запрос.
  if (token && (isAdmin.value || isAdminUnauthorized.value || isAdminPath())) {
    headers['Authorization'] = `Bearer ${token}`
  }
  
  let fetchBody: any = options.body
  if (fetchBody && !(fetchBody instanceof Blob) && !(fetchBody instanceof FormData) && typeof fetchBody === 'object') {
    fetchBody = JSON.stringify(fetchBody)
    headers['Content-Type'] = 'application/json'
  }
  
  const response = await fetch(apiUrl(endpoint), {
    ...options,
    body: fetchBody,
    headers
  })
  
  if (!response.ok) {
    if (response.status === 401 && (isAdmin.value || isAdminUnauthorized.value)) {
      showUnauthorizedPage()
    } else if (response.status === 403 && (isAdmin.value || isAdminUnauthorized.value)) {
      showForbiddenPage()
    }
    await response.text()
    throw new Error('request_failed')
  }
  
  return response
}



// Load Session History records
async function loadHistory() {
  loadingHistory.value = true
  try {
    const res = await apiFetch('/api/history')
    history.value = await res.json()
  } catch {
    // history is optional for diagnostics UI
  } finally {
    loadingHistory.value = false
  }
}

async function loadAdminHistory() {
  loadingHistory.value = true
  selectedHistoryIds.value = []
  try {
    const params = new URLSearchParams()
    // Convert local datetime-local strings to UTC ISO for the backend.
    if (historyFrom.value) {
      const fromDate = new Date(historyFrom.value)
      if (!isNaN(fromDate.getTime())) params.set('from', fromDate.toISOString())
    }
    if (historyTo.value) {
      const toDate = new Date(historyTo.value)
      if (!isNaN(toDate.getTime())) params.set('to', toDate.toISOString())
    }
    const query = params.toString()
    const res = await apiFetch(`/api/admin/history${query ? `?${query}` : ''}`)
    adminHistory.value = await res.json()
  } catch {
    // admin history panel stays empty on load failure
  } finally {
    loadingHistory.value = false
  }
}

// Quick presets for the admin history period filter
function setHistoryPeriodPreset(hours: number) {
  historyTo.value = toLocalInputValue(new Date())
  historyFrom.value = toLocalInputValue(new Date(Date.now() - hours * 60 * 60 * 1000))
  loadAdminHistory()
}

function deleteSelectedHistory() {
  if (selectedHistoryIds.value.length === 0) return
  showConfirm(
    'Удалить выбранные сессии',
    `Вы уверены, что хотите безвозвратно удалить выбранные сессии (${selectedHistoryIds.value.length})? Действие нельзя отменить.`,
    async () => {
      confirmModal.value.open = false
      try {
        await apiFetch('/api/admin/history/bulk', { 
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(selectedHistoryIds.value)
        })
        const deletedSet = new Set(selectedHistoryIds.value)
        adminHistory.value = adminHistory.value.filter(r => !deletedSet.has(r.id))
        history.value = history.value.filter(r => !deletedSet.has(r.id))
        selectedHistoryIds.value = []
        showNotification('Выбранные записи удалены', 'success')
      } catch (err) {
        showSafeError('Не удалось удалить выбранные записи, попробуйте ещё раз')
      }
    },
    'Удалить'
  )
}

const isAllSelected = computed(() => {
  const filtered = finalFilteredAdminHistory.value
  if (filtered.length === 0) return false
  return filtered.every(r => selectedHistoryIds.value.includes(r.id))
})

function toggleSelectAll() {
  const filtered = finalFilteredAdminHistory.value
  if (isAllSelected.value) {
    selectedHistoryIds.value = selectedHistoryIds.value.filter(id => !filtered.some(r => r.id === id))
  } else {
    const newIds = new Set([...selectedHistoryIds.value, ...filtered.map(r => r.id)])
    selectedHistoryIds.value = Array.from(newIds)
  }
}

function toggleSelectRecord(id: string) {
  const index = selectedHistoryIds.value.indexOf(id)
  if (index > -1) {
    selectedHistoryIds.value.splice(index, 1)
  } else {
    selectedHistoryIds.value.push(id)
  }
}

// Load clicked history item
function loadHistoryRecord(record: SessionHistoryRecord) {
  activeTab.value = 'diagnostics'
  complaintText.value = record.complaintText
  expandedDiseaseIndex.value = null
  loadedRecordId.value = record.id
  analysisResult.value = {
    success: true,
    extractedSymptoms: record.detectedSymptoms,
    assumedSymptoms: record.assumedSymptoms || [],
    results: record.results
  }
  stopSynthesizing()
  nextTick(() => resizeTextarea())
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

// Process NLP diagnosis text analysis
async function analyzeComplaint() {
  if (complaintText.value.trim().length < 15) {
    submissionError.value = 'error'
    showNotification('Опишите ощущения подробнее – так диагностика будет точнее', 'warning')
    return
  }

  isAnalyzing.value = true
  analysisResult.value = null
  expandedDiseaseIndex.value = null
  loadedRecordId.value = null
  submissionError.value = ''
  stopSynthesizing()

  if (analysisAbortController) {
    analysisAbortController.abort()
  }
  analysisAbortController = new AbortController()

  try {
    const res = await apiFetch('/api/analyze', {
      method: 'POST',
      body: { 
        text: complaintText.value
      },
      signal: analysisAbortController.signal
    })
    const data: AnalyzeResponse = await res.json()
    analysisResult.value = data
    if (data.historyRecordId) {
      loadedRecordId.value = data.historyRecordId
    }
    await loadHistory()
    const latestHistoryRecord = history.value[0]
    if (!loadedRecordId.value && latestHistoryRecord) {
      loadedRecordId.value = latestHistoryRecord.id
    }

    // Auto voice output readout if enabled
    if (autoPlayTts.value) {
      nextTick(() => {
        playTtsVoice()
      })
    }
  } catch (err: any) {
    if (err?.name === 'AbortError') {
      return
    }
    showSafeError('Ошибка при анализе жалоб, попробуйте ещё раз')
  } finally {
    isAnalyzing.value = false
    analysisAbortController = null
  }
}


// Voice recording triggers (SaluteSpeech API STT)
async function toggleSpeechRecording() {
  if (isRecording.value) {
    stopRecording()
  } else {
    await startRecording()
  }
}

async function startRecording() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
    activeStream = stream
    leftChannel = []
    
    const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext
    audioCtx = new AudioContextClass()
    if (audioCtx.state === 'suspended') {
      await audioCtx.resume()
    }
    recordingSampleRate = audioCtx.sampleRate
    micSource = audioCtx.createMediaStreamSource(stream)
    
    scriptProcessor = audioCtx.createScriptProcessor(4096, 1, 1)
    
    scriptProcessor.onaudioprocess = (event) => {
      if (!isRecording.value) return
      const inputBuffer = event.inputBuffer.getChannelData(0)
      leftChannel.push(new Float32Array(inputBuffer))
    }
    
    micSource.connect(scriptProcessor)
    scriptProcessor.connect(audioCtx.destination)
    
    isRecording.value = true
    recordingDuration.value = 0
    recordingTimer = setInterval(() => {
      recordingDuration.value++
    }, 1000)
  } catch {
    showNotification('Нет доступа к микрофону – проверьте разрешения в браузере', 'error')
  }
}

function stopRecording() {
  if (!isRecording.value) return

  isRecording.value = false

  if (recordingTimer) {
    clearInterval(recordingTimer)
    recordingTimer = null
  }

  // Дождаться последнего onaudioprocess перед разбором буфера.
  window.setTimeout(async () => {
    if (activeStream) {
      activeStream.getTracks().forEach((track) => track.stop())
      activeStream = null
    }

    if (scriptProcessor) {
      scriptProcessor.disconnect()
      scriptProcessor.onaudioprocess = null
      scriptProcessor = null
    }
    if (micSource) {
      micSource.disconnect()
      micSource = null
    }
    if (audioCtx) {
      await audioCtx.close()
      audioCtx = null
    }

    if (leftChannel.length === 0) {
      showNotification('Запись пустая – удерживайте кнопку дольше и говорите ближе к микрофону', 'warning')
      return
    }

    const mergedBuffer = mergeBuffers(leftChannel)
    const normalizedBuffer = normalizeAudioBuffer(mergedBuffer)
    const downsampledBuffer = downsampleBuffer(normalizedBuffer, 16000)
    const wavBlob = encodeWAV(downsampledBuffer, 16000)

    leftChannel = []
    sendVoiceBlobToSTT(wavBlob)
  }, 100)
}

// Helpers for WAV encoding and downsampling
function normalizeAudioBuffer(buffer: Float32Array): Float32Array {
  let peak = 0
  for (let i = 0; i < buffer.length; i++) {
    const sample = buffer[i]
    if (sample !== undefined) {
      peak = Math.max(peak, Math.abs(sample))
    }
  }

  if (peak < 0.001) {
    return buffer
  }

  if (peak >= 0.85) {
    return buffer
  }

  const gain = 0.9 / peak
  const normalized = new Float32Array(buffer.length)
  for (let i = 0; i < buffer.length; i++) {
    const sample = buffer[i]
    normalized[i] = sample !== undefined ? sample * gain : 0
  }
  return normalized
}

function mergeBuffers(channelBuffer: Float32Array[]): Float32Array {
  let resultLength = 0
  for (let i = 0; i < channelBuffer.length; i++) {
    const buf = channelBuffer[i]
    if (buf) {
      resultLength += buf.length
    }
  }
  const result = new Float32Array(resultLength)
  let offset = 0
  for (let i = 0; i < channelBuffer.length; i++) {
    const buf = channelBuffer[i]
    if (buf) {
      result.set(buf, offset)
      offset += buf.length
    }
  }
  return result
}

function downsampleBuffer(buffer: Float32Array, toSampleRate: number): Float32Array {
  if (toSampleRate === recordingSampleRate) {
    return buffer
  }
  const sampleRateRatio = recordingSampleRate / toSampleRate
  const newLength = Math.round(buffer.length / sampleRateRatio)
  const result = new Float32Array(newLength)
  let offsetResult = 0
  let offsetBuffer = 0
  while (offsetResult < result.length) {
    const nextOffsetBuffer = Math.round((offsetResult + 1) * sampleRateRatio)
    let accum = 0
    let count = 0
    for (let i = offsetBuffer; i < nextOffsetBuffer && i < buffer.length; i++) {
      const val = buffer[i]
      if (val !== undefined) {
        accum += val
        count++
      }
    }
    result[offsetResult] = count > 0 ? accum / count : 0
    offsetResult++
    offsetBuffer = nextOffsetBuffer
  }
  return result
}

function encodeWAV(samples: Float32Array, sampleRate: number): Blob {
  const buffer = new ArrayBuffer(44 + samples.length * 2)
  const view = new DataView(buffer)
  
  /* RIFF identifier */
  writeString(view, 0, 'RIFF')
  /* file length */
  view.setUint32(4, 36 + samples.length * 2, true)
  /* RIFF type */
  writeString(view, 8, 'WAVE')
  /* format chunk identifier */
  writeString(view, 12, 'fmt ')
  /* format chunk length */
  view.setUint32(16, 16, true)
  /* sample format (raw PCM = 1) */
  view.setUint16(20, 1, true)
  /* channel count */
  view.setUint16(22, 1, true)
  /* sample rate */
  view.setUint32(24, sampleRate, true)
  /* byte rate (sample rate * block align) */
  view.setUint32(28, sampleRate * 2, true)
  /* block align (channel count * bytes per sample) */
  view.setUint16(32, 2, true)
  /* bits per sample */
  view.setUint16(34, 16, true)
  /* data chunk identifier */
  writeString(view, 36, 'data')
  /* data chunk length */
  view.setUint32(40, samples.length * 2, true)
  
  floatTo16BitPCM(view, 44, samples)
  
  return new Blob([view], { type: 'audio/wav' })
}

function floatTo16BitPCM(output: DataView, offset: number, input: Float32Array) {
  for (let i = 0; i < input.length; i++, offset += 2) {
    const val = input[i]
    if (val !== undefined) {
      let s = Math.max(-1, Math.min(1, val))
      output.setInt16(offset, s < 0 ? s * 0x8000 : s * 0x7FFF, true)
    }
  }
}

function writeString(view: DataView, offset: number, string: string) {
  for (let i = 0; i < string.length; i++) {
    view.setUint8(offset + i, string.charCodeAt(i))
  }
}

async function sendVoiceBlobToSTT(blob: Blob) {
  speechRecognizing.value = true
  try {
    const res = await fetch(`${API_BASE}/api/speech/recognize`, {
      method: 'POST',
      headers: {
        'Content-Type': blob.type,
        'Session-Id': sessionId.value
      },
      body: blob
    })
    
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data = await res.json()
    
    if (data.success && data.text) {
      if (complaintText.value.trim()) {
        complaintText.value = complaintText.value.trim() + ' ' + data.text
      } else {
        complaintText.value = data.text
      }
      nextTick(() => resizeTextarea())
    } else {
      showNotification('Голос не распознан – запишите сообщение ещё раз', 'warning')
    }
  } catch (err) {
    showSafeError('Не удалось распознать речь, проверьте микрофон')
  } finally {
    speechRecognizing.value = false
  }
}

// Speak outcome text synthesis (SaluteSpeech API)
async function playTtsVoice() {
  if (!analysisResult.value || !analysisResult.value.results.length) return
  if (isSynthesizing.value) {
    stopSynthesizing()
    return
  }

  isSynthesizing.value = true
  const resultsToVoice = filteredResults.value
  
  let speechText = ''
  if (resultsToVoice.length > 0) {
    const maxThreatLevel = Math.max(...resultsToVoice.map(r => r.threatLevel))
    if (maxThreatLevel > 0) {
      let parts = []
      for (const [i, d] of resultsToVoice.entries()) {
        const threatText = getThreatLabel(d.threatLevel).toLowerCase()
        if (i === 0) {
          parts.push(`Наиболее вероятным заболеванием является ${d.disease}, уровень угрозы: ${threatText}.`)
        } else if (i === 1) {
          parts.push(`Далее по степени вероятности следует ${d.disease}, уровень угрозы: ${threatText}.`)
        } else if (i === 2) {
          parts.push(`Затем идет ${d.disease}, уровень угрозы: ${threatText}.`)
        } else if (i === 3) {
          parts.push(`Следующее возможное заболевание — ${d.disease}, уровень угрозы: ${threatText}.`)
        } else if (i === 4) {
          parts.push(`И на пятом месте — ${d.disease}, уровень угрозы: ${threatText}.`)
        }
      }
      parts.push(`Рекомендация: ${getThreatAdvice(maxThreatLevel)}`)
      if (maxThreatLevel === 3) {
        parts.push('Вы можете вызвать экстренную помощь по номерам 112 или 103.')
      }
      speechText = parts.join(' ')
    } else {
      speechText = `По результатам анализа заболеваний не выявлено. Рекомендация: ${getThreatAdvice(0)}`
    }
  } else {
    speechText = `По результатам анализа заболеваний не выявлено. Рекомендация: ${getThreatAdvice(0)}`
  }

  try {
    let url = ttsCache.get(speechText)
    if (!url) {
      const res = await apiFetch('/api/speech/synthesize', {
        method: 'POST',
        body: JSON.stringify({ text: speechText })
      })

      const audioBlob = await res.blob()
      url = URL.createObjectURL(audioBlob)
      ttsCache.set(speechText, url)
    }

    playingAudioUrl.value = url

    if (!audioElement.value) {
      audioElement.value = new Audio()
    }
    audioElement.value.src = url
    audioElement.value.onended = () => {
      isSynthesizing.value = false
    }
    await audioElement.value.play()
  } catch (err) {
    showSafeError('Не удалось воспроизвести голосовое сообщение')
    isSynthesizing.value = false
  }
}

function stopSynthesizing() {
  if (audioElement.value) {
    audioElement.value.pause()
  }
  isSynthesizing.value = false
}

// Helper to sort symptoms in a disease card so that matched symptoms appear first
function getSortedDiseaseSymptoms(diseaseSymptoms: string[] | undefined) {
  if (!diseaseSymptoms) return []
  return [...diseaseSymptoms].sort((a, b) => {
    const aExt = (analysisResult.value?.extractedSymptoms || []).some(s => s.toLowerCase() === a.toLowerCase())
    const bExt = (analysisResult.value?.extractedSymptoms || []).some(s => s.toLowerCase() === b.toLowerCase())
    const aAss = (analysisResult.value?.assumedSymptoms || []).some(s => s.toLowerCase() === a.toLowerCase())
    const bAss = (analysisResult.value?.assumedSymptoms || []).some(s => s.toLowerCase() === b.toLowerCase())
    
    const scoreA = aExt ? 2 : (aAss ? 1 : 0)
    const scoreB = bExt ? 2 : (bAss ? 1 : 0)
    return scoreB - scoreA
  })
}

function triggerPdfDownload(blob: Blob, serverFilename?: string) {
  const urlBlob = URL.createObjectURL(blob)
  let filename = serverFilename
  if (!filename) {
    const now = new Date()
    const pad = (n: number) => String(n).padStart(2, '0')
    const timestamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`
    filename = `OphthalmoGuide_${timestamp}.pdf`
  }

  const a = document.createElement('a')
  a.href = urlBlob
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(urlBlob)
}

function resolvePdfSessionId(record?: SessionHistoryRecord): string {
  if (record?.sessionId) return record.sessionId
  const loadedId = loadedRecordId.value
  if (loadedId) {
    const match =
      history.value.find(r => r.id === loadedId) ??
      adminHistory.value.find(r => r.id === loadedId)
    if (match?.sessionId) return match.sessionId
  }
  return sessionId.value
}

async function fetchPdfBlob(
  options: { recordId?: string; recordSessionId?: string } = {}
): Promise<{ blob: Blob; filename: string }> {
  const headers: Record<string, string> = {
    'Session-Id': options.recordSessionId || sessionId.value
  }

  let url = `${API_BASE}/api/report/pdf`
  const targetId = options.recordId || loadedRecordId.value
  if (targetId) {
    url += `?id=${encodeURIComponent(targetId)}`
  }

  const response = await fetch(url, { method: 'GET', headers })
  if (!response.ok) {
    await response.text()
    throw new Error('pdf_request_failed')
  }

  const blob = await response.blob()
  let filename = ''
  const disposition = response.headers.get('content-disposition')
  if (disposition && disposition.indexOf('attachment') !== -1) {
    const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/
    const matches = filenameRegex.exec(disposition)
    if (matches != null && matches[1]) {
      filename = matches[1].replace(/['"]/g, '')
    }
  }

  if (filename) {
    try {
      filename = decodeURIComponent(filename)
    } catch {}
  }

  return { blob, filename }
}

async function downloadPdfReport(record?: SessionHistoryRecord) {
  const recordId = record?.id ?? loadedRecordId.value ?? undefined
  const recordSessionId = resolvePdfSessionId(record)

  try {
    const { blob, filename } = await fetchPdfBlob({ recordId, recordSessionId })
    triggerPdfDownload(blob, filename)
  } catch {
    showNotification('Не удалось сформировать или скачать отчёт', 'error')
  }
}

// Knowledge configuration state logic
async function loadKnowledgeData(): Promise<boolean> {
  loadingKnowledge.value = true
  knowledgeLoadFailed.value = false
  try {
    const symRes = await apiFetch('/api/symptoms')
    const loadedSymptoms = await symRes.json()
    symptoms.value = loadedSymptoms
    originalSymptoms.value = JSON.parse(JSON.stringify(loadedSymptoms))

    const disRes = await apiFetch('/api/diseases')
    const loadedDiseases = await disRes.json()
    diseases.value = loadedDiseases.map((d: any) => ({
      name: d.name,
      threatLevel: d.threatLevel ?? 1,
      symptoms: d.symptoms?.length
        ? d.symptoms
        : (d.activeSymptoms || []).map((name: string) => ({ name, redFlag: false }))
    }))
    originalDiseases.value = JSON.parse(JSON.stringify(loadedDiseases))

    const firstDisease = diseases.value[0]
    if (firstDisease && !selectedDisease.value) {
      selectDisease(firstDisease)
    }
    return true
  } catch {
    knowledgeLoadFailed.value = true
    selectedDisease.value = null
    return false
  } finally {
    loadingKnowledge.value = false
  }
}

function selectDisease(disease: DiseaseRecord) {
  selectedDisease.value = JSON.parse(JSON.stringify(disease))
}

function updateSelectedDiseaseInList() {
  if (!selectedDisease.value) return
  const idx = diseases.value.findIndex(d => d.name === selectedDisease.value!.name)
  if (idx !== -1) {
    diseases.value[idx] = JSON.parse(JSON.stringify(selectedDisease.value))
  }
}

function toggleSymptomForSelectedDisease(symptom: string) {
  if (!selectedDisease.value) return
  if (!selectedDisease.value.symptoms) {
    selectedDisease.value.symptoms = []
  }
  const index = selectedDisease.value.symptoms.findIndex(s => s.name === symptom)
  if (index === -1) {
    selectedDisease.value.symptoms.push({ name: symptom, redFlag: false })
  } else {
    selectedDisease.value.symptoms.splice(index, 1)
  }
  updateSelectedDiseaseInList()
}

function addNewSymptom() {
  const name = newSymptomName.value.trim()
  if (!name) return
  if (symptoms.value.includes(name)) {
    return
  }
  symptoms.value.push(name)
  newSymptomName.value = ''
}

function deleteSymptom(symptom: string) {
  showConfirm(
    'Удалить симптом из базы?',
    `Вы действительно хотите полностью стереть симптом "${symptom}"? Он будет убран из настроек всех заболеваний.`,
    () => {
      symptoms.value = symptoms.value.filter(s => s !== symptom)
      diseases.value.forEach(d => {
        d.symptoms = d.symptoms.filter(s => s.name !== symptom)
      })
      if (selectedDisease.value) {
        selectedDisease.value.symptoms = selectedDisease.value.symptoms.filter(s => s.name !== symptom)
      }
    },
    'Удалить симптом'
  )
}

function addNewDisease() {
  const name = newDiseaseName.value.trim()
  if (!name) return
  if (diseases.value.some(d => d.name.toLowerCase() === name.toLowerCase())) {
    return
  }
  
  const newRecord: DiseaseRecord = {
    name,
    threatLevel: 1,
    symptoms: []
  }
  
  diseases.value.push(newRecord)
  selectDisease(newRecord)
  newDiseaseName.value = ''
}

function deleteDisease(diseaseName: string) {
  showConfirm(
    'Удалить заболевание?',
    `Вы действительно хотите удалить заболевание "${diseaseName}" из базы данных?`,
    () => {
      diseases.value = diseases.value.filter(d => d.name !== diseaseName)
      if (selectedDisease.value && selectedDisease.value.name === diseaseName) {
        selectedDisease.value = diseases.value.length > 0 ? JSON.parse(JSON.stringify(diseases.value[0])) : null
      }
    },
    'Удалить заболевание'
  )
}

async function saveKnowledgeToDb() {
  if (savingKnowledge.value || !isKnowledgeDirty.value) return

  savingKnowledge.value = true
  try {
    const res = await apiFetch('/api/update-data', {
      method: 'POST',
      body: {
        symptoms: symptoms.value,
        diseases: diseases.value
      }
    })
    const data = await res.json()
    if (data.success) {
      originalSymptoms.value = JSON.parse(JSON.stringify(symptoms.value))
      originalDiseases.value = JSON.parse(JSON.stringify(diseases.value))
      showNotification('Изменения в базе знаний сохранены', 'success')
    } else {
      showSafeError('Не удалось сохранить изменения в базе знаний')
    }
  } catch (err) {
    showSafeError('Не удалось сохранить изменения в базе знаний')
  } finally {
    savingKnowledge.value = false
  }
}

// Text Threat Labels
function getThreatLabel(level: number) {
  switch (level) {
    case 0: return 'Нет угрозы'
    case 1: return 'Низкий'
    case 2: return 'Средний'
    case 3: return 'Критический'
    default: return 'Неопределен'
  }
}

function getThreatAdvice(level: number): string {
  switch (level) {
    case 0:
      return 'Здоровье ваших глаз в пределах нормы. Рекомендуется проходить профилактический осмотр у офтальмолога раз в год, защищать глаза от УФ-излучения качественными солнцезащитными очками и делать регулярные перерывы при работе за компьютером. При появлении новых симптомов повторно обратитесь к системе или врачу.'
    case 1:
      return 'Выявленные симптомы могут указывать на легкие рефракционные нарушения или усталость глаз. Рекомендуется запланировать плановый визит к офтальмологу в течение ближайших недель для проверки остроты зрения и подбора коррекции. Регулярно делайте гимнастику для глаз и минимизируйте зрительное перенапряжение.'
    case 2:
      return 'Симптомы указывают на возможное развитие воспалительного или хронического заболевания глаз. Рекомендуется обратиться к офтальмологу в ближайшие 2-3 дня для очной консультации и точной диагностики. Воздержитесь от ношения контактных линз, не трите глаза руками и не используйте глазные капли без назначения врача.'
    case 3:
      return 'Данное состояние представляет непосредственную угрозу для зрения и требует экстренной медицинской помощи. Срочно, в течение суток, обратитесь в ближайший пункт неотложной офтальмологической помощи или вызовите скорую помощь. Не пытайтесь самостоятельно промывать или лечить глаз, обеспечьте ему максимальный покой.'
    default:
      return ''
  }
}

const YANDEX_MAPS_EMERGENCY_SEARCH_QUERY = 'Центр неотложной офтальмологической помощи'

function openNearestEmergencyHospitalOnMap() {
  const url = `https://yandex.ru/maps/?text=${encodeURIComponent(YANDEX_MAPS_EMERGENCY_SEARCH_QUERY)}`
  window.open(url, '_blank', 'noopener,noreferrer')
}

// Colors for SVG indicators
function getThreatColor(level: number) {
  switch (level) {
    case 0: return 'var(--color-green)'
    case 1: return 'var(--color-blue)'
    case 2: return 'var(--color-orange)'
    case 3: return 'var(--color-red)'
    default: return 'var(--color-gray)'
  }
}

function getThreatColorClass(level: number) {
  switch (level) {
    case 0: return 'threat-green'
    case 1: return 'threat-blue'
    case 2: return 'threat-orange'
    case 3: return 'threat-red'
    default: return 'threat-gray'
  }
}

// Knowledge Base filters
const filteredDiseases = computed(() => {
  const query = knowledgeSearchQuery.value.toLowerCase().trim()
  if (!query) return diseases.value
  return diseases.value.filter(d => 
    d.name.toLowerCase().includes(query) || 
    d.symptoms?.some(s => s.name.toLowerCase().includes(query))
  )
})

const filteredGlobalSymptoms = computed(() => {
  const query = knowledgeSearchQuery.value.toLowerCase().trim()
  if (!query) return symptoms.value
  return symptoms.value.filter(s => s.toLowerCase().includes(query))
})

const filteredSymptoms = computed(() => {
  const query = symptomSearchQuery.value.trim().toLowerCase()
  if (!query) return symptoms.value
  return symptoms.value.filter(s => s.toLowerCase().includes(query))
})

const filteredAdminHistory = computed(() => {
  const query = adminHistorySearch.value.trim().toLowerCase()
  if (!query) return adminHistory.value

  return adminHistory.value.filter(record => {
    const diseaseNames = record.results?.map(result => result.disease).join(' ') || ''
    const symptoms = record.detectedSymptoms?.join(' ') || ''
    return [
      record.sessionId || '',
      record.complaintText,
      symptoms,
      diseaseNames
    ].some(value => value.toLowerCase().includes(query))
  })
})

const finalFilteredAdminHistory = computed(() => {
  let list = filteredAdminHistory.value
  if (historyViewMode.value === 'table') {
    if (tableFilterDate.value) {
      const hasTime = tableFilterDate.value.includes('T')
      const filterDate = new Date(tableFilterDate.value)
      if (!isNaN(filterDate.getTime())) {
        list = list.filter(r => {
          const rDate = new Date(r.timestamp)
          const dateMatch = rDate.getFullYear() === filterDate.getFullYear() &&
                            rDate.getMonth() === filterDate.getMonth() &&
                            rDate.getDate() === filterDate.getDate()
          if (!dateMatch) return false
          if (hasTime) {
            return rDate.getHours() === filterDate.getHours() &&
                   rDate.getMinutes() === filterDate.getMinutes()
          }
          return true
        })
      }
    }
    if (tableFilterSessionId.value) {
      const sidQuery = tableFilterSessionId.value.trim().toLowerCase()
      list = list.filter(r => r.sessionId?.toLowerCase().includes(sidQuery))
    }
    if (tableFilterComplaint.value) {
      const compQuery = tableFilterComplaint.value.trim().toLowerCase()
      list = list.filter(r => r.complaintText.toLowerCase().includes(compQuery))
    }
    if (tableFilterSymptom.value) {
      const symQuery = tableFilterSymptom.value.trim().toLowerCase()
      list = list.filter(r => r.detectedSymptoms?.some(s => s.toLowerCase().includes(symQuery)))
    }
    if (tableFilterDisease.value) {
      const disQuery = tableFilterDisease.value.trim().toLowerCase()
      list = list.filter(r => r.results?.some(d => d.disease.toLowerCase().includes(disQuery)))
    }
  }
  return list
})

const uniqueSessionIds = computed(() => {
  return [...new Set(adminHistory.value.map(r => r.sessionId).filter(Boolean))].sort()
})

const uniqueHistorySymptoms = computed(() => {
  return [...new Set(adminHistory.value.flatMap(r => r.detectedSymptoms || []))].sort()
})

const uniqueHistoryDiseases = computed(() => {
  return [...new Set(adminHistory.value.flatMap(r => r.results?.map(d => d.disease) || []))].sort()
})

const isKnowledgeDirty = computed(() => {
  return JSON.stringify(symptoms.value) !== JSON.stringify(originalSymptoms.value) ||
         JSON.stringify(diseases.value) !== JSON.stringify(originalDiseases.value)
})

function startRenameDisease(name: string) {
  editingDiseaseName.value = name
  editingSymptomName.value = null
  tempEditName.value = name
}

function startRenameSymptom(name: string) {
  editingSymptomName.value = name
  editingDiseaseName.value = null
  tempEditName.value = name
}

function cancelRename() {
  editingDiseaseName.value = null
  editingSymptomName.value = null
  tempEditName.value = ''
}

function renameDisease(oldName: string) {
  const newName = tempEditName.value.trim()
  if (!newName || newName === oldName) {
    cancelRename()
    return
  }
  if (diseases.value.some(d => d.name.toLowerCase() === newName.toLowerCase() && d.name !== oldName)) {
    return
  }
  
  diseases.value = diseases.value.map(d => {
    if (d.name === oldName) {
      d.name = newName
    }
    return d
  })
  
  if (selectedDisease.value && selectedDisease.value.name === oldName) {
    selectedDisease.value.name = newName
  }
  
  cancelRename()
}

function renameSymptom(oldName: string) {
  const newName = tempEditName.value.trim()
  if (!newName || newName === oldName) {
    cancelRename()
    return
  }
  if (symptoms.value.some(s => s.toLowerCase() === newName.toLowerCase() && s !== oldName)) {
    return
  }
  
  symptoms.value = symptoms.value.map(s => s === oldName ? newName : s)
  
  diseases.value.forEach(d => {
    d.symptoms = d.symptoms.map(s => s.name === oldName ? { ...s, name: newName } : s)
  })
  
  if (selectedDisease.value) {
    selectedDisease.value.symptoms = selectedDisease.value.symptoms.map(s =>
      s.name === oldName ? { ...s, name: newName } : s
    )
  }
  
  cancelRename()
}

function handleAddItem() {
  const name = newItemName.value.trim()
  if (!name) return
  
  if (sidebarActiveTab.value === 'diseases') {
    if (diseases.value.some(d => d.name.toLowerCase() === name.toLowerCase())) {
      return
    }
    const newRecord: DiseaseRecord = {
      name,
      threatLevel: 1,
      symptoms: []
    }
    diseases.value.push(newRecord)
    selectDisease(newRecord)
    newItemName.value = ''
  } else {
    if (symptoms.value.includes(name)) {
      return
    }
    symptoms.value.push(name)
    newItemName.value = ''
  }
}

function selectAllFilteredSymptoms() {
  if (!selectedDisease.value) return
  filteredSymptoms.value.forEach(symptom => {
    if (!isSymptomSelected(selectedDisease.value!, symptom)) {
      selectedDisease.value!.symptoms.push({ name: symptom, redFlag: false })
    }
  })
  updateSelectedDiseaseInList()
}

function deselectAllFilteredSymptoms() {
  if (!selectedDisease.value) return
  selectedDisease.value.symptoms = selectedDisease.value.symptoms.filter(
    s => !filteredSymptoms.value.includes(s.name)
  )
  updateSelectedDiseaseInList()
}

// Format dates
function formatDate(isoString: string) {
  try {
    const date = new Date(isoString)
    return date.toLocaleString('ru-RU', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  } catch (e) {
    return isoString
  }
}

// Reset validation state when user types
watch(complaintText, () => {
  if (submissionError.value) {
    submissionError.value = ''
  }
})

// Watchers
watch(activeTab, (newTab) => {
  if (!isAdmin.value) return
  if (newTab === 'knowledge') {
    loadKnowledgeData()
  } else if (newTab === 'history') {
    historyTo.value = toLocalInputValue(new Date())
    historyFrom.value = toLocalInputValue(new Date(Date.now() - 24 * 60 * 60 * 1000))
    loadAdminHistory()
  } else if (newTab === 'diagnostics') {
    loadHistory()
  }
})

function onPopState() {
  void checkAdminRoute()
}

onMounted(async () => {
  const loggedOut = sessionStorage.getItem('logged_out_notification')
  if (loggedOut) {
    showNotification('Вы успешно вышли из системы', 'success')
    sessionStorage.removeItem('logged_out_notification')
  }

  mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
  isDark.value = mediaQuery.matches
  mediaQuery.addEventListener('change', updateTheme)

  initSession()
  await fetchConfig()
  await handleAuthentikCallback()
  loadHistory()
  await checkAdminRoute()
  window.addEventListener('popstate', onPopState)
  connectivityMonitor = createConnectivityMonitor(handleConnectivityChange)

  adminSessionCheckInterval = setInterval(() => {
    void validateAdminSessionOnly()
  }, 10000)
})

onUnmounted(() => {
  mediaQuery?.removeEventListener('change', updateTheme)
  window.removeEventListener('popstate', onPopState)
  connectivityMonitor?.stop()
  connectivityMonitor = null
  if (restoredTimeout) clearTimeout(restoredTimeout)
  if (adminSessionCheckInterval) clearInterval(adminSessionCheckInterval)
  if (recordingTimer) clearInterval(recordingTimer)
  stopSynthesizing()
})
</script>

<template>
  <!-- Connection Status Banner -->
  <Transition name="slide-down">
    <div v-if="!isOnline" class="offline-banner" role="alert">
      <span class="offline-banner-icon offline-banner-icon--pulse">
        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M12 20h.01" />
          <path d="M8.5 16.429a5 5 0 0 1 7 0" />
          <path d="M5 12.859a10 10 0 0 1 5.17-2.69" />
          <path d="M19 12.859a10 10 0 0 0-2.007-1.523" />
          <path d="M2 8.82a15 15 0 0 1 4.177-2.643" />
          <path d="M22 8.82a15 15 0 0 0-11.288-3.764" />
          <path d="m2 2 20 20" />
        </svg>
      </span>
      <span class="offline-banner-text">Что-то не так с соединением</span>
    </div>
    <div v-else-if="showRestoredBanner" class="offline-banner online-restored-banner" role="status">
      <span class="offline-banner-icon offline-banner-icon--restored">
        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2.25" fill="none" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <polyline class="offline-banner-check-mark" points="4 12 9 17 20 6" />
        </svg>
      </span>
      <span class="offline-banner-text">Соединение восстановлено</span>
    </div>
  </Transition>

  <div 
    class="ophthalmo-app" 
    :class="{ 
      'ophthalmo-app--with-bottom-nav': isAdmin,
      'ophthalmo-app--full-width': isAdmin,
      'ophthalmo-app--admin-knowledge': isAdmin && activeTab === 'knowledge'
    }"
  >
    <!-- Floating Admin entry corner -->
    <div v-if="!isAdmin && !isAdminUnauthorized" class="admin-entry-corner">
      <a 
        href="/admin/" 
        class="btn-admin-login" 
        aria-label="Открыть панель управления"
        @click="navigateToAdmin"
      >
        <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2.5" fill="none">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
        Панель управления
      </a>
    </div>

    <!-- Notivue Notifications container -->
    <Notivue v-slot="item">
      <Notifications :item="item" :theme="isDark ? darkTheme : lightTheme" />
    </Notivue>

    <!-- Confirm Modal Overlay System -->
    <ConfirmModal
      v-if="confirmModal.open"
      :title="confirmModal.title"
      :message="confirmModal.message"
      :confirm-text="confirmModal.confirmText"
      @cancel="confirmModal.open = false"
      @confirm="confirmModal.onConfirm"
    />


    <!-- Header Block (Only visible to Admin or if Unauthorized Admin Attempt) -->
    <header v-if="isAdmin || isAdminUnauthorized" class="app-header-premium">
      <!-- Desktop navigation tabs -->
      <nav v-if="isAdmin" class="app-nav-premium app-nav-desktop" aria-label="Навигация администратора">
        <button 
          class="nav-tab" 
          :class="{ active: activeTab === 'diagnostics' }" 
          @click="activeTab = 'diagnostics'"
        >
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
            <line x1="16" y1="13" x2="8" y2="13"></line>
            <line x1="16" y1="17" x2="8" y2="17"></line>
          </svg>
          <span>Диагностика</span>
          <span class="tab-indicator" v-if="activeTab === 'diagnostics'"></span>
        </button>
        <button 
          class="nav-tab" 
          :class="{ active: activeTab === 'knowledge' }" 
          @click="activeTab = 'knowledge'"
        >
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
            <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
            <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
          </svg>
          <span>База знаний</span>
          <span class="tab-indicator" v-if="activeTab === 'knowledge'"></span>
        </button>
        <button 
          class="nav-tab" 
          :class="{ active: activeTab === 'history' }"
          @click="activeTab = 'history'"
        >
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
            <circle cx="12" cy="12" r="10"></circle>
            <polyline points="12 6 12 12 16 14"></polyline>
          </svg>
          <span>История взаимодействий</span>
          <span class="tab-indicator" v-if="activeTab === 'history'"></span>
        </button>

        <a 
          v-if="authConfig?.enabled"
          :href="authentikUserPortalUrl"
          target="_blank"
          class="nav-tab nav-tab-settings" 
        >
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
            <circle cx="12" cy="12" r="3"></circle>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
          </svg>
          <span>Настройки пользователя</span>
        </a>
        <button 
          v-if="authConfig?.enabled"
          class="nav-tab nav-tab-logout" 
          @click="logoutAdmin"
        >
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16 17 21 12 16 7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
          <span>Выйти</span>
        </button>
      </nav>

      <!-- Desktop: settings / logout when logged in but not in admin group -->
      <nav
        v-if="isAdminUnauthorized && authConfig?.enabled"
        class="app-nav-premium app-nav-desktop"
        aria-label="Действия учётной записи"
      >
        <a
          :href="authentikUserPortalUrl"
          target="_blank"
          class="nav-tab nav-tab-settings"
        >
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
            <circle cx="12" cy="12" r="3"></circle>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
          </svg>
          <span>Настройки пользователя</span>
        </a>
        <button
          class="nav-tab nav-tab-logout"
          @click="logoutAdmin"
        >
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16 17 21 12 16 7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
          <span>Выйти</span>
        </button>
      </nav>

      <!-- Mobile: settings / logout only (main tabs move to bottom bar) -->
      <div v-if="(isAdmin || isAdminUnauthorized) && authConfig?.enabled" class="app-admin-mobile-actions">
        <a 
          :href="authentikUserPortalUrl"
          target="_blank"
          class="nav-tab nav-tab-settings" 
          aria-label="Настройки пользователя"
          title="Настройки пользователя"
        >
          <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
            <circle cx="12" cy="12" r="3"></circle>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
          </svg>
        </a>
        <button 
          class="nav-tab nav-tab-logout" 
          @click="logoutAdmin"
          aria-label="Выйти"
          title="Выйти"
        >
          <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16 17 21 12 16 7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
        </button>
      </div>
    </header>

    <!-- Workspace View Panels -->
    <main
      class="app-workspace-container"
      :class="{ 'with-admin-nav': isAdmin || isAdminUnauthorized }"
    >
      <Transition name="admin-panel-slide" mode="out-in">

      <!-- State: Admin Unauthorized (Access Denied) -->
        <section v-if="isAdminUnauthorized" key="unauthorized" class="diagnostics-panel-centered admin-workspace-panel">
          <div class="centered-workspace-card">
            
            <AppBrand danger />

            <div class="workspace-card-wrapper admin-access-denied-card">
              <div class="admin-access-denied-icon" aria-hidden="true">
                <svg
                  viewBox="0 0 24 24"
                  width="36"
                  height="36"
                  stroke="currentColor"
                  stroke-width="2"
                  fill="none"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <circle cx="12" cy="12" r="10"></circle>
                  <line x1="12" y1="8" x2="12" y2="12"></line>
                  <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
              </div>
              <h2 class="admin-access-denied-title">
                Доступ ограничен
              </h2>
              <p class="admin-access-denied-text">
                Вам не выписали рецепт для просмотра этого раздела.
              </p>
            </div>

          </div>
        </section>

        <!-- Tab 1: Centered Diagnostic Form -->
        <section
          v-else-if="activeTab === 'diagnostics'"
          key="diagnostics"
          class="diagnostics-panel-centered admin-workspace-panel"
          :class="{ 'diagnostics-has-results': !!(analysisResult && !isAnalyzing) }"
        >
        <div class="centered-workspace-card">
          
          <!-- Centered Brand Logo, Title & Subtitle -->
          <AppBrand
            clickable
            subtitle="Информационно-справочная система предварительной диагностики офтальмологических заболеваний"
            @reset="resetToNewAnalysis"
          />

          <!-- Outer Card -->
          <div class="workspace-card-wrapper">
            
            <!-- Sleek styled textarea wrapper with reactive state borders -->
            <div class="textarea-container-premium" :class="borderStateClass">
              <textarea 
                ref="textareaRef"
                v-model="complaintText" 
                placeholder="Расскажите, что Вы чувствуете? Например: зуд и жжение век, покраснение, помутнение зрения..."
                rows="5"
                :disabled="isAnalyzing"
                @input="resizeTextarea"
              ></textarea>


              
              <!-- Bottom Toolbar inside input box -->
              <div class="textarea-toolbar">
                
                <!-- Left aligned STT and Auto-TTS Controls -->
                <div class="diagnostic-actions-left">
                  
                  <div class="audio-controls-group">
                    <!-- Clean Round Microphone Button -->
                    <div class="microphone-wrapper-group">
                      <button 
                        class="btn-mic-record-clean" 
                        :class="{ recording: isRecording, converting: speechRecognizing }"
                        @click="toggleSpeechRecording"
                        :disabled="isAnalyzing"
                        title="Голосовой ввод жалоб"
                        :aria-label="isRecording ? 'Остановить запись жалоб' : 'Начать голосовой ввод жалоб'"
                      >
                        <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none">
                          <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path>
                          <path d="M19 10v2a7 7 0 0 1-14 0v-2"></path>
                          <line x1="12" y1="19" x2="12" y2="23"></line>
                          <line x1="8" y1="23" x2="16" y2="23"></line>
                        </svg>
                      </button>
                    </div>

                    <!-- Auto play TTS dynamic toggler (Speaker button) -->
                    <button 
                      class="btn-speaker-auto-play" 
                      :class="{ active: autoPlayTts }"
                      @click="autoPlayTts = !autoPlayTts"
                      title="Автоматически озвучивать результаты диагностики"
                      :aria-pressed="autoPlayTts"
                      aria-label="Автоматически озвучивать результаты диагностики"
                    >
                      <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none">
                        <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon>
                        <path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"></path>
                      </svg>
                    </button>
                  </div>

                  <!-- Play/Stop TTS toggle: visible when results exist -->
                  <button
                    v-if="analysisResult && !isAnalyzing"
                    class="btn-tts-toggle"
                    :class="{ playing: isSynthesizing }"
                    @click="isSynthesizing ? stopSynthesizing() : playTtsVoice()"
                    :title="isSynthesizing ? 'Остановить воспроизведение' : 'Озвучить результат'"
                    :aria-label="isSynthesizing ? 'Остановить озвучивание результата' : 'Озвучить результат диагностики'"
                  >
                    <!-- Stop icon -->
                    <svg v-if="isSynthesizing" viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
                      <rect x="6" y="6" width="12" height="12" rx="1.5"></rect>
                    </svg>
                    <!-- Play icon (triangle) -->
                    <svg v-else viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
                      <polygon points="6 4 20 12 6 20 6 4"></polygon>
                    </svg>
                  </button>

                  <span v-if="isRecording" class="status-tip">Идет запись...</span>
                  <span v-else-if="speechRecognizing" class="status-tip">Распознавание...</span>
                </div>

                <!-- Clear text button (ONLY the input field).
                     Click the eye logo in the header for full reset (text + analysis result). -->
                <button 
                  class="btn-clean-text" 
                  @click="clearComplaintText" 
                  :disabled="!complaintText || isAnalyzing"
                  aria-label="Очистить текст жалобы"
                >
                  Очистить
                </button>
              </div>
            </div>

            <!-- Submit diagnostic action -->
            <div class="submit-action-row">
              <button 
                class="btn-primary-submit-diagnostic" 
                @click="analyzeComplaint" 
                :disabled="isAnalyzing"
              >
                <span v-if="isAnalyzing" class="btn-loader-group">
                  <span class="ring-loader-light"></span>
                  <span>Анализируем...</span>
                </span>
                <span v-else>Начать диагностику</span>
              </button>
            </div>
          </div>


          <!-- Diagnostic output -->
          <div 
            class="results-transition-wrapper" 
            :class="{ 'results-visible': analysisResult && !isAnalyzing }"
          >
            <div class="results-card-premium" v-if="analysisResult">
              
              <!-- Action bar -->
              <div class="results-header-actions">
                <h3>Заключение предварительного разбора</h3>
                
                <div class="action-btn-row">

                  <!-- Download diagnostic report -->
                  <button class="btn-export-pdf-report" @click="() => downloadPdfReport()">
                    <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" stroke-width="2.5" fill="none">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                      <polyline points="7 10 12 15 17 10"></polyline>
                      <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                    Скачать отчёт
                  </button>
                </div>
              </div>

              <!-- Detected symptoms block -->
              <div class="results-symptoms-layout">
                <span class="results-label-caps">Выделенные клинические симптомы</span>
                <div class="symptom-tag-chips-group">
                  <span v-for="symptom in analysisResult.extractedSymptoms" :key="symptom" class="symptom-pill-premium direct-pill">
                    <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" stroke-width="3" fill="none" class="check-symptom-svg">
                      <polyline points="20 6 9 17 4 12"></polyline>
                    </svg>
                    {{ symptom }}
                  </span>
                  <p v-if="!analysisResult.extractedSymptoms.length" class="empty-outcome-text">
                    Симптоматические проявления в тексте жалобы не выделены.
                  </p>
                </div>

                <!-- Assumed/inferred symptoms by LLM -->
                <template v-if="analysisResult.assumedSymptoms && analysisResult.assumedSymptoms.length">
                  <span class="results-label-caps" style="margin-top: 1.25rem;">Косвенные клинические симптомы</span>
                  <div class="symptom-tag-chips-group assumed-symptoms-group">
                    <span v-for="symptom in analysisResult.assumedSymptoms" :key="symptom" class="symptom-pill-premium assumed-pill">
                      <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" stroke-width="2.5" fill="none" class="assumed-symptom-svg">
                        <polyline points="20 6 9 17 4 12"></polyline>
                      </svg>
                      {{ symptom }}
                    </span>
                  </div>
                </template>
              </div>

              <!-- Probable Pathology outcome cards -->
              <div class="results-diseases-layout">
                <span class="results-label-caps">Предполагаемые причины</span>
                <div class="outcome-tiles-list">
                  
                  <div 
                    v-for="(match, index) in filteredResults" 
                    :key="index"
                    class="outcome-tile-premium outcome-tile-premium-interactive"
                    :class="{ 
                      'tile-threat-green': match.threatLevel === 0,
                      'tile-threat-blue': match.threatLevel === 1,
                      'tile-threat-orange': match.threatLevel === 2,
                      'tile-threat-red': match.threatLevel === 3
                    }"
                    @click="toggleDiseaseExpand(index)"
                  >
                    <div class="tile-header-flex">
                      <div class="disease-meta-flex" style="align-items: center;">
                        <span class="disease-name-bold">{{ match.disease }}</span>
                        <span class="threat-micro-badge" :class="getThreatColorClass(match.threatLevel)">
                          {{ getThreatLabel(match.threatLevel) }}
                        </span>
                        <!-- Chevron icon indicator -->
                        <span class="disease-chevron-icon" :class="{ 'chevron-rotated': expandedDiseaseIndex === index }">
                          <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" stroke-width="3" fill="none" style="display: block;">
                            <polyline points="6 9 12 15 18 9"></polyline>
                          </svg>
                        </span>
                      </div>
                    </div>

                    <div class="tile-footer-flex">
                      <span>Совпадение по симптомам: <strong>{{ match.matchPercentage }}%</strong> ({{ match.matchingSymptomsCount }} из {{ match.totalDiseaseSymptomsCount }} симптомов)</span>
                      <div class="diagnosis-priority-badge" :class="priorityClass(match)" :title="`Относительный дифференциальный вес`">
                        <span class="priority-label">Дифференциальный вес:</span>
                        <span class="priority-value">{{ formatDifferentialWeight(match) }}</span>
                      </div>
                    </div>

                    <!-- Expandable detailed symptoms overview -->
                    <div 
                      v-if="expandedDiseaseIndex === index" 
                      class="disease-expandable-panel"
                      @click.stop
                    >
                      <div class="expandable-divider"></div>
                      <template v-if="shouldShowClinicalMapping(match)">
                        <span class="results-label-caps" style="margin-bottom: 0.65rem; display: block;">Сопоставление клинической картины:</span>
                        <!-- Clinical picture mapping (unified list of chips) -->
                        <div class="expandable-symptoms-chips-group" style="margin-bottom: 1rem;">
                          <span 
                            v-for="symptom in getSortedDiseaseSymptoms(match.allDiseaseSymptoms)" 
                            :key="symptom"
                            class="symptom-pill-premium"
                            :class="{ 
                              'symptom-match-extracted': (analysisResult?.extractedSymptoms || []).some(s => s.toLowerCase() === symptom.toLowerCase()),
                              'symptom-match-assumed': (analysisResult?.assumedSymptoms || []).some(s => s.toLowerCase() === symptom.toLowerCase()),
                              'symptom-unmatched': !(analysisResult?.extractedSymptoms || []).some(s => s.toLowerCase() === symptom.toLowerCase()) && !(analysisResult?.assumedSymptoms || []).some(s => s.toLowerCase() === symptom.toLowerCase())
                            }"
                          >
                            <svg 
                              v-if="(analysisResult?.extractedSymptoms || []).some(s => s.toLowerCase() === symptom.toLowerCase())" 
                              viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" stroke-width="3" fill="none" class="check-symptom-svg"
                            >
                              <polyline points="20 6 9 17 4 12"></polyline>
                            </svg>
                            <svg 
                              v-else-if="(analysisResult?.assumedSymptoms || []).some(s => s.toLowerCase() === symptom.toLowerCase())" 
                              viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" stroke-width="2.5" fill="none" class="assumed-symptom-svg"
                            >
                              <polyline points="20 6 9 17 4 12"></polyline>
                            </svg>
                            <svg
                              v-else
                              viewBox="0 0 24 24"
                              width="10"
                              height="10"
                              stroke="currentColor"
                              stroke-width="2"
                              fill="none"
                              stroke-linecap="round"
                              stroke-linejoin="round"
                              class="unmatched-symptom-svg"
                              aria-hidden="true"
                            >
                              <circle cx="12" cy="12" r="10"></circle>
                              <line x1="15" y1="9" x2="9" y2="15"></line>
                              <line x1="9" y1="9" x2="15" y2="15"></line>
                            </svg>
                            {{ symptom }}
                          </span>
                        </div>
                        <div class="expandable-divider"></div>
                      </template>
                      <span class="results-label-caps" style="margin-bottom: 0.5rem; display: block;">Рекомендации и дальнейшие действия:</span>
                      <div class="threat-advice-box" :class="'advice-' + getThreatColorClass(match.threatLevel)">
                        <p class="threat-advice-text">
                          <strong>Уровень угрозы: {{ getThreatLabel(match.threatLevel) }}</strong><br/>
                          {{ getThreatAdvice(match.threatLevel) }}
                        </p>
                        <div v-if="match.threatLevel === 3" class="threat-advice-critical-extra">
                          <p class="threat-advice-text threat-advice-text-phones">
                            <a href="tel:112" class="threat-advice-inline-link" @click.stop aria-label="Позвонить по номеру 112">
                              <strong>112</strong>
                            </a>
                            – единый номер вызова экстренных оперативных служб<br>
                            <a href="tel:103" class="threat-advice-inline-link" @click.stop aria-label="Позвонить по номеру 103">
                              <strong>103</strong>
                            </a>
                            – общефедеральный номер вызова скорой медицинской помощи
                          </p>
                          <button
                            type="button"
                            class="btn-find-hospital-maps"
                            @click.stop="openNearestEmergencyHospitalOnMap"
                          >
                            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2.5" fill="none" aria-hidden="true">
                              <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path>
                              <circle cx="12" cy="10" r="3"></circle>
                            </svg>
                            Найти пункт неотложной помощи на карте
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div v-if="!filteredResults.length" class="empty-outcome-text">
                    Пересечений симптомов с клинической базой заболеваний не обнаружено.
                  </div>
                </div>
              </div>

            </div>
          </div>

          <!-- History list at the bottom (Visible only in diagnostics view if history has records) -->
          <div 
            v-if="history.length > 0 && !isAdminUnauthorized" 
            class="app-history-bottom-layout"
            style="margin-top: 1.5rem; max-width: none;"
          >
            <div class="history-bottom-header">
              <h3>Предыдущие сессии диагностики</h3>
            </div>
            
            <div class="history-grid-bottom">
              <div 
                v-for="record in history" 
                :key="record.id" 
                class="history-card-bottom" 
                @click="loadHistoryRecord(record)"
              >
                <div class="hist-card-title-row">
                  <span class="hist-time">{{ formatDate(record.timestamp) }}</span>
                </div>
                <p class="hist-preview-text">{{ record.complaintText }}</p>
              </div>
            </div>
          </div>

        </div>
      </section>

      <!-- Tab 2: Disease-symptom configuration editor (Only Admin) -->
      <section v-else-if="activeTab === 'knowledge' && isAdmin" key="knowledge" class="panel-knowledge-premium admin-workspace-panel">
        <div class="knowledge-grid-layout">
          
          <!-- Left Column: Diseases/Symptoms unified sidebar manager -->
          <div class="card diseases-list-card-premium">
            <!-- Sidebar tabs -->
            <div class="sidebar-tabs-container">
              <button 
                type="button"
                class="sidebar-tab-btn" 
                :class="{ active: sidebarActiveTab === 'diseases' }"
                @click="sidebarActiveTab = 'diseases'"
              >
                Патологии ({{ diseases.length }})
              </button>
              <button 
                type="button"
                class="sidebar-tab-btn" 
                :class="{ active: sidebarActiveTab === 'symptoms' }"
                @click="sidebarActiveTab = 'symptoms'"
              >
                Симптомы ({{ symptoms.length }})
              </button>
            </div>

            <div class="card-search-header-unified">
              <div class="search-input-wrapper-clean" style="margin-bottom: 0.75rem;">
                <input 
                  v-model="knowledgeSearchQuery" 
                  type="text" 
                  :placeholder="sidebarActiveTab === 'diseases' ? 'Поиск заболевания...' : 'Поиск симптома...'" 
                />
              </div>
              
              <!-- Add new item inline form -->
              <div class="add-disease-inline-form">
                <input 
                  v-model="newItemName"
                  type="text"
                  :placeholder="sidebarActiveTab === 'diseases' ? 'Новая патология...' : 'Новый симптом...'"
                  @keyup.enter="handleAddItem"
                />
                <button 
                  class="btn-add-item" 
                  @click="handleAddItem"
                >
                  +
                </button>
              </div>
            </div>

            <!-- List items: Diseases tab -->
            <div v-if="sidebarActiveTab === 'diseases'" class="diseases-scroller-premium">
              <div v-if="loadingKnowledge" class="knowledge-loader-spinner">Загрузка данных...</div>
              <div 
                v-for="d in filteredDiseases" 
                :key="d.name" 
                class="disease-manager-tile"
                :class="{ active: selectedDisease && selectedDisease.name === d.name }"
                @click="selectDisease(d)"
              >
                <div class="tile-content-group">
                  <div v-if="editingDiseaseName === d.name" class="inline-edit-form" @click.stop>
                    <input 
                      v-model="tempEditName" 
                      type="text" 
                      class="input-inline-edit"
                      @keyup.enter="renameDisease(d.name)"
                      @keyup.esc="cancelRename"
                    />
                    <button class="btn-inline-save" @click="renameDisease(d.name)">✓</button>
                    <button class="btn-inline-cancel" @click="cancelRename">✕</button>
                  </div>
                  <div v-else class="d-meta-row">
                    <div class="tile-title-line">
                      <span class="d-label-name">{{ d.name }}</span>
                      <button class="btn-tile-edit" @click.stop="startRenameDisease(d.name)" title="Редактировать название" :aria-label="`Переименовать заболевание ${d.name}`">
                        <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="2" fill="none">
                          <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                          <path d="M18.5 2.5a2.121 2.121 0 1 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                        </svg>
                      </button>
                    </div>
                    <div class="tile-info-line">
                      <span class="threat-badge-mini" :class="getThreatColorClass(d.threatLevel)">
                        {{ getThreatLabel(d.threatLevel) }}
                      </span>
                      <span class="symptom-count-badge">
                        {{ d.symptoms?.length || 0 }} признаков
                      </span>
                    </div>
                  </div>
                </div>
                  <button class="btn-tile-delete" @click.stop="deleteDisease(d.name)" title="Удалить заболевание" :aria-label="`Удалить заболевание ${d.name}`">
                  &times;
                </button>
              </div>
            </div>

            <!-- List items: Symptoms tab -->
            <div v-else class="diseases-scroller-premium">
              <div v-if="loadingKnowledge" class="knowledge-loader-spinner">Загрузка данных...</div>
              <div 
                v-for="s in filteredGlobalSymptoms" 
                :key="s" 
                class="disease-manager-tile symptom-tile"
              >
                <div class="tile-content-group">
                  <div v-if="editingSymptomName === s" class="inline-edit-form" @click.stop>
                    <input 
                      v-model="tempEditName" 
                      type="text" 
                      class="input-inline-edit"
                      @keyup.enter="renameSymptom(s)"
                      @keyup.esc="cancelRename"
                    />
                    <button class="btn-inline-save" @click="renameSymptom(s)">✓</button>
                    <button class="btn-inline-cancel" @click="cancelRename">✕</button>
                  </div>
                  <div v-else class="d-meta-row">
                    <div class="tile-title-line">
                      <span class="d-label-name">{{ s }}</span>
                      <button class="btn-tile-edit" @click.stop="startRenameSymptom(s)" title="Редактировать название" :aria-label="`Переименовать симптом ${s}`">
                        <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="2" fill="none">
                          <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                          <path d="M18.5 2.5a2.121 2.121 0 1 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                        </svg>
                      </button>
                    </div>
                  </div>
                </div>
                <button class="btn-tile-delete" @click.stop="deleteSymptom(s)" title="Удалить симптом" :aria-label="`Удалить симптом ${s}`">
                  &times;
                </button>
              </div>
            </div>

            <!-- Bottom Action Button to save changes to Valkey db -->
            <div style="margin-top: auto; padding-top: 1rem; border-top: 1px solid var(--border-color);">
              <button 
                class="btn-save-valkey-db" 
                @click="saveKnowledgeToDb" 
                :disabled="savingKnowledge || !isKnowledgeDirty"
              >
                Сохранить изменения
              </button>
            </div>

          </div>

          <!-- Right Column: load error -->
          <div
            v-if="knowledgeLoadFailed"
            class="symptom-editor-card-premium symptom-editor-empty knowledge-load-error"
          >
            <div class="knowledge-empty-icon knowledge-empty-icon--error" aria-hidden="true">
              <svg
                viewBox="0 0 24 24"
                width="32"
                height="32"
                stroke="currentColor"
                stroke-width="2"
                fill="none"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
              </svg>
            </div>
            <h3 class="knowledge-empty-title">Не удалось загрузить базу знаний</h3>
            <p class="knowledge-empty-text">
              Проверьте доступность сервера и нажмите «Повторить», чтобы загрузить патологии и симптомы снова
            </p>
            <button type="button" class="btn-bulk-action" :disabled="loadingKnowledge" @click="() => loadKnowledgeData()">
              Повторить
            </button>
          </div>

          <!-- Right Column: Detail Editor -->
          <div v-else-if="selectedDisease" class="symptom-editor-card-premium">
            <div class="editor-header-sticky-premium">
              <div class="editor-header-row">
                <div>
                  <h2 style="margin: 0; font-size: 1.25rem; font-weight: 700; color: var(--text-main);">
                    Настройка патологии: <span class="focused-disease-title">{{ selectedDisease.name }}</span>
                  </h2>
                  <p style="margin: 0.25rem 0 0 0; font-size: 0.8rem; color: var(--text-muted);">
                    Свяжите симптомы и настройте уровень угрозы для этой патологии
                  </p>
                </div>
              </div>

              <!-- Interactive segmented threat picker -->
              <div class="threat-segmented-picker">
                <span class="picker-label">Уровень угрозы</span>
                <div class="segments-container">
                  <button 
                    type="button" 
                    class="segment-btn threat-green" 
                    :class="{ active: selectedDisease.threatLevel === 0 }"
                    @click="selectedDisease.threatLevel = 0; updateSelectedDiseaseInList()"
                    :title="getThreatAdvice(0)"
                  >
                    <span class="segment-dot"></span>
                    <span>Нет угрозы</span>
                  </button>
                  <button 
                    type="button" 
                    class="segment-btn threat-blue" 
                    :class="{ active: selectedDisease.threatLevel === 1 }"
                    @click="selectedDisease.threatLevel = 1; updateSelectedDiseaseInList()"
                    :title="getThreatAdvice(1)"
                  >
                    <span class="segment-dot"></span>
                    <span>Низкий</span>
                  </button>
                  <button 
                    type="button" 
                    class="segment-btn threat-orange" 
                    :class="{ active: selectedDisease.threatLevel === 2 }"
                    @click="selectedDisease.threatLevel = 2; updateSelectedDiseaseInList()"
                    :title="getThreatAdvice(2)"
                  >
                    <span class="segment-dot"></span>
                    <span>Средний</span>
                  </button>
                  <button 
                    type="button" 
                    class="segment-btn threat-red" 
                    :class="{ active: selectedDisease.threatLevel === 3 }"
                    @click="selectedDisease.threatLevel = 3; updateSelectedDiseaseInList()"
                    :title="getThreatAdvice(3)"
                  >
                    <span class="segment-dot"></span>
                    <span>Критический</span>
                  </button>
                </div>
              </div>
            </div>

            <!-- Symptom checklist wrapper -->
            <div class="symptom-search-bar-wrapper">
              <div class="symptom-search-field">
                <input 
                  v-model="symptomSearchQuery" 
                  type="text" 
                  placeholder="Поиск симптомов для привязки..." 
                />
                <button 
                  v-if="symptomSearchQuery" 
                  class="btn-clear-search" 
                  @click="symptomSearchQuery = ''"
                >
                  &times;
                </button>
              </div>
              <div class="symptom-bulk-actions">
                <button 
                  type="button" 
                  class="btn-bulk-action" 
                  @click="selectAllFilteredSymptoms"
                >
                  Выбрать отфильтрованные
                </button>
                <button 
                  type="button" 
                  class="btn-bulk-action" 
                  @click="deselectAllFilteredSymptoms"
                >
                  Снять выбор
                </button>
              </div>
            </div>

            <span class="editor-sub-lbl">Список симптомов</span>
            <div class="symptoms-grid-checklist">
              <div class="checklist-grid">
                <div 
                  v-for="symptom in filteredSymptoms" 
                  :key="symptom" 
                  class="symptom-checkbox-card"
                  :class="{ selected: isSymptomSelected(selectedDisease, symptom) }"
                  @click="toggleSymptomForSelectedDisease(symptom)"
                >
                  <div class="checkbox-custom-wrapper">
                    <span class="checkbox-indicator"></span>
                  </div>
                  <span class="checkbox-label-text">{{ symptom }}</span>
                  <label
                    v-if="isSymptomSelected(selectedDisease, symptom)"
                    class="symptom-redflag-toggle"
                    @click.stop
                    title="Red flag – ключевой симптом (×3 к score)"
                  >
                    <input
                      type="checkbox"
                      :checked="isSymptomRedFlag(selectedDisease, symptom)"
                      @change="toggleSymptomRedFlag(symptom)"
                    />
                    <span>RF</span>
                  </label>
                </div>
              </div>
            </div>
          </div>

          <!-- Empty State (No pathology selected) -->
          <div v-else class="symptom-editor-card-premium symptom-editor-empty">
            <div class="knowledge-empty-icon knowledge-empty-icon--info" aria-hidden="true">
              <svg viewBox="0 0 24 24" width="32" height="32" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path d="M9 18h6"></path>
                <path d="M10 22h4"></path>
                <path d="M12 2a7 7 0 0 0-4 12.74V17h8v-2.26A7 7 0 0 0 12 2z"></path>
              </svg>
            </div>
            <h3 class="knowledge-empty-title">Патология не выбрана</h3>
            <p class="knowledge-empty-text">
              Выберите патологию из списка слева, чтобы настроить её симптомы и уровень угрозы.
            </p>
          </div>

        </div>
      </section>
      <section v-else-if="activeTab === 'history' && isAdmin" key="history" class="panel-knowledge-premium admin-workspace-panel">
        <div class="history-period-filter">
          <div class="history-period-fields">
            <div class="history-period-field">
              <label for="history-from">Период с</label>
              <input
                id="history-from"
                type="datetime-local"
                step="1"
                v-model="historyFrom"
                :max="historyTo"
                :disabled="loadingHistory"
              />
            </div>
            <div class="history-period-field">
              <label for="history-to">Период по</label>
              <input
                id="history-to"
                type="datetime-local"
                step="1"
                v-model="historyTo"
                :min="historyFrom"
                :disabled="loadingHistory"
              />
            </div>
            <button
              class="btn-apply-period"
              @click="loadAdminHistory"
              :disabled="loadingHistory"
            >
              Применить
            </button>
          </div>
          <div class="history-period-presets">
            <button class="history-preset-chip" @click="setHistoryPeriodPreset(24)" :disabled="loadingHistory">24 часа</button>
            <button class="history-preset-chip" @click="setHistoryPeriodPreset(24 * 7)" :disabled="loadingHistory">7 дней</button>
            <button class="history-preset-chip" @click="setHistoryPeriodPreset(24 * 30)" :disabled="loadingHistory">30 дней</button>
          </div>
        </div>

        <div v-if="loadingHistory" class="empty-symptom-placeholder">
          <p>Загрузка истории сессий...</p>
        </div>

        <div v-else-if="adminHistory.length > 0" class="app-history-bottom-layout history-panel-layout">
          <div class="history-bottom-header">
            <h3>Все сессии диагностики</h3>
            <div class="history-header-actions">
              <span class="history-stat-chip">{{ finalFilteredAdminHistory.length }} из {{ adminHistory.length }} записей</span>
              <button
                class="btn-delete-history"
                @click="deleteSelectedHistory"
                :disabled="loadingHistory || selectedHistoryIds.length === 0"
              >
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                  <polyline points="3 6 5 6 21 6"></polyline>
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                  <line x1="10" y1="11" x2="10" y2="17"></line>
                  <line x1="14" y1="11" x2="14" y2="17"></line>
                </svg>
                Удалить выбранные ({{ selectedHistoryIds.length }})
              </button>
            </div>
          </div>

          <div class="history-table-wrapper-premium">
            <table class="history-table-premium">
              <thead>
                <tr class="table-header-row">
                  <th style="width: 44px; text-align: center;">
                    <input 
                      type="checkbox" 
                      :checked="isAllSelected" 
                      @change="toggleSelectAll"
                      class="history-checkbox-all"
                      aria-label="Выбрать все сессии"
                    />
                  </th>
                  <th>Дата и время</th>
                  <th>ID сессии</th>
                  <th>Текст жалобы</th>
                  <th>Симптомы</th>
                  <th>Диагнозы</th>
                  <th style="width: 44px; text-align: center;"></th>
                </tr>
                <tr class="table-filter-row">
                  <td></td>
                  <td>
                    <input v-model="tableFilterDate" type="datetime-local" class="table-filter-input" />
                  </td>
                  <td>
                    <input 
                      v-model="tableFilterSessionId" 
                      list="session-ids-list" 
                      placeholder="Выбрать..." 
                      class="table-filter-input" 
                    />
                    <datalist id="session-ids-list">
                      <option v-for="id in uniqueSessionIds" :key="id" :value="id"></option>
                    </datalist>
                  </td>
                  <td>
                    <input v-model="tableFilterComplaint" type="text" placeholder="Фильтр..." class="table-filter-input" />
                  </td>
                  <td>
                    <input 
                      v-model="tableFilterSymptom" 
                      list="history-symptoms-list" 
                      placeholder="Выбрать..." 
                      class="table-filter-input" 
                    />
                    <datalist id="history-symptoms-list">
                      <option v-for="symptom in uniqueHistorySymptoms" :key="symptom" :value="symptom"></option>
                    </datalist>
                  </td>
                  <td>
                    <input 
                      v-model="tableFilterDisease" 
                      list="history-diseases-list" 
                      placeholder="Выбрать..." 
                      class="table-filter-input" 
                    />
                    <datalist id="history-diseases-list">
                      <option v-for="disease in uniqueHistoryDiseases" :key="disease" :value="disease"></option>
                    </datalist>
                  </td>
                  <td style="text-align: center;">
                    <button 
                      v-if="tableFilterDate || tableFilterSessionId || tableFilterComplaint || tableFilterSymptom || tableFilterDisease"
                      @click="clearTableFilters" 
                      class="btn-clear-table-filters" 
                      title="Сбросить все фильтры"
                    >
                      ✕
                    </button>
                  </td>
                </tr>
              </thead>
              <tbody>
                <tr 
                  v-for="record in finalFilteredAdminHistory" 
                  :key="record.id"
                  class="history-table-row-premium"
                  :class="{ 'row-selected': selectedHistoryIds.includes(record.id) }"
                >
                  <td style="text-align: center;" data-label="Выбрать">
                    <input 
                      type="checkbox" 
                      :checked="selectedHistoryIds.includes(record.id)" 
                      @change="toggleSelectRecord(record.id)"
                      class="history-checkbox-row"
                    />
                  </td>
                  <td class="td-time" data-label="Дата и время">{{ formatDate(record.timestamp) }}</td>
                  <td class="td-session" data-label="ID сессии">
                    <span class="table-session-id-text" style="font-size: 0.75rem; word-break: break-all; white-space: normal;">
                      {{ record.sessionId || '—' }}
                    </span>
                  </td>
                  <td class="td-complaint" :title="record.complaintText" data-label="Текст жалобы">
                    {{ record.complaintText }}
                  </td>
                  <td class="td-symptoms" data-label="Симптомы">
                    <div class="table-symptoms-group">
                      <span 
                        v-for="symptom in record.detectedSymptoms" 
                        :key="symptom" 
                        class="symptom-pill-premium direct-pill"
                        style="margin: 2px;"
                      >
                        <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" stroke-width="3" fill="none" class="check-symptom-svg">
                          <polyline points="20 6 9 17 4 12"></polyline>
                        </svg>
                        {{ symptom }}
                      </span>
                      <span 
                        v-for="symptom in record.assumedSymptoms" 
                        :key="symptom" 
                        class="symptom-pill-premium assumed-pill"
                        style="margin: 2px;"
                      >
                        <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" stroke-width="2.5" fill="none" class="assumed-symptom-svg">
                          <polyline points="20 6 9 17 4 12"></polyline>
                        </svg>
                        {{ symptom }}
                      </span>
                      <span v-if="!record.detectedSymptoms?.length && !record.assumedSymptoms?.length" class="text-muted">—</span>
                    </div>
                  </td>
                  <td class="td-diseases" data-label="Диагнозы">
                    <div class="table-diseases-group" style="display: flex; flex-direction: column; gap: 0.5rem; align-items: flex-start; max-width: none;">
                      <div 
                        v-for="res in record.results" 
                        :key="res.disease" 
                        class="history-disease-item"
                        style="display: flex; flex-direction: column; align-items: flex-start; gap: 4px; width: 100%; padding-bottom: 6px;"
                      >
                        <div 
                          style="display: flex; align-items: center; gap: 0.35rem; font-size: 0.78rem; flex-wrap: wrap; cursor: pointer; user-select: none;"
                          @click="toggleHistoryDiseaseExpand(record.id, res.disease)"
                        >
                          <span class="disease-name-bold" style="font-size: 0.78rem;">{{ res.disease }}</span>
                          <span class="threat-micro-badge" :class="getThreatColorClass(res.threatLevel || 0)" style="font-size: 0.62rem; min-height: 16px; padding: 0px 6px; line-height: 16px;">
                            {{ getThreatLabel(res.threatLevel || 0) }}
                          </span>
                          <!-- Interactive chevron -->
                          <span class="disease-chevron-icon" :class="{ 'chevron-rotated': expandedHistoryDiseases[`${record.id}_${res.disease}`] }">
                            <svg viewBox="0 0 24 24" width="11" height="11" stroke="currentColor" stroke-width="3" fill="none">
                              <polyline points="6 9 12 15 18 9"></polyline>
                            </svg>
                          </span>
                        </div>
                        
                        <!-- Dropdown panel with matching symptoms info -->
                        <div 
                          v-if="expandedHistoryDiseases[`${record.id}_${res.disease}`]"
                          style="width: 100%; padding-left: 0.5rem; margin-top: 4px; font-size: 0.75rem; color: var(--text-muted);"
                        >
                          <div style="margin-bottom: 6px; display: flex; flex-direction: column; gap: 4px;">
                            <div style="display: flex; align-items: center; gap: 0.35rem;">
                              <span class="priority-label">Дифференциальный вес:</span>
                              <div class="diagnosis-priority-badge" :class="priorityClassForRecord(record, res)" style="font-size: 0.65rem; padding: 0.1rem 0.45rem; border-radius: 4px; gap: 0.2rem;" :title="`Относительный дифференциальный вес`">
                                <span class="priority-value" style="font-weight: 800;">{{ formatDifferentialWeightForRecord(record, res) }}</span>
                              </div>
                            </div>
                            <div>
                              Совпадение по симптомам: <strong>{{ res.matchPercentage }}%</strong> ({{ res.matchingSymptomsCount }} из {{ res.totalDiseaseSymptomsCount }} симптомов)
                            </div>
                          </div>
                          <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                            <span 
                              v-for="symptom in res.matchedSymptoms" 
                              :key="symptom" 
                              class="symptom-pill-premium direct-pill"
                              style="font-size: 0.7rem; padding: 0.1rem 0.4rem; min-height: auto;"
                            >
                              <svg viewBox="0 0 24 24" width="8" height="8" stroke="currentColor" stroke-width="3" fill="none" class="check-symptom-svg">
                                <polyline points="20 6 9 17 4 12"></polyline>
                              </svg>
                              {{ symptom }}
                            </span>
                          </div>
                        </div>
                      </div>
                      <span v-if="!record.results?.length" class="text-muted">—</span>
                    </div>
                  </td>
                  <td class="td-actions" style="text-align: center;">
                    <div style="display: inline-flex; gap: 8px; align-items: center; justify-content: center;">
                      <button
                        class="btn-download-history-pdf"
                        @click.stop="downloadPdfReport(record)"
                        title="Скачать PDF отчёт"
                        aria-label="Скачать PDF отчёт"
                      >
                        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2.5" fill="none" style="display: block;">
                          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                          <polyline points="7 10 12 15 17 10"></polyline>
                          <line x1="12" y1="15" x2="12" y2="3"></line>
                        </svg>
                      </button>
                    </div>
                  </td>
                </tr>
                <tr v-if="finalFilteredAdminHistory.length === 0">
                  <td colspan="7" style="text-align: center; padding: 3rem; color: var(--text-muted);">
                    Записи, удовлетворяющие условиям фильтра, не найдены.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div v-else class="audit-timeline-card-premium" style="display: flex; flex-direction: column; align-items: center; padding: 3.5rem; text-align: center; border: 2px dashed var(--border-color); background: var(--bg-card-sub); border-radius: 16px; gap: 1.25rem;">
          <div style="width: 56px; height: 56px; border-radius: 50%; background: var(--bg-hover); display: flex; align-items: center; justify-content: center; color: var(--text-muted);">
            <svg viewBox="0 0 24 24" width="28" height="28" stroke="currentColor" stroke-width="1.75" fill="none">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
              <polyline points="14 2 14 8 20 8"></polyline>
              <line x1="16" y1="13" x2="8" y2="13"></line>
              <line x1="16" y1="17" x2="8" y2="17"></line>
            </svg>
          </div>
          <div>
            <h3 style="margin: 0; font-size: 1.1rem; font-weight: 700; color: var(--text-main);">За выбранный период записей нет</h3>
            <p style="margin: 0.5rem 0 0 0; font-size: 0.85rem; color: var(--text-muted); max-width: 440px; line-height: 1.5;">
              Измените период выше, чтобы увидеть другие записи.
            </p>
          </div>
        </div>
      </section>

      </Transition>
    </main>

    <!-- Mobile bottom navigation (admin only) -->
    <nav v-if="isAdmin" class="app-nav-bottom-mobile" aria-label="Навигация администратора">
      <button
        type="button"
        class="bottom-nav-item"
        :class="{ active: activeTab === 'diagnostics' }"
        @click="activeTab = 'diagnostics'"
        aria-label="Диагностика"
        title="Диагностика"
      >
        <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
          <polyline points="14 2 14 8 20 8"></polyline>
          <line x1="16" y1="13" x2="8" y2="13"></line>
          <line x1="16" y1="17" x2="8" y2="17"></line>
        </svg>
      </button>
      <button
        type="button"
        class="bottom-nav-item"
        :class="{ active: activeTab === 'knowledge' }"
        @click="activeTab = 'knowledge'"
        aria-label="База знаний"
        title="База знаний"
      >
        <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
          <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
          <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
          <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
        </svg>
      </button>
      <button
        type="button"
        class="bottom-nav-item"
        :class="{ active: activeTab === 'history' }"
        aria-label="История взаимодействий"
        title="История взаимодействий"
        @click="activeTab = 'history'"
      >
        <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
          <circle cx="12" cy="12" r="10"></circle>
          <polyline points="12 6 12 12 16 14"></polyline>
        </svg>
      </button>
    </nav>



    <!-- Medical Disclaimer Footer (diagnostics only) -->
    <footer v-if="activeTab === 'diagnostics'" class="app-disclaimer-footer">
      <p class="disclaimer-text">
        Сервис носит исключительно информационно-справочный характер и не является медицинским изделием или системой поддержки принятия врачебных решений.<br>
        Представленные сведения не являются диагнозом, назначением или руководством к самолечению и не заменяют очную консультацию квалифицированного врача.<br>
        Полнота и точность представленной информации не гарантируются; ответственность за её самостоятельную интерпретацию и принятые на её основе решения несёт пользователь.<br>
        При любых симптомах обратитесь к врачу-специалисту, а в неотложных случаях – вызовите скорую медицинскую помощь (112/103).
      </p>
    </footer>
  </div>
</template>

<style>
/* Floating admin entry styles */
.admin-entry-corner {
  position: absolute;
  top: 24px;
  right: 24px;
  z-index: 100;
}
.btn-admin-login {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 999px;
  color: var(--text-muted);
  font-size: 0.85rem;
  font-weight: 600;
  text-decoration: none;
  transition: var(--transition-smooth);
  box-shadow: var(--shadow-sm);
}

.btn-admin-login svg {
  color: var(--accent);
  flex-shrink: 0;
}

.btn-admin-login:hover {
  background: var(--accent-light);
  border-color: var(--accent);
  color: var(--text-main);
  transform: translateY(-1px);
  box-shadow: var(--shadow-md);
}

.btn-admin-login:focus-visible {
  outline: 3px solid var(--border-focus);
  outline-offset: 2px;
}

@media (max-width: 640px) {
  .admin-entry-corner {
    position: static;
    display: flex;
    justify-content: center;
    margin: 0.5rem 0 0.75rem;
  }

  .btn-admin-login {
    width: 100%;
    justify-content: center;
  }
}

/* Font overrides and CSS reset layout variables */
:root {
  --bg-app: #f6f8fa; 
  --bg-card: #ffffff;
  --bg-card-sub: #f8fafc;
  --bg-input: #ffffff;
  --bg-hover: #f1f5f9;
  
  --text-main: #0f172a;
  --text-muted: #64748b;
  --text-light: #94a3b8;
  
  --border-color: rgba(15, 23, 42, 0.08);
  --border-focus: #0284c7;
  
  --accent: #0284c7;
  --accent-light: rgba(2, 132, 199, 0.06);
  --accent-hover: #0369a1;
  --on-accent: #ffffff;
  
  --color-green: #10b981;
  --color-blue: #3b82f6;
  --color-orange: #f59e0b;
  --color-red: #ef4444;
  --color-purple: #8b5cf6;
  --color-gray: #94a3b8;
  
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.02);
  --shadow-md: 0 10px 25px -5px rgba(15, 23, 42, 0.04), 0 8px 16px -6px rgba(15, 23, 42, 0.02);
  --shadow-lg: 0 25px 50px -12px rgba(15, 23, 42, 0.08);
  --shadow-focus: 0 0 0 4px rgba(2, 132, 199, 0.12);
  
  --transition-smooth: all 0.35s cubic-bezier(0.16, 1, 0.3, 1);
  --border-radius-card: 20px;

  /* Высота нижней панели админа (мобильный режим) */
  --app-bottom-nav-height: 3.5rem;
  --app-bottom-nav-offset: calc(var(--app-bottom-nav-height) + env(safe-area-inset-bottom, 0px));
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg-app: #0c0c0c;
    --bg-card: #141414;
    --bg-card-sub: #1a1a1a;
    --bg-input: #101010;
    --bg-hover: #242424;

    --text-main: #f5f5f5;
    --text-muted: #a3a3a3;
    --text-light: #737373;

    --border-color: rgba(255, 255, 255, 0.09);
    --border-focus: #d4d4d4;

    --accent: #e5e5e5;
    --accent-light: rgba(255, 255, 255, 0.07);
    --accent-hover: #ffffff;
    --on-accent: #111111;

    --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.35);
    --shadow-md: 0 12px 28px rgba(0, 0, 0, 0.45);
    --shadow-lg: 0 28px 56px rgba(0, 0, 0, 0.55);
    --shadow-focus: 0 0 0 4px rgba(255, 255, 255, 0.1);
  }

  .btn-mic-record-clean.converting {
    color: var(--on-accent);
    box-shadow: 0 0 12px rgba(255, 255, 255, 0.12);
  }

  .search-input-wrapper-clean input:focus {
    box-shadow: var(--shadow-focus);
  }

  .disease-manager-tile:hover {
    border-color: rgba(255, 255, 255, 0.14);
  }

  .disease-manager-tile.active {
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.35);
  }

  .btn-speaker-auto-play.active {
    color: var(--on-accent);
    box-shadow: 0 0 12px rgba(255, 255, 255, 0.12);
  }

  .symptom-checkbox-card.selected {
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.35);
  }

  .history-card-bottom:hover,
  .btn-copy-session-id:hover {
    border-color: rgba(255, 255, 255, 0.18);
  }

  .segment-btn:hover,
  .symptom-count-badge {
    background-color: var(--bg-hover);
  }
}

*, *::before, *::after {
  box-sizing: border-box;
}

html {
  height: 100%;
  overflow-y: auto;
}

body {
  background-color: var(--bg-app) !important;
  color: var(--text-main) !important;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  margin: 0;
  padding: 0;
  min-height: 100%;
  display: block !important;
  transition: background-color 0.3s, color 0.3s;
}

.ophthalmo-app {
  width: 100%;
  max-width: min(1140px, 100%);
  margin: 0 auto;
  min-height: 100vh;
  min-height: 100dvh;
  padding: clamp(0.65rem, 2.5vw, 0.75rem) clamp(0.75rem, 4vw, 1.5rem);
  display: flex;
  flex-direction: column;
  position: relative;
  overflow-x: clip;
  box-sizing: border-box;
}

.ophthalmo-app.ophthalmo-app--full-width {
  max-width: 100%;
}

@media (min-width: 769px) {
  .ophthalmo-app.ophthalmo-app--admin-knowledge {
    height: 100dvh;
    max-height: 100dvh;
    overflow: hidden;
  }
}

/* Brand aligned top left layout (clean & elegant) */
.app-header-premium {
  display: flex;
  justify-content: center;
  align-items: center;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border-color);
  flex-wrap: wrap;
  gap: 0.75rem;
  flex-shrink: 0;            /* header should never cause overflow */
}

.brand-group-centered {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: 0.4rem;
  width: 100%;
  margin-bottom: 0.75rem;
}

.logo-wrapper-row {
  display: flex;
  align-items: center;
  gap: 0.65rem;
  cursor: pointer;
  transition: opacity 0.25s, transform 0.25s;
  user-select: none;
}

.logo-wrapper-button {
  appearance: none;
  border: 0;
  background: transparent;
  padding: 0;
  color: inherit;
  font: inherit;
}

.logo-wrapper-button:focus-visible {
  outline: 3px solid var(--border-focus);
  outline-offset: 6px;
  border-radius: 12px;
}

.logo-wrapper-row:hover {
  opacity: 0.8;
}

.logo-wrapper-row:active {
  transform: scale(0.98);
}

.blinking-eye-logo {
  width: 28px;
  height: 28px;
  color: var(--accent);
  transform-origin: 12px 12px;
  animation: blink-eye-anim 7s infinite ease-in-out;
  flex-shrink: 0;
}

@keyframes blink-eye-anim {
  0%, 82%, 88%, 94%, 100% {
    transform: scaleY(1);
  }
  85%, 91% {
    transform: scaleY(0.08);
  }
}

.brand-group-centered .logo-text {
  font-size: 1.8rem;
  font-weight: 800;
  margin: 0;
  letter-spacing: -0.03em;
  color: var(--text-main);
}

.brand-group-centered .logo-subtitle {
  font-size: 0.88rem;
  color: var(--text-muted);
  margin: 0;
  line-height: 1.4;
  font-weight: 400;
  max-width: 580px;
}

/* Underline Navigation tabs (Only visible to Admin) */
.app-nav-premium {
  display: flex;
  gap: 1.5rem;
  position: relative;
  margin-top: 0.25rem;
}

.nav-tab {
  background: none;
  border: none;
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--text-muted);
  cursor: pointer;
  position: relative;
  padding: 0.5rem 0.25rem 0.75rem 0.25rem;
  transition: var(--transition-smooth);
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
}

.nav-tab:hover {
  color: var(--text-main);
}

.nav-tab.active {
  color: var(--accent);
  font-weight: 600;
}

.tab-indicator {
  position: absolute;
  bottom: -1px;
  left: 0;
  right: 0;
  height: 2px;
  background-color: var(--accent);
  border-radius: 2px;
  animation: slide-in 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}

/* Main workspace area */
.app-workspace-container {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
  width: 100%;
  max-width: 100%;
  min-width: 0;
}

.app-workspace-container.with-admin-nav {
  padding-top: 1.25rem;
}

.app-admin-mobile-actions {
  display: none;
}

.app-nav-bottom-mobile {
  display: none;
  box-sizing: border-box;
}

.bottom-nav-item {
  appearance: none;
  border: 0;
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  display: flex;
  flex: 1;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.2rem;
  min-width: 0;
  padding: 0.45rem 0.15rem;
  font-size: 0.62rem;
  font-weight: 600;
  line-height: 1.15;
  text-align: center;
  transition: color 0.2s ease, background-color 0.2s ease;
}

.bottom-nav-item span {
  max-width: 100%;
  overflow-wrap: anywhere;
}

.bottom-nav-item svg {
  flex-shrink: 0;
}

.bottom-nav-item.active {
  color: var(--accent);
}

.bottom-nav-item:active {
  background-color: var(--bg-hover);
}

/* Center diagnostic panel */
.diagnostics-panel-centered {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  justify-content: center;
  width: 100%;
  flex: 1;
  min-height: 0;
  padding: clamp(1rem, 4vh, 2.5rem) 0;
}

/* Initial state: brand + complaint form vertically centered in the workspace */
.diagnostics-panel-centered:not(.diagnostics-has-results) {
  justify-content: center;
}

/* After analysis: flow from the top (toward tabs) so results fit on screen */
.diagnostics-panel-centered.diagnostics-has-results {
  justify-content: flex-start;
  padding-top: clamp(0.75rem, 2vh, 1.25rem);
  padding-bottom: 0.75rem;
  overflow-y: auto;
}

.centered-workspace-card {
  width: 100%;
  max-width: 860px;
  margin-inline: auto;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;   /* space between input card and results when they appear */
}

/* Workspace Card */
.workspace-card-wrapper {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-card);
  padding: clamp(1.25rem, 2.5vw, 1.75rem);
  box-shadow: var(--shadow-md);
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.section-title {
  font-size: 1.25rem;
  margin: 0 0 1.25rem 0;
  font-weight: 700;
  letter-spacing: -0.01em;
  text-align: center;
  color: var(--text-main);
}

/* Input Area Container Premium with Reactive Border Glows */
.textarea-container-premium {
  background-color: var(--bg-card);
  border: 1.5px solid var(--border-color);
  border-radius: 16px;
  padding: 1rem;
  display: flex;
  flex-direction: column;
  transition: var(--transition-smooth);
  box-shadow: var(--shadow-sm);
  position: relative;
}

.textarea-clear-btn {
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;
  width: 24px;
  height: 24px;
  background-color: transparent;
  border: none;
  color: var(--text-muted);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: var(--transition-smooth);
  z-index: 10;
  outline: none;
  padding: 0;
  opacity: 0.75;
}

.textarea-clear-btn:hover:not(:disabled) {
  background-color: transparent;
  color: var(--text-main);
  border-color: transparent;
  opacity: 1;
}

.textarea-container-premium:hover,
.textarea-container-premium:focus-within {
  border-color: var(--accent) !important;
  box-shadow: var(--shadow-focus), var(--shadow-md) !important;
}

.textarea-container-premium textarea {
  background: none;
  border: none;
  resize: none;
  color: var(--text-main);
  font-family: inherit;
  font-size: 1.05rem;
  line-height: 1.6;
  outline: none;
  min-height: 150px;
  max-height: 420px;
  overflow-y: auto;
  padding: 0;
}

.textarea-container-premium textarea::placeholder {
  color: var(--text-main);
  opacity: 0.75;
  font-size: 1.05rem;
}

/* Glowing Border States */
.textarea-container-premium.border-validating {
  border-color: var(--accent);
  box-shadow: 0 0 0 3.5px var(--accent-light);
}

.textarea-container-premium.border-success {
  border-color: var(--color-green) !important;
  box-shadow: 0 0 0 3.5px rgba(16, 185, 129, 0.08) !important;
}

.textarea-container-premium.border-error {
  border-color: var(--color-red) !important;
  box-shadow: 0 0 0 3.5px rgba(239, 68, 68, 0.08) !important;
  animation: shake-input-field 0.3s cubic-bezier(0.36, 0.07, 0.19, 0.97) both;
}

@keyframes shake-input-field {
  10%, 90% { transform: translate3d(-1px, 0, 0); }
  20%, 80% { transform: translate3d(2px, 0, 0); }
  30%, 50%, 70% { transform: translate3d(-4px, 0, 0); }
  40%, 60% { transform: translate3d(4px, 0, 0); }
}

/* Bottom Toolbar Inside Input Area */
.textarea-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-top: 1px solid var(--border-color);
  padding-top: 0.9rem;
  margin-top: 0.75rem;
  gap: 0.75rem;
  flex-wrap: nowrap;
}

.diagnostic-actions-left {
  display: flex;
  align-items: center;
  flex: 1;
  min-width: 0;
  flex-wrap: nowrap;
  gap: 0.75rem;
}

.audio-controls-group {
  display: inline-flex;
  align-items: center;
  gap: 0.75rem;
  flex-shrink: 0;
}

/* Clean circular Microphone recording button */
.microphone-wrapper-group {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  position: relative;
}

.btn-mic-record-clean {
  position: relative;
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background-color: var(--bg-card-sub);
  border: 1px solid var(--border-color);
  color: var(--text-muted);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: var(--transition-smooth);
  box-shadow: var(--shadow-sm);
  outline: none;
}

.btn-mic-record-clean:hover:not(:disabled) {
  color: var(--text-main);
  background-color: var(--bg-hover);
  transform: scale(1.05);
}

.btn-mic-record-clean.recording {
  background-color: var(--color-red);
  border-color: var(--color-red);
  color: #ffffff;
  box-shadow: 0 0 12px rgba(239, 68, 68, 0.35);
}

.btn-mic-record-clean.recording:hover {
  background-color: rgba(239, 68, 68, 0.85);
  border-color: rgba(239, 68, 68, 0.85);
}

.btn-mic-record-clean.converting {
  background-color: var(--accent);
  border-color: var(--accent);
  color: var(--on-accent);
  box-shadow: 0 0 12px rgba(2, 132, 199, 0.35);
}

.btn-mic-record-clean.converting:hover {
  background-color: var(--accent-hover);
  border-color: var(--accent-hover);
}

/* Glowing ripple rings on recording */
.mic-ripple-pulse {
  position: absolute;
  top: 0; left: 0; right: 0; bottom: 0;
  border-radius: 50%;
  border: 1.5px solid var(--color-red);
  box-shadow: 0 0 10px rgba(239, 68, 68, 0.35);
  animation: pulse-ring-ripple 1.5s infinite ease-out;
  pointer-events: none;
}

@keyframes pulse-ring-ripple {
  0% { transform: scale(1); opacity: 0.8; }
  100% { transform: scale(1.4); opacity: 0; }
}

/* EQ waveform mini visualizer */
.stt-waveform-mini {
  display: flex;
  align-items: center;
  gap: 2px;
  height: 10px;
}

.stt-waveform-mini .wave-bar {
  width: 2px;
  height: 100%;
  background-color: var(--color-red);
  border-radius: 1px;
  animation: wave-bounce 0.6s infinite ease-in-out alternate;
}

.stt-waveform-mini .wb-1 { animation-delay: 0.1s; }
.stt-waveform-mini .wb-2 { animation-delay: 0.3s; }
.stt-waveform-mini .wb-3 { animation-delay: 0.2s; }
.stt-waveform-mini .wb-4 { animation-delay: 0.4s; }

/* Speaker Toggle Button for Auto-readout (TTS) */
.btn-speaker-auto-play {
  position: relative;
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background-color: var(--bg-card-sub);
  border: 1px solid var(--border-color);
  color: var(--text-muted);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: var(--transition-smooth);
  box-shadow: var(--shadow-sm);
  outline: none;
}

.btn-speaker-auto-play:hover {
  color: var(--text-main);
  background-color: var(--bg-hover);
  transform: scale(1.05);
}

.btn-speaker-auto-play.active {
  background-color: var(--accent);
  border-color: var(--accent);
  color: var(--on-accent);
  box-shadow: 0 0 12px rgba(2, 132, 199, 0.35);
}

.btn-speaker-auto-play.active:hover {
  background-color: var(--accent-hover);
  border-color: var(--accent-hover);
}

/* Play/Stop TTS toggle button styling */
.btn-tts-toggle {
  position: relative;
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background-color: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  color: #22c55e;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: var(--transition-smooth);
  box-shadow: var(--shadow-sm);
  outline: none;
}

.btn-tts-toggle:hover {
  background-color: rgba(34, 197, 94, 0.2);
  border-color: rgba(34, 197, 94, 0.5);
  transform: scale(1.05);
}

.btn-tts-toggle.playing {
  background-color: var(--color-red);
  border-color: var(--color-red);
  color: #ffffff;
  box-shadow: 0 0 12px rgba(239, 68, 68, 0.35);
}

.btn-tts-toggle.playing:hover {
  background-color: rgba(239, 68, 68, 0.85);
  border-color: rgba(239, 68, 68, 0.85);
}

.status-tip {
  font-size: 0.82rem;
  color: var(--text-muted);
  margin-left: 0.25rem;
  animation: anim-fade-in 0.2s;
}

.status-tip.tip-muted {
  opacity: 0.65;
}

.btn-clean-text {
  background: none;
  border: none;
  font-size: 0.8rem;
  color: var(--text-muted);
  cursor: pointer;
  padding: 0.35rem 0.75rem;
  border-radius: 6px;
  font-weight: 500;
  transition: var(--transition-smooth);
  flex-shrink: 0;
  white-space: nowrap;
}

.btn-clean-text:hover:not(:disabled) {
  color: var(--color-red);
  background-color: rgba(239, 68, 68, 0.05);
}

.btn-clean-text:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

/* Preset pills */
.complaints-presets-premium {
  margin-top: 1rem;
}

.presets-intro {
  font-size: 0.75rem;
  color: var(--text-muted);
  display: block;
  margin-bottom: 0.5rem;
}

.presets-pills-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
}

.preset-capsule {
  background-color: var(--bg-card-sub);
  border: 1px solid var(--border-color);
  color: var(--text-muted);
  font-size: 0.75rem;
  padding: 0.3rem 0.7rem;
  border-radius: 30px;
  cursor: pointer;
  transition: var(--transition-smooth);
}

.preset-capsule:hover {
  background-color: var(--bg-hover);
  color: var(--text-main);
  border-color: var(--text-light);
}

.submit-action-row {
  margin-top: 0;
  display: flex;
  justify-content: center;
}

.btn-primary-submit-diagnostic {
  width: 100%;
  background: linear-gradient(135deg, var(--accent) 30%, #3b82f6);
  border: none;
  color: var(--on-accent);
  font-size: 0.95rem;
  font-weight: 600;
  min-height: 52px;
  padding: 0.95rem 2rem;
  border-radius: 12px;
  cursor: pointer;
  box-shadow: 0 10px 20px -10px rgba(2, 132, 199, 0.3);
  transition: var(--transition-smooth);
  display: flex;
  align-items: center;
  justify-content: center;
}

.btn-primary-submit-diagnostic:hover:not(:disabled) {
  opacity: 0.95;
  transform: translateY(-1px);
  box-shadow: 0 12px 24px -10px rgba(2, 132, 199, 0.4);
}

.btn-primary-submit-diagnostic:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none !important;
  box-shadow: none !important;
}

.diagnosis-confidence-badge .confidence-word {
  font-size: 0.68rem;
  font-weight: 600;
  color: var(--text-muted);
  white-space: nowrap;
}

.threat-micro-badge {
  display: inline-flex;
  align-items: center;
  min-height: 24px;
  padding: 0.2rem 0.55rem;
  border-radius: 999px;
  font-size: 0.72rem;
  font-weight: 750;
  line-height: 1;
  white-space: nowrap;
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
}

.threat-micro-badge.threat-green {
  color: var(--color-green);
  background-color: rgba(16, 185, 129, 0.08);
  border-color: rgba(16, 185, 129, 0.24);
}

.threat-micro-badge.threat-blue {
  color: var(--color-blue);
  background-color: rgba(59, 130, 246, 0.08);
  border-color: rgba(59, 130, 246, 0.24);
}

.threat-micro-badge.threat-orange {
  color: var(--color-orange);
  background-color: rgba(245, 158, 11, 0.08);
  border-color: rgba(245, 158, 11, 0.24);
}

.threat-micro-badge.threat-red {
  color: var(--color-red);
  background-color: rgba(239, 68, 68, 0.08);
  border-color: rgba(239, 68, 68, 0.24);
}

/* Admin workspace shared layout */
.history-stat-chip {
  display: inline-flex;
  align-items: center;
  min-height: 34px;
  padding: 0.35rem 0.7rem;
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 999px;
  color: var(--text-main);
  font-size: 0.8rem;
  font-weight: 700;
  white-space: nowrap;
}

.history-header-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 0.55rem;
  flex-shrink: 0;
}

/* View switcher */
.history-view-switcher {
  display: inline-flex;
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 2px;
  gap: 2px;
}

.btn-view-mode {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border: none;
  background: transparent;
  color: var(--text-muted);
  border-radius: 6px;
  cursor: pointer;
  transition: var(--transition-smooth);
}

.btn-view-mode:hover {
  color: var(--text-main);
  background-color: var(--bg-hover);
}

.btn-view-mode.active {
  color: var(--accent, #2f6df4);
  background-color: rgba(47, 109, 244, 0.08);
}

/* Premium History Table View */
.history-table-wrapper-premium {
  width: 100%;
  overflow-x: auto;
  border: 1px solid var(--border-color);
  border-radius: 12px;
  background-color: var(--bg-card-sub);
  margin-top: 1rem;
}

.history-table-premium {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: 0.85rem;
}

.history-table-premium th,
.history-table-premium td {
  padding: 0.85rem 1rem;
  border-bottom: 1px solid var(--border-color);
  vertical-align: top;
}

.history-disease-item {
  border-bottom: 1px solid var(--border-color);
}

.history-disease-item:last-child {
  border-bottom: none !important;
  padding-bottom: 0 !important;
}

.history-table-premium th {
  background-color: var(--bg-card);
  color: var(--text-main);
  font-weight: 700;
  font-size: 0.82rem;
  text-transform: none;
  letter-spacing: normal;
  white-space: normal;
}

.table-header-row th {
  border-bottom: 1px solid var(--border-color);
}

/* Inline filters */
.table-filter-row {
  background-color: var(--bg-card);
}

.table-filter-row td {
  padding: 0.4rem 0.65rem;
  border-bottom: 2px solid var(--border-color);
}

.table-filter-input {
  width: 100%;
  min-height: 28px;
  padding: 0.3rem 0.5rem;
  border-radius: 6px;
  border: 1px solid var(--border-color);
  background-color: var(--bg-card-sub);
  color: var(--text-main);
  font-size: 0.78rem;
  transition: var(--transition-smooth);
}

.table-filter-input:focus {
  outline: none;
  border-color: var(--accent, #2f6df4);
  background-color: var(--bg-card);
}

.btn-clear-table-filters {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  border: 1px solid var(--border-color);
  background-color: var(--bg-card);
  color: var(--color-red, #ef4444);
  font-size: 0.8rem;
  cursor: pointer;
  transition: var(--transition-smooth);
}

.btn-clear-table-filters:hover {
  background-color: rgba(239, 68, 68, 0.08);
  border-color: var(--color-red, #ef4444);
}

/* Rows styling */
.history-table-row-premium {
  transition: var(--transition-smooth);
}

.history-table-row-premium:hover {
  background-color: var(--bg-hover);
}

.history-table-row-premium:last-child td {
  border-bottom: none;
}

.td-time {
  white-space: normal;
  word-break: break-word;
  font-weight: 500;
  color: var(--text-main);
}

.td-session {
  white-space: normal;
  word-break: break-word;
}

.table-session-id-row {
  display: flex;
  align-items: center;
  gap: 0.35rem;
}

.table-session-id-text {
  font-family: monospace;
  color: var(--text-muted);
}

.btn-copy-table-session-id {
  border: none;
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  padding: 2px;
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: var(--transition-smooth);
}

.btn-copy-table-session-id:hover {
  color: var(--text-main);
  background-color: var(--bg-hover);
}

.td-complaint {
  max-width: 320px;
  white-space: normal;
  word-break: break-word;
  color: var(--text-muted);
}

/* Tags layout inside table cell */
.table-symptoms-group,
.table-diseases-group {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
  max-width: 240px;
}

.table-symptom-tag {
  display: inline-flex;
  align-items: center;
  font-size: 0.72rem;
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  color: var(--text-main);
}

.table-disease-tag {
  display: inline-flex;
  align-items: center;
  font-size: 0.72rem;
  font-weight: 600;
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  border: 1px solid transparent;
}

.table-disease-tag.threat-green {
  color: var(--color-green);
  background-color: rgba(16, 185, 129, 0.06);
  border-color: rgba(16, 185, 129, 0.18);
}

.table-disease-tag.threat-blue {
  color: var(--color-blue);
  background-color: rgba(59, 130, 246, 0.06);
  border-color: rgba(59, 130, 246, 0.18);
}

.table-disease-tag.threat-orange {
  color: var(--color-orange);
  background-color: rgba(245, 158, 11, 0.06);
  border-color: rgba(245, 158, 11, 0.18);
}

.table-disease-tag.threat-red {
  color: var(--color-red);
  background-color: rgba(239, 68, 68, 0.06);
  border-color: rgba(239, 68, 68, 0.18);
}

.btn-loader-group {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.ring-loader-light {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(255, 255, 255, 0.25);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.8s infinite linear;
}

/* Loading Shimmer */
.analysis-loading-shimmer {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 2.5rem;
  color: var(--text-muted);
  gap: 0.85rem;
  font-size: 0.85rem;
}

.shimmer-pulse-circle {
  width: 28px;
  height: 28px;
  border: 3px solid var(--border-color);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.8s infinite linear;
}

/* cancel button removed */

/* Results Card styles */
.results-card-premium {
  width: 100%;
  min-width: 0;
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-card);
  padding: 1.25rem;   /* reduced to help content fit on screen */
  box-shadow: var(--shadow-md);
}

/* Completely remove the results wrapper from layout when there is no result yet.
   This eliminates unwanted empty space/gap under the input card (the gap: 2rem
   on .centered-workspace-card no longer reserves space for an empty sibling). */
.results-transition-wrapper:not(.results-visible) {
  display: none;
}

.results-transition-wrapper.results-visible {
  width: 100%;
  min-width: 0;
}

.results-header-actions {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 1rem;
  margin-bottom: 1.5rem;
  flex-wrap: wrap;
  gap: 1rem;
}

.results-header-actions h3 {
  font-size: 1.15rem;
  font-weight: 700;
  margin: 0;
  color: var(--text-main);
  letter-spacing: -0.01em;
}

.action-btn-row {
  display: flex;
  gap: 0.5rem;
}

.btn-export-pdf-report {
  background-color: var(--bg-card-sub);
  border: 1px solid var(--border-color);
  color: var(--text-main);
  font-size: 0.8rem;
  padding: 0.45rem 0.85rem;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  transition: var(--transition-smooth);
}

.btn-export-pdf-report:hover {
  background-color: var(--bg-hover);
  transform: translateY(-1px);
}

.results-label-caps {
  font-size: 0.75rem;
  color: var(--text-muted);
  font-weight: 700;
  text-transform: uppercase;
  display: block;
  margin-bottom: 0.75rem;
}



.results-symptoms-layout {
  margin-bottom: 2rem;
}

.symptom-tag-chips-group {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  background-color: var(--bg-card-sub);
  padding: 0.85rem;
  border-radius: 12px;
  border: 1px solid var(--border-color);
  transition: border-color 0.35s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.35s cubic-bezier(0.16, 1, 0.3, 1);
}

.symptom-tag-chips-group:hover {
  border-color: rgba(72, 187, 120, 0.35);
  box-shadow: 0 4px 15px rgba(72, 187, 120, 0.03);
  transform: translateY(-1px);
}

.symptom-pill-premium {
  background-color: var(--bg-card-sub);
  border: 1px solid var(--border-color);
  color: var(--text-main);
  padding: 0.25rem 0.65rem;
  border-radius: 30px;
  font-size: 0.8rem;
  font-weight: 500;
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  box-shadow: var(--shadow-sm);
}

.direct-pill {
  background-color: rgba(16, 185, 129, 0.08) !important;
  border-color: rgba(16, 185, 129, 0.25) !important;
}

.check-symptom-svg {
  color: var(--color-green);
}

.assumed-symptom-svg {
  color: var(--color-blue);
}

.unmatched-symptom-svg {
  flex-shrink: 0;
  color: var(--text-muted);
}

.symptom-unmatched .unmatched-symptom-svg {
  opacity: 1;
}

.assumed-symptoms-group {
  border-color: rgba(59, 130, 246, 0.2);
  background-color: rgba(59, 130, 246, 0.04);
}

.assumed-symptoms-group:hover {
  border-color: rgba(59, 130, 246, 0.45) !important;
  box-shadow: 0 4px 15px rgba(59, 130, 246, 0.04) !important;
  transform: translateY(-1px);
}

.assumed-pill {
  background-color: rgba(59, 130, 246, 0.08) !important;
  border-color: rgba(59, 130, 246, 0.25) !important;
}



.empty-outcome-text {
  font-size: 0.85rem;
  color: var(--text-muted);
  font-style: italic;
  margin: 0;
}

.results-diseases-layout {
  margin-bottom: 1.5rem;
  width: 100%;
  min-width: 0;
}

.outcome-tiles-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  width: 100%;
  min-width: 0;
}

.outcome-tile-premium {
  width: 100%;
  min-width: 0;
  background-color: var(--bg-card-sub);
  border: 1px solid var(--border-color);
  border-radius: 14px;
  padding: 1.25rem;
  transition: border-color 0.35s cubic-bezier(0.16, 1, 0.3, 1),
              box-shadow 0.35s cubic-bezier(0.16, 1, 0.3, 1),
              transform 0.35s cubic-bezier(0.16, 1, 0.3, 1);
  overflow: hidden;
}

.outcome-tile-premium-interactive {
  cursor: pointer;
}

.outcome-tile-premium-interactive:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}

.tile-header-flex {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 0.75rem;
}

.disease-meta-flex {
  min-width: 0;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.45rem 0.65rem;
}

.disease-name-bold {
  color: var(--text-main);
  font-size: 1rem;
  font-weight: 750;
  line-height: 1.25;
  overflow-wrap: anywhere;
}

.diagnosis-priority-badge {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.35rem;
  padding: 0.3rem 0.7rem;
  border-radius: 8px;
  font-size: 0.72rem;
  font-weight: 750;
  line-height: 1.3;
  width: fit-content;
  border: 1px solid transparent;
  transition: var(--transition-smooth);
}

.diagnosis-priority-badge .priority-label {
  font-weight: 500;
  color: var(--text-muted);
}

.diagnosis-priority-badge .priority-value {
  font-weight: 800;
}

.diagnosis-priority-badge.priority-high {
  background-color: rgba(139, 92, 246, 0.07);
  color: var(--color-purple);
  border-color: rgba(139, 92, 246, 0.18);
}

.diagnosis-priority-badge.priority-medium {
  background-color: rgba(99, 102, 241, 0.07);
  color: #6366f1;
  border-color: rgba(99, 102, 241, 0.18);
}

.diagnosis-priority-badge.priority-low {
  background-color: rgba(148, 163, 184, 0.07);
  color: var(--text-light);
  border-color: rgba(148, 163, 184, 0.18);
}

.threat-micro-badge {
  display: inline-flex;
  align-items: center;
  min-height: 24px;
  padding: 0.2rem 0.55rem;
  border-radius: 999px;
  font-size: 0.72rem;
  font-weight: 750;
  line-height: 1;
  white-space: nowrap;
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
}

.threat-micro-badge.threat-green {
  color: var(--color-green);
  background-color: rgba(16, 185, 129, 0.08);
  border-color: rgba(16, 185, 129, 0.24);
}

.threat-micro-badge.threat-blue {
  color: var(--color-blue);
  background-color: rgba(59, 130, 246, 0.08);
  border-color: rgba(59, 130, 246, 0.24);
}

.threat-micro-badge.threat-orange {
  color: var(--color-orange);
  background-color: rgba(245, 158, 11, 0.08);
  border-color: rgba(245, 158, 11, 0.24);
}

.threat-micro-badge.threat-red {
  color: var(--color-red);
  background-color: rgba(239, 68, 68, 0.08);
  border-color: rgba(239, 68, 68, 0.24);
}

.tile-footer-flex {
  display: flex;
  flex-direction: row;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-top: 0.85rem;
  color: var(--text-muted);
  font-size: 0.86rem;
  line-height: 1.35;
}

.tile-footer-flex strong {
  color: var(--text-main);
}

.symptoms-matched-tooltip {
  max-width: 100%;
  color: var(--text-main);
  overflow: hidden;
  text-overflow: ellipsis;
}

.tile-threat-green {
  border-color: rgba(72, 187, 120, 0.2) !important;
  background: linear-gradient(185deg, var(--bg-card-sub) 60%, rgba(72, 187, 120, 0.03)) !important;
}
.tile-threat-green:hover {
  border-color: rgba(72, 187, 120, 0.45) !important;
}

.tile-threat-blue {
  border-color: rgba(66, 153, 225, 0.2) !important;
  background: linear-gradient(185deg, var(--bg-card-sub) 60%, rgba(66, 153, 225, 0.03)) !important;
}
.tile-threat-blue:hover {
  border-color: rgba(66, 153, 225, 0.45) !important;
}

.tile-threat-orange {
  border-color: rgba(237, 137, 54, 0.2) !important;
  background: linear-gradient(185deg, var(--bg-card-sub) 60%, rgba(237, 137, 54, 0.03)) !important;
}
.tile-threat-orange:hover {
  border-color: rgba(237, 137, 54, 0.45) !important;
}

.tile-threat-red {
  border-color: rgba(245, 101, 101, 0.3) !important;
  background: linear-gradient(185deg, var(--bg-card-sub) 60%, rgba(245, 101, 101, 0.05)) !important;
}
.tile-threat-red:hover {
  border-color: rgba(245, 101, 101, 0.6) !important;
  box-shadow: 0 4px 20px rgba(245, 101, 101, 0.05);
}

.disease-chevron-icon {
  margin-left: 0.35rem;
  color: var(--text-muted);
  display: inline-flex;
  align-items: center;
  transition: transform 0.2s ease;
}

.chevron-rotated {
  transform: rotate(180deg);
}

.disease-expandable-panel {
  margin-top: 1rem;
  text-align: left;
}

.expandable-divider {
  border-top: 1px solid var(--border-color);
  margin-bottom: 0.85rem;
}

.expandable-symptoms-chips-group {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
}

.symptom-match-extracted {
  background-color: rgba(16, 185, 129, 0.08) !important;
  border-color: rgba(16, 185, 129, 0.25) !important;
  color: var(--text-main) !important;
  font-weight: 600 !important;
}

.symptom-match-assumed {
  background-color: rgba(59, 130, 246, 0.08) !important;
  border-color: rgba(59, 130, 246, 0.25) !important;
  color: var(--text-main) !important;
  font-weight: 600 !important;
}

.symptom-unmatched {
  opacity: 0.55;
  background-color: rgba(255, 255, 255, 0.02) !important;
  border-color: var(--border-color) !important;
}

.expandable-sub-section {
  margin-bottom: 0.85rem;
}

.expandable-sub-title {
  display: block;
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  margin-bottom: 0.35rem;
}

.expandable-sub-title.title-green {
  color: var(--color-green);
}

.expandable-sub-title.title-blue {
  color: var(--color-blue);
}

.expandable-sub-title.title-gray {
  color: var(--text-light);
}

/* Admin workspace shared layout */
.history-stat-chip {
  display: inline-flex;
  align-items: center;
  min-height: 34px;
  padding: 0.35rem 0.7rem;
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 999px;
  color: var(--text-main);
  font-size: 0.8rem;
  font-weight: 700;
  white-space: nowrap;
}

.history-header-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 0.55rem;
  flex-shrink: 0;
}

.btn-delete-history {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  min-height: 34px;
  padding: 0.35rem 0.85rem;
  background-color: rgba(255, 74, 74, 0.08);
  border: 1px solid rgba(255, 74, 74, 0.35);
  border-radius: 999px;
  color: #d83a3a;
  font-size: 0.8rem;
  font-weight: 700;
  white-space: nowrap;
  cursor: pointer;
  transition: background-color 0.15s ease, border-color 0.15s ease, opacity 0.15s ease;
}

.btn-delete-history:hover:not(:disabled) {
  background-color: rgba(255, 74, 74, 0.16);
  border-color: rgba(255, 74, 74, 0.55);
}

.btn-delete-history:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.history-period-filter {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  justify-content: space-between;
  gap: 0.75rem 1rem;
  margin-bottom: 1.25rem;
  padding: 1rem 1.1rem;
  background: var(--bg-card-sub);
  border: 1px solid var(--border-color);
  border-radius: 12px;
}

.history-period-fields {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: 0.75rem;
}

.history-period-field {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
}

.history-period-field label {
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
  color: var(--text-muted);
}

.history-period-field input {
  min-height: 38px;
  padding: 0.4rem 0.65rem;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  color: var(--text-main);
  font-size: 0.85rem;
  font-family: inherit;
}

.history-period-field input:focus {
  outline: none;
  border-color: var(--accent, #2f6df4);
}

.btn-apply-period {
  min-height: 38px;
  padding: 0.4rem 1.1rem;
  background: var(--accent, #2f6df4);
  border: 1px solid var(--accent, #2f6df4);
  border-radius: 8px;
  color: var(--on-accent, #fff);
  font-size: 0.85rem;
  font-weight: 700;
  cursor: pointer;
  transition: opacity 0.15s ease, background-color 0.15s ease;
}

.btn-apply-period:hover:not(:disabled) {
  background: var(--accent-hover, #2558c7);
  border-color: var(--accent-hover, #2558c7);
  opacity: 1;
}

.btn-apply-period:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.history-period-presets {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
}

.history-preset-chip {
  min-height: 32px;
  padding: 0.3rem 0.7rem;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 999px;
  color: var(--text-main);
  font-size: 0.78rem;
  font-weight: 600;
  cursor: pointer;
  transition: border-color 0.15s ease, background-color 0.15s ease;
}

.history-preset-chip:hover:not(:disabled) {
  border-color: var(--accent, #2f6df4);
  background: rgba(47, 109, 244, 0.06);
}

.history-preset-chip:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

@media (max-width: 760px) {
  .history-header-actions {
    justify-content: flex-start;
  }
}

/* Tab 2: Knowledge Base Management panel CSS (Admin only) */
.panel-knowledge-premium {
  margin-top: 0;
  width: 100%;
  max-width: 100%;
  min-width: 0;
  overflow-x: clip;
}

@media (min-width: 769px) {
  .panel-knowledge-premium {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
}

/* Avoid width/height "expansion" when panels mount; keep hover/color transitions */
.panel-knowledge-premium .diseases-list-card-premium,
.panel-knowledge-premium .symptom-editor-card-premium,
.panel-knowledge-premium .symptom-editor-empty,
.panel-knowledge-premium .audit-timeline-card-premium,
.panel-knowledge-premium .history-period-filter,
.diagnostics-panel-centered.admin-workspace-panel .workspace-card-wrapper,
.diagnostics-panel-centered.admin-workspace-panel .app-history-bottom-layout {
  transition:
    border-color 0.35s cubic-bezier(0.16, 1, 0.3, 1),
    box-shadow 0.35s cubic-bezier(0.16, 1, 0.3, 1),
    background-color 0.35s cubic-bezier(0.16, 1, 0.3, 1),
    color 0.35s cubic-bezier(0.16, 1, 0.3, 1),
    transform 0.35s cubic-bezier(0.16, 1, 0.3, 1),
    opacity 0.35s cubic-bezier(0.16, 1, 0.3, 1);
}

.knowledge-grid-layout {
  display: grid;
  grid-template-columns: minmax(0, 0.8fr) minmax(0, 1.6fr);
  gap: clamp(0.75rem, 2vw, 1.25rem);
  align-items: stretch;
  width: 100%;
  min-width: 0;
}

@media (min-width: 769px) {
  .knowledge-grid-layout {
    flex: 1;
    min-height: 0;
  }
}

@media (max-width: 900px) {
  .knowledge-grid-layout {
    grid-template-columns: 1fr;
  }
}

/* Sidebar tab switches for knowledge config */
.sidebar-tabs-container {
  display: flex;
  background-color: var(--bg-card-sub);
  padding: 0.25rem;
  border-radius: 10px;
  border: 1px solid var(--border-color);
  margin-bottom: 1rem;
  gap: 0.25rem;
}
.sidebar-tab-btn {
  flex: 1;
  border: none;
  background: transparent;
  padding: 0.5rem 0.75rem;
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--text-muted);
  border-radius: 8px;
  cursor: pointer;
  transition: var(--transition-smooth);
}
.sidebar-tab-btn.active {
  background-color: var(--bg-card);
  color: var(--accent);
  box-shadow: var(--shadow-sm);
}

.card-search-header-unified {
  margin-bottom: 0;
}

/* Edit & Rename buttons */
.tile-content-group {
  display: flex;
  flex: 1;
  align-items: center;
  min-width: 0;
  overflow: hidden;
}
.tile-title-line {
  display: flex;
  align-items: center;
  gap: 6px;
  width: 100%;
  min-width: 0;
}
.btn-tile-edit {
  border: none;
  background: transparent;
  padding: 2px;
  color: var(--text-light);
  border-radius: 4px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  opacity: 0;
  transition: var(--transition-smooth);
}
.disease-manager-tile:hover .btn-tile-edit {
  opacity: 1;
}
.btn-tile-edit:hover {
  color: var(--accent);
  background-color: var(--bg-hover);
}

/* Inline input editor for renames */
.inline-edit-form {
  display: flex;
  align-items: center;
  gap: 4px;
  width: 100%;
}
.input-inline-edit {
  flex: 1;
  background: var(--bg-input);
  border: 1px solid var(--border-focus);
  color: var(--text-main);
  font-size: 0.8rem;
  padding: 4px 8px;
  border-radius: 6px;
  outline: none;
}
.btn-inline-save, .btn-inline-cancel {
  border: none;
  background: transparent;
  font-size: 0.85rem;
  font-weight: bold;
  cursor: pointer;
  padding: 2px 6px;
  border-radius: 4px;
  transition: var(--transition-smooth);
}
.btn-inline-save {
  color: var(--color-green);
}
.btn-inline-save:hover {
  background-color: rgba(16, 185, 129, 0.1);
}
.btn-inline-cancel {
  color: var(--color-red);
}
.btn-inline-cancel:hover {
  background-color: rgba(239, 68, 68, 0.1);
}

.symptom-tile {
  cursor: default !important;
}


.diseases-list-card-premium {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-card);
  padding: 1.15rem;
  box-shadow: var(--shadow-md);
  min-height: 560px;
  display: flex;
  flex-direction: column;
  width: 100%;
  max-width: 100%;
  min-width: 0;
  box-sizing: border-box;
}

@media (min-width: 769px) {
  .diseases-list-card-premium {
    height: 100%;
    min-height: 0;
  }
}

.card-search-header h2 {
  font-size: 1.1rem;
  font-weight: 700;
  margin: 0 0 0.25rem 0;
  color: var(--text-main);
}

.sidebar-summary-premium {
  font-size: 0.72rem;
  color: var(--text-muted);
  margin-bottom: 0.75rem;
  font-weight: 500;
}

.search-input-wrapper-clean {
  width: 100%;
  min-width: 0;
}

.search-input-wrapper-clean input {
  width: 100%;
  max-width: 100%;
  box-sizing: border-box;
  background-color: var(--bg-input);
  border: 1px solid var(--border-color);
  color: var(--text-main);
  border-radius: 8px;
  padding: 0.6rem 0.85rem;
  font-size: 0.85rem;
  outline: none;
  transition: var(--transition-smooth);
}

.search-input-wrapper-clean input:focus {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.15);
}

.diseases-scroller-premium {
  flex: 1;
  overflow-y: auto;
  max-height: 420px;
  display: flex;
  flex-direction: column;
  gap: 0.45rem;
  margin: 0.35rem 0 0.85rem;
  padding-right: 0.25rem;
}

@media (min-width: 769px) {
  .diseases-scroller-premium {
    flex: 1;
    max-height: none;
  }
}

.disease-manager-tile {
  background-color: var(--bg-card-sub);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 0.72rem 0.8rem;
  cursor: pointer;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 0.35rem;
  width: 100%;
  max-width: 100%;
  min-width: 0;
  box-sizing: border-box;
  transition: var(--transition-smooth);
}

.disease-manager-tile:hover {
  background-color: var(--bg-hover);
  border-color: rgba(2, 132, 199, 0.2);
}

.disease-manager-tile.active {
  border-color: var(--accent);
  background-color: var(--accent-light);
  box-shadow: 0 2px 8px rgba(2, 132, 199, 0.1);
}

.d-meta-row {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  flex: 1;
  min-width: 0;
}

.d-label-name {
  flex: 1;
  min-width: 0;
  font-size: 0.85rem;
  font-weight: 650;
  color: var(--text-main);
  line-height: 1.3;
  overflow-wrap: anywhere;
  word-break: break-word;
}

.tile-info-line {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.threat-badge-mini {
  font-size: 0.65rem;
  font-weight: 600;
  padding: 0.05rem 0.35rem;
  border-radius: 4px;
  text-transform: uppercase;
}

.threat-badge-mini.threat-green {
  background-color: rgba(16, 185, 129, 0.1);
  color: var(--color-green);
}
.threat-badge-mini.threat-blue {
  background-color: rgba(59, 130, 246, 0.1);
  color: var(--color-blue);
}
.threat-badge-mini.threat-orange {
  background-color: rgba(245, 158, 11, 0.1);
  color: var(--color-orange);
}
.threat-badge-mini.threat-red {
  background-color: rgba(239, 68, 68, 0.1);
  color: var(--color-red);
}

.symptom-count-badge {
  font-size: 0.68rem;
  color: var(--text-muted);
  background-color: rgba(15, 23, 42, 0.04);
  padding: 0.05rem 0.35rem;
  border-radius: 4px;
  border: 1px solid var(--border-color);
}

.btn-tile-delete {
  background: none;
  border: none;
  color: var(--text-light);
  font-size: 1.3rem;
  cursor: pointer;
  line-height: 1;
  padding: 0 0.25rem;
  flex-shrink: 0;
  transition: var(--transition-smooth);
}

.btn-tile-delete:hover {
  color: var(--color-red);
}

.add-disease-inline-form {
  display: flex;
  gap: 0.4rem;
  margin-bottom: 1rem;
  min-width: 0;
  width: 100%;
}

.add-disease-inline-form input {
  flex: 1;
  min-width: 0;
  background-color: var(--bg-input);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  color: var(--text-main);
  padding: 0.55rem;
  font-size: 0.82rem;
  outline: none;
  transition: var(--transition-smooth);
}

.add-disease-inline-form input:focus {
  border-color: var(--border-focus);
}

.btn-add-item {
  background-color: var(--accent);
  color: #fff;
  border: none;
  font-weight: 600;
  padding: 0 1rem;
  border-radius: 8px;
  cursor: pointer;
  transition: var(--transition-smooth);
}

.btn-add-item:hover:not(:disabled) {
  background-color: #02669a;
}

.btn-save-valkey-db {
  width: 100%;
  background-color: var(--color-green);
  color: #fff;
  border: none;
  font-size: 0.88rem;
  font-weight: 700;
  padding: 0.8rem;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  box-shadow: 0 2px 6px rgba(16, 185, 129, 0.2);
}

.btn-save-valkey-db:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
}

.btn-save-valkey-db:disabled {
  background-color: var(--color-gray);
  cursor: not-allowed;
  opacity: 0.55;
  box-shadow: none;
  transform: none;
}

.symptom-editor-card-premium {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-card);
  padding: 1.25rem;
  box-shadow: var(--shadow-md);
  width: 100%;
  max-width: 100%;
  min-width: 0;
  box-sizing: border-box;
}

@media (min-width: 769px) {
  .symptom-editor-card-premium {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }
}

.editor-header-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1rem;
  min-width: 0;
}

.symptom-editor-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  min-height: 400px;
  border: 2px dashed var(--border-color);
  background: var(--bg-card-sub);
  border-radius: 16px;
  padding: 2rem;
  box-sizing: border-box;
}

.knowledge-load-error {
  border-color: rgba(239, 68, 68, 0.35);
  background: rgba(239, 68, 68, 0.04);
}

.knowledge-empty-icon {
  width: 64px;
  height: 64px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 1.25rem;
}

.knowledge-empty-icon--error {
  background: rgba(239, 68, 68, 0.1);
  color: var(--color-red);
}

.knowledge-empty-icon--info {
  background: var(--accent-light);
  color: var(--accent);
}

.knowledge-empty-title {
  margin: 0 0 0.5rem 0;
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--text-main);
}

.knowledge-load-error .knowledge-empty-title {
  color: var(--color-red);
}

.knowledge-empty-text {
  margin: 0 0 1rem 0;
  font-size: 0.85rem;
  color: var(--text-muted);
  max-width: 320px;
  line-height: 1.5;
}

.editor-header-sticky-premium {
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 1.25rem;
  margin-bottom: 1.25rem;
}

.focused-disease-title {
  color: var(--accent);
  text-decoration: underline;
  text-underline-offset: 4px;
}

/* Interactive segmented threat picker */
.threat-segmented-picker {
  margin-top: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.picker-label {
  font-size: 0.78rem;
  color: var(--text-muted);
  font-weight: 700;
  text-transform: uppercase;
}

.segments-container {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  background-color: var(--bg-card-sub);
  padding: 0.25rem;
  border-radius: 10px;
  border: 1px solid var(--border-color);
  gap: 0.25rem;
}

@media (max-width: 600px) {
  .segments-container {
    grid-template-columns: 1fr;
  }
}

.segment-btn {
  border: none;
  background: none;
  padding: 0.5rem 0.75rem;
  border-radius: 8px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  font-size: 0.8rem;
  font-weight: 600;
  transition: all 0.2s ease;
  color: var(--text-muted);
}

.segment-btn:hover {
  background-color: rgba(15, 23, 42, 0.04);
  color: var(--text-main);
}

.segment-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: var(--text-light);
  transition: transform 0.2s ease;
}

.segment-btn.active {
  color: #fff;
}

.segment-btn.active .segment-dot {
  background-color: #fff;
  box-shadow: 0 0 6px rgba(255,255,255,0.8);
}

.segment-btn.threat-green.active {
  background-color: var(--color-green);
  box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3);
}
.segment-btn.threat-green:not(.active) .segment-dot { background-color: var(--color-green); }

.segment-btn.threat-blue.active {
  background-color: var(--color-blue);
  box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3);
}
.segment-btn.threat-blue:not(.active) .segment-dot { background-color: var(--color-blue); }

.segment-btn.threat-orange.active {
  background-color: var(--color-orange);
  box-shadow: 0 2px 8px rgba(245, 158, 11, 0.3);
}
.segment-btn.threat-orange:not(.active) .segment-dot { background-color: var(--color-orange); }

.segment-btn.threat-red.active {
  background-color: var(--color-red);
  box-shadow: 0 2px 8px rgba(239, 68, 68, 0.3);
}
.segment-btn.threat-red:not(.active) .segment-dot { background-color: var(--color-red); }

/* Symptom search & bulk action styles */
.symptom-search-bar-wrapper {
  background-color: var(--bg-card-sub);
  border: 1px solid var(--border-color);
  padding: 0.8rem;
  border-radius: 12px;
  margin-bottom: 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.symptom-search-field {
  position: relative;
  display: flex;
  align-items: center;
}

.symptom-search-field input {
  width: 100%;
  padding: 0.55rem 2rem 0.55rem 0.85rem;
  font-size: 0.85rem;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  outline: none;
  background-color: var(--bg-input);
  color: var(--text-main);
  transition: var(--transition-smooth);
}

.symptom-search-field input:focus {
  border-color: var(--border-focus);
}

.btn-clear-search {
  position: absolute;
  right: 0.65rem;
  background: none;
  border: none;
  color: var(--text-light);
  font-size: 1.2rem;
  cursor: pointer;
}

.btn-clear-search:hover {
  color: var(--text-main);
}

.symptom-bulk-actions {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.btn-bulk-action {
  background-color: var(--bg-input);
  border: 1px solid var(--border-color);
  color: var(--text-muted);
  font-size: 0.72rem;
  font-weight: 600;
  padding: 0.35rem 0.65rem;
  border-radius: 6px;
  cursor: pointer;
  transition: var(--transition-smooth);
}

.btn-bulk-action:hover {
  background-color: var(--bg-hover);
  color: var(--text-main);
  border-color: var(--text-light);
}

.editor-sub-lbl {
  font-size: 0.78rem;
  color: var(--text-muted);
  font-weight: 700;
  text-transform: uppercase;
  display: block;
  margin-bottom: 0.85rem;
}

.symptoms-grid-checklist {
  margin-bottom: 1.5rem;
}

.checklist-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 11.5rem), 1fr));
  gap: 0.45rem;
  max-height: 340px;
  overflow-y: auto;
  overflow-x: hidden;
  border: 1px solid var(--border-color);
  padding: 0.75rem;
  border-radius: 12px;
  background-color: var(--bg-card-sub);
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
}

@media (min-width: 769px) {
  .symptoms-grid-checklist {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    margin-bottom: 0;
  }

  .checklist-grid {
    flex: 1;
    min-height: 0;
    max-height: none;
  }
}

.symptom-checkbox-card {
  background-color: var(--bg-input);
  border: 1px solid var(--border-color);
  border-radius: 10px;
  padding: 0.55rem 0.7rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  min-width: 0;
  max-width: 100%;
  box-sizing: border-box;
  cursor: pointer;
  transition: all 0.15s ease;
}

.symptom-checkbox-card:hover {
  border-color: var(--text-light);
  background-color: var(--bg-hover);
}

.symptom-checkbox-card.selected {
  border-color: var(--accent);
  background-color: var(--accent-light);
  box-shadow: 0 1px 4px rgba(2, 132, 199, 0.08);
}

.symptom-redflag-toggle {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  margin-left: auto;
  flex-shrink: 0;
  padding: 0.15rem 0.35rem;
  border-radius: 6px;
  border: 1px solid var(--border-color);
  background: var(--bg-card);
  color: var(--text-muted);
  font-size: 0.7rem;
  font-weight: 700;
  cursor: pointer;
  user-select: none;
}

.symptom-redflag-toggle:has(input:checked) {
  border-color: #ef4444;
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
}

.symptom-redflag-toggle input {
  width: 12px;
  height: 12px;
  margin: 0;
  cursor: pointer;
  accent-color: var(--color-red);
}

.checkbox-custom-wrapper {
  display: flex;
  align-items: center;
  position: relative;
}

.checkbox-custom-wrapper input {
  position: absolute;
  opacity: 0;
  cursor: pointer;
  height: 0; width: 0;
}

.checkbox-indicator {
  width: 15px;
  height: 15px;
  border: 1.5px solid var(--text-light);
  border-radius: 4px;
  background-color: var(--bg-input);
  display: inline-block;
  position: relative;
  transition: all 0.15s ease;
}

.symptom-checkbox-card.selected .checkbox-indicator {
  background-color: var(--accent);
  border-color: var(--accent);
}

.symptom-checkbox-card.selected .checkbox-indicator::after {
  content: "";
  position: absolute;
  display: block;
  left: 4.5px;
  top: 1.5px;
  width: 3.5px;
  height: 7px;
  border: solid white;
  border-width: 0 1.8px 1.8px 0;
  transform: rotate(45deg);
}

@media (prefers-color-scheme: dark) {
  .symptom-checkbox-card.selected .checkbox-indicator {
    background-color: var(--color-blue);
    border-color: var(--color-blue);
  }

  .symptom-checkbox-card.selected .checkbox-indicator::after {
    border-color: #ffffff;
  }

  .symptom-redflag-toggle input {
    color-scheme: dark;
  }
}

.checkbox-label-text {
  font-size: 0.8rem;
  color: var(--text-main);
  flex: 1;
  min-width: 0;
  line-height: 1.3;
  overflow-wrap: anywhere;
  word-break: break-word;
}

.btn-remove-symptom-tag-global {
  background: none;
  border: none;
  color: var(--text-light);
  cursor: pointer;
  font-size: 1.1rem;
  padding: 0 0.15rem;
  line-height: 1;
  transition: var(--transition-smooth);
}

.btn-remove-symptom-tag-global:hover {
  color: var(--color-red);
}

.empty-symptoms-search {
  grid-column: 1 / -1;
  text-align: center;
  padding: 2rem;
  color: var(--text-muted);
  font-size: 0.85rem;
}

.add-symptom-global-form-premium {
  border-top: 1px solid var(--border-color);
  padding-top: 1.25rem;
}

.add-symptom-global-form-premium h3 {
  font-size: 0.85rem;
  margin-bottom: 0.5rem;
  color: var(--text-muted);
}

.inline-symptom-form {
  display: flex;
  gap: 0.4rem;
}

.inline-symptom-form input {
  flex: 1;
  background-color: var(--bg-input);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  color: var(--text-main);
  padding: 0.55rem;
  font-size: 0.82rem;
  outline: none;
  transition: var(--transition-smooth);
}

.inline-symptom-form input:focus {
  border-color: var(--border-focus);
}

.btn-submit-symptom {
  background-color: var(--bg-card-sub);
  border: 1px solid var(--border-color);
  color: var(--text-main);
  font-size: 0.8rem;
  padding: 0.5rem 1.2rem;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
  transition: var(--transition-smooth);
}

.btn-submit-symptom:hover {
  background-color: var(--accent);
  color: #fff;
  border-color: var(--accent);
}

.empty-symptom-placeholder {
  display: flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  color: var(--text-muted);
  min-height: 550px;
}

.audit-timeline-card-premium {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-card);
  padding: 1.05rem 1.15rem;
  box-shadow: var(--shadow-md);
}

.admin-collapsible-panel summary {
  cursor: pointer;
  list-style: none;
}

.admin-collapsible-panel summary::-webkit-details-marker {
  display: none;
}

.admin-collapsible-panel summary::after {
  content: "Показать";
  color: var(--accent);
  font-size: 0.78rem;
  font-weight: 750;
}

.admin-collapsible-panel[open] summary {
  margin-bottom: 1rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border-color);
}

.admin-collapsible-panel[open] summary::after {
  content: "Скрыть";
}

.audit-timeline-card-premium h2 {
  font-size: 0.95rem;
  font-weight: 700;
  margin: 0;
  text-transform: uppercase;
}

.audit-header-actions-premium {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1rem;
}

.btn-clear-perf-metrics {
  background: none;
  border: 1px solid var(--border-color);
  color: var(--color-red);
  font-size: 0.75rem;
  padding: 0.4rem 0.85rem;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 600;
  transition: var(--transition-smooth);
}

.btn-clear-perf-metrics:hover {
  background-color: rgba(239, 68, 68, 0.05);
}

.audit-log-scroller-premium {
  max-height: 250px;
  overflow-y: auto;
  border: 1px solid var(--border-color);
  border-radius: 10px;
  margin-top: 1.25rem;
}

.audit-log-scroller-wide {
  overflow-x: auto;
}

.audit-log-table-premium {
  width: 100%;
  min-width: 920px;
  border-collapse: collapse;
  font-size: 0.78rem;
}

.audit-log-table-premium th {
  background-color: var(--bg-card-sub);
  color: var(--text-muted);
  padding: 0.65rem 0.85rem;
  border-bottom: 1px solid var(--border-color);
  text-align: left;
  font-weight: 600;
}

.audit-log-table-premium td {
  padding: 0.65rem 0.85rem;
  border-bottom: 1px solid var(--border-color);
  color: var(--text-main);
}

.col-timestamp {
  color: var(--text-light);
  white-space: nowrap;
}

.badge-timeline-event {
  font-size: 0.65rem;
  padding: 0.1rem 0.35rem;
  border-radius: 4px;
  font-weight: 700;
  text-transform: uppercase;
}

.badge-timeline-event.event-analyze {
  background-color: var(--accent-light);
  color: var(--accent);
}

.badge-timeline-event.event-update {
  background-color: rgba(16, 185, 129, 0.08);
  color: var(--color-green);
}

.badge-timeline-event.event-reset {
  background-color: rgba(245, 158, 11, 0.08);
  color: var(--color-orange);
}



/* Custom confirmation modal styling */
.confirm-modal-overlay {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background-color: rgba(0, 0, 0, 0.35);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 2500;
  animation: anim-fade-in 0.2s ease-out;
}

.confirm-modal-card {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 20px;
  padding: 1.75rem;
  width: 340px;
  box-shadow: var(--shadow-lg);
  display: flex;
  flex-direction: column;
  gap: 1rem;
  animation: anim-scale-up 0.28s cubic-bezier(0.16, 1, 0.3, 1);
}

.confirm-modal-card h3 {
  margin: 0;
  font-size: 1.05rem;
  font-weight: 700;
  color: var(--text-main);
  letter-spacing: -0.01em;
}

.confirm-modal-card p {
  margin: 0;
  font-size: 0.85rem;
  color: var(--text-muted);
  line-height: 1.45;
}

.btn-modal-confirm {
  background-color: var(--color-red);
  color: #fff;
  border: none;
  font-size: 0.85rem;
  padding: 0.45rem 1.1rem;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
  transition: var(--transition-smooth);
}

.btn-modal-confirm:hover {
  opacity: 0.9;
  transform: translateY(-1px);
}

.modal-buttons {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
  margin-top: 0.5rem;
}

.btn-modal-cancel {
  background-color: var(--glass-bg);
  color: var(--text-secondary);
  border: 1px solid var(--border-color);
  font-size: 0.85rem;
  padding: 0.45rem 1.1rem;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
  transition: var(--transition-smooth);
}

.btn-modal-cancel:hover {
  background-color: var(--border-color);
  color: var(--text-primary);
  transform: translateY(-1px);
}

/* Animations spin */
@keyframes spin {
  100% { transform: rotate(360deg); }
}

/* Bottom history panel */
.app-history-bottom-layout {
  width: 100%;
  max-width: 860px;
  margin: 1.5rem auto 0;
  padding: 1.25rem;
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius-card);
  box-shadow: var(--shadow-md);
}

.history-panel-layout {
  max-width: none;
  margin-top: 0;
}

.history-search-wrapper {
  margin-bottom: 1rem;
}

.history-bottom-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding-bottom: 1rem;
  margin-bottom: 1rem;
  border-bottom: 1px solid var(--border-color);
}

.history-bottom-header h3 {
  margin: 0;
  color: var(--text-main);
  font-size: 1.05rem;
  font-weight: 750;
  letter-spacing: -0.01em;
}

.history-grid-bottom {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 0.85rem;
}

.history-card-bottom {
  border: 1px solid var(--border-color);
  background-color: var(--bg-card-sub);
  border-radius: 14px;
  padding: 0.9rem 1rem;
  cursor: pointer;
  transition: var(--transition-smooth);
  min-width: 0;
}

.history-card-bottom:hover {
  transform: translateY(-2px);
  border-color: rgba(2, 132, 199, 0.28);
  box-shadow: var(--shadow-sm);
}

.hist-card-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  margin-bottom: 0.55rem;
}

.hist-time {
  color: var(--accent);
  font-size: 0.78rem;
  font-weight: 750;
}

.btn-delete-history-item {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  padding: 0;
  border: 1px solid rgba(255, 74, 74, 0.25);
  border-radius: 10px;
  background: rgba(255, 74, 74, 0.06);
  color: #d83a3a;
  cursor: pointer;
  flex-shrink: 0;
  transition: background-color 0.15s ease, border-color 0.15s ease, opacity 0.15s ease;
}

.btn-delete-history-item:hover:not(:disabled) {
  background: rgba(255, 74, 74, 0.14);
  border-color: rgba(255, 74, 74, 0.45);
}

.btn-delete-history-item:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.btn-download-history-pdf {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  padding: 0;
  border: 1px solid var(--border-color);
  border-radius: 10px;
  background: var(--bg-card-sub);
  color: var(--accent);
  cursor: pointer;
  flex-shrink: 0;
  transition: var(--transition-smooth);
}

.btn-download-history-pdf:hover {
  background: var(--accent-light);
  border-color: var(--accent);
  color: var(--accent-hover);
}

.hist-session-id-row {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  margin-bottom: 0.45rem;
  min-width: 0;
}

.hist-session-id {
  flex: 1;
  min-width: 0;
  margin-bottom: 0;
  color: var(--text-muted);
  font-family: var(--font-mono, monospace);
  font-size: 0.7rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.btn-copy-session-id {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 28px;
  height: 28px;
  padding: 0;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  background: var(--bg-card);
  color: var(--text-muted);
  cursor: pointer;
  transition: var(--transition-smooth);
}

.btn-copy-session-id:hover {
  color: var(--accent);
  border-color: rgba(2, 132, 199, 0.35);
  background: var(--bg-hover);
}

.hist-preview-text {
  margin: 0;
  color: var(--text-main);
  font-size: 0.86rem;
  line-height: 1.45;
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
  overflow-wrap: anywhere;
}

@media (max-width: 640px) {
  .history-bottom-header {
    align-items: stretch;
    flex-direction: column;
  }

}

/* Medical Disclaimer Footer CSS */
.app-disclaimer-footer {
  margin-top: 1.25rem;
  margin-inline: calc(-1 * clamp(0.75rem, 4vw, 1.5rem));
  padding-top: 0.75rem;
  padding-bottom: 0.75rem;
  padding-inline: clamp(0.75rem, 4vw, 1.5rem);
  width: calc(100% + 2 * clamp(0.75rem, 4vw, 1.5rem));
  box-sizing: border-box;
  text-align: center;
  border-top: 1px solid var(--border-color);
}

.disclaimer-text {
  font-size: 0.8rem;
  color: var(--text-muted);
  line-height: 1.6;
  margin: 0;
  width: 100%;
  max-width: none;
}

/* Admin access denied (logged in, no admin group) */
.admin-access-denied-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1.25rem;
  padding: 2.5rem;
  text-align: center;
  border: 1px solid rgba(255, 74, 74, 0.25);
  background: rgba(255, 74, 74, 0.04);
  border-radius: 12px;
}

.admin-access-denied-icon {
  width: 64px;
  height: 64px;
  border-radius: 50%;
  background: rgba(255, 74, 74, 0.1);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #ff4a4a;
}

.admin-access-denied-title {
  color: #ff4a4a;
  font-weight: 700;
  margin: 0;
  font-size: 1.5rem;
}

.admin-access-denied-text {
  color: var(--text-secondary);
  max-width: 480px;
  line-height: 1.6;
  margin: 0;
}

/* Admin workspace panels: smooth slide-up on tab switch */
.admin-workspace-panel {
  width: 100%;
  min-width: 0;
}

.admin-panel-slide-enter-active {
  transition:
    opacity 0.38s cubic-bezier(0.16, 1, 0.3, 1),
    transform 0.38s cubic-bezier(0.16, 1, 0.3, 1);
}

.admin-panel-slide-enter-from {
  opacity: 0;
  transform: translateY(28px);
}

.admin-panel-slide-enter-to {
  opacity: 1;
  transform: translateY(0);
}

.admin-panel-slide-leave-active {
  display: none;
}

@media (prefers-reduced-motion: reduce) {
  .admin-panel-slide-enter-active {
    transition: opacity 0.15s ease;
  }

  .admin-panel-slide-enter-from {
    transform: none;
  }
}

.nav-tab-logout {
  color: var(--color-red) !important;
  opacity: 0.8;
}

.nav-tab-logout:hover {
  opacity: 1 !important;
}

.nav-tab-settings {
  text-decoration: none;
  display: inline-flex;
  align-items: center;
}

@media (max-width: 768px) {
  .ophthalmo-app {
    padding-inline: clamp(0.65rem, 3.5vw, 1rem);
  }

  .ophthalmo-app.ophthalmo-app--with-bottom-nav {
    min-height: 100dvh;
    padding-bottom: var(--app-bottom-nav-offset);
    scroll-padding-bottom: var(--app-bottom-nav-offset);
  }

  .app-header-premium {
    padding-bottom: 0.35rem;
    border-bottom: none;
  }

  .app-nav-desktop {
    display: none;
  }

  .app-admin-mobile-actions {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    flex-wrap: wrap;
    gap: 0.75rem 1.25rem;
    width: 100%;
  }

  .app-nav-bottom-mobile {
    display: flex;
    position: fixed;
    inset-inline: 0;
    bottom: 0;
    width: 100%;
    max-width: 100vw;
    z-index: 200;
    align-items: stretch;
    gap: 0.15rem;
    min-height: var(--app-bottom-nav-height);
    padding: 0.35rem 0.5rem calc(0.35rem + env(safe-area-inset-bottom, 0px));
    background: var(--bg-card);
    border-top: 1px solid var(--border-color);
    box-shadow: 0 -8px 24px rgba(15, 23, 42, 0.08);
  }

  .app-workspace-container.with-admin-nav {
    padding-top: 0.5rem;
    flex: 1;
    min-height: 0;
  }

  .ophthalmo-app--with-bottom-nav .app-history-bottom-layout {
    margin-bottom: 0.75rem;
  }

  .app-disclaimer-footer {
    margin-bottom: 0;
    flex-shrink: 0;
    margin-inline: calc(-1 * clamp(0.65rem, 3.5vw, 1rem));
    padding-inline: clamp(0.65rem, 3.5vw, 1rem);
    width: calc(100% + 2 * clamp(0.65rem, 3.5vw, 1rem));
  }

  .centered-workspace-card {
    max-width: 100%;
  }

  .workspace-card-wrapper {
    border-radius: 18px;
  }

  .textarea-container-premium textarea {
    min-height: 130px;
    font-size: 1rem;
  }

  .textarea-container-premium textarea::placeholder {
    font-size: 1rem;
  }

  .textarea-toolbar {
    flex-direction: row;
    align-items: center;
    gap: 0.5rem;
  }

  .diagnostic-actions-left {
    justify-content: flex-start;
    overflow-x: auto;
    scrollbar-width: none;
  }

  .diagnostic-actions-left::-webkit-scrollbar {
    display: none;
  }

  .status-tip {
    white-space: nowrap;
  }

  .history-period-filter {
    flex-direction: column;
    align-items: stretch;
  }

  .history-period-fields {
    flex-direction: column;
    align-items: stretch;
    width: 100%;
  }

  .history-period-field {
    width: 100%;
  }

  .history-period-field input {
    width: 100%;
    box-sizing: border-box;
  }

  .btn-apply-period {
    width: 100%;
  }

  .history-grid-bottom {
    grid-template-columns: 1fr;
  }

  .diseases-list-card-premium {
    min-height: 0;
    padding: clamp(0.75rem, 3vw, 1.15rem);
  }

  .knowledge-grid-layout {
    grid-template-columns: minmax(0, 1fr);
    gap: clamp(0.65rem, 2.5vw, 1rem);
  }

  .sidebar-tabs-container {
    gap: 0.2rem;
  }

  .sidebar-tab-btn {
    min-width: 0;
    padding: 0.45rem 0.5rem;
    font-size: clamp(0.7rem, 3.2vw, 0.82rem);
  }

  .diseases-scroller-premium {
    max-height: min(38dvh, 22rem);
    overflow-x: hidden;
    -webkit-overflow-scrolling: touch;
  }

  .disease-manager-tile:hover {
    transform: none;
  }

  .disease-manager-tile:hover .btn-tile-edit,
  .btn-tile-edit {
    opacity: 1;
  }

  .symptom-editor-card-premium {
    padding: clamp(0.75rem, 3vw, 1.25rem);
  }

  .symptom-editor-empty {
    min-height: min(42dvh, 16rem);
    padding: clamp(1rem, 4vw, 2rem);
  }

  .editor-header-row {
    flex-direction: column;
    align-items: stretch;
  }

  .checklist-grid {
    grid-template-columns: minmax(0, 1fr);
    max-height: min(42dvh, 24rem);
  }

  .symptom-bulk-actions {
    flex-direction: column;
    align-items: stretch;
  }

  .btn-bulk-action {
    width: 100%;
    text-align: center;
  }

  /* Adaptive mobile styles for history table */
  .history-table-wrapper-premium {
    border: none;
    background: transparent;
    margin-top: 0.5rem;
  }

  .history-table-premium thead {
    display: none;
  }

  .history-table-premium,
  .history-table-premium tbody,
  .history-table-premium tr.history-table-row-premium,
  .history-table-premium tr.history-table-row-premium td {
    display: block;
    width: 100%;
    box-sizing: border-box;
  }

  .history-table-premium tr.history-table-row-premium {
    margin-bottom: 1.25rem;
    background-color: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius-card);
    padding: 1.25rem 1rem;
    box-shadow: var(--shadow-sm);
  }

  .history-table-premium tr.history-table-row-premium td {
    padding: 0.65rem 0 !important;
    border-bottom: 1px solid var(--border-color) !important;
    text-align: left !important;
    background: transparent !important;
  }

  .history-table-premium tr.history-table-row-premium td::before {
    content: attr(data-label);
    font-weight: 700;
    color: var(--accent);
    font-size: 0.72rem;
    text-transform: uppercase;
    display: block;
    margin-bottom: 0.35rem;
    letter-spacing: 0.05em;
  }

  .history-table-premium tr.history-table-row-premium td.td-diseases {
    border-bottom: none !important;
  }

  .history-table-premium tr.history-table-row-premium td.td-actions {
    display: flex !important;
    justify-content: flex-end;
    align-items: center;
    border-bottom: none !important;
    padding-bottom: 0 !important;
    padding-top: 0 !important;
  }
}

@media (max-width: 380px) {
  .sidebar-tab-btn {
    font-size: 0.68rem;
    padding: 0.4rem 0.35rem;
  }

  .threat-badge-mini,
  .symptom-count-badge {
    font-size: 0.6rem;
  }
}



.threat-advice-box {
  position: relative;
  border-radius: 12px;
  padding: 1rem 1rem 1rem 1.85rem;
  margin-top: 0.75rem;
  border: 1px solid var(--border-color);
  background-color: var(--bg-card-sub);
  transition: var(--transition-smooth);
}

.threat-advice-box::before {
  content: '';
  position: absolute;
  left: 10px;
  top: 1rem;
  bottom: 1rem;
  width: 4px;
  border-radius: 99px;
  transition: var(--transition-smooth);
}

.threat-advice-text {
  margin: 0;
  font-size: 0.85rem;
  line-height: 1.5;
  color: var(--text-main);
}

.threat-advice-text strong {
  font-weight: 700;
}

/* Threat specific styling */
.threat-advice-box.advice-threat-green {
  border-color: rgba(16, 185, 129, 0.15);
  background: linear-gradient(90deg, rgba(16, 185, 129, 0.04) 0%, var(--bg-card-sub) 100%);
}
.threat-advice-box.advice-threat-green::before {
  background-color: var(--color-green);
  box-shadow: 0 0 8px rgba(16, 185, 129, 0.45);
}

.threat-advice-box.advice-threat-blue {
  border-color: rgba(59, 130, 246, 0.15);
  background: linear-gradient(90deg, rgba(59, 130, 246, 0.04) 0%, var(--bg-card-sub) 100%);
}
.threat-advice-box.advice-threat-blue::before {
  background-color: var(--color-blue);
  box-shadow: 0 0 8px rgba(59, 130, 246, 0.45);
}

.threat-advice-box.advice-threat-orange {
  border-color: rgba(245, 158, 11, 0.15);
  background: linear-gradient(90deg, rgba(245, 158, 11, 0.04) 0%, var(--bg-card-sub) 100%);
}
.threat-advice-box.advice-threat-orange::before {
  background-color: var(--color-orange);
  box-shadow: 0 0 8px rgba(245, 158, 11, 0.45);
}

.threat-advice-box.advice-threat-red {
  border-color: rgba(239, 68, 68, 0.15);
  background: linear-gradient(90deg, rgba(239, 68, 68, 0.04) 0%, var(--bg-card-sub) 100%);
}
.threat-advice-box.advice-threat-red::before {
  background-color: var(--color-red);
  box-shadow: 0 0 8px rgba(239, 68, 68, 0.45);
}

.threat-advice-critical-extra {
  margin-top: 0.75rem;
  padding-top: 0.75rem;
  border-top: 1px solid rgba(239, 68, 68, 0.18);
}

.threat-advice-text-phones {
  margin-top: 0;
}

.threat-advice-inline-link {
  color: inherit;
  text-decoration: none;
}

.threat-advice-inline-link strong {
  color: var(--color-red);
  font-weight: 800;
}

.threat-advice-inline-link:hover strong {
  text-decoration: underline;
}

.threat-advice-inline-link:focus-visible {
  outline: 2px solid var(--color-red);
  outline-offset: 2px;
  border-radius: 2px;
}

.btn-find-hospital-maps {
  margin-top: 0.75rem;
  width: 100%;
  padding: 0.55rem 0.85rem;
  border-radius: 8px;
  border: 1px solid rgba(239, 68, 68, 0.28);
  background: rgba(239, 68, 68, 0.08);
  color: var(--text-main);
  font-size: 0.85rem;
  font-weight: 600;
  line-height: 1.35;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  transition: var(--transition-smooth);
}

.btn-find-hospital-maps:hover {
  background: rgba(239, 68, 68, 0.14);
  border-color: rgba(239, 68, 68, 0.45);
  transform: translateY(-1px);
}

.btn-find-hospital-maps:focus-visible {
  outline: 2px solid var(--color-red);
  outline-offset: 2px;
}

.btn-find-hospital-maps svg {
  color: var(--color-red);
  flex-shrink: 0;
}

/* Mobile responsiveness adjustments */
@media (max-width: 480px) {
  .diagnostic-actions-left {
    width: auto;
  }
  .results-header-actions {
    flex-direction: column;
    align-items: stretch;
    gap: 0.75rem;
    text-align: center;
  }
  .results-header-actions h3 {
    font-size: 1rem;
  }
  .action-btn-row {
    justify-content: center;
    width: 100%;
  }
  .btn-export-pdf-report {
    width: 100%;
    justify-content: center;
    display: inline-flex;
  }
}

/* Dark-mode action buttons: must come after base rules to win the cascade */
@media (prefers-color-scheme: dark) {
  .history-period-field input,
  .table-filter-input {
    color-scheme: dark;
  }

  .history-period-field input::-webkit-calendar-picker-indicator,
  .table-filter-input::-webkit-calendar-picker-indicator {
    filter: invert(1);
    cursor: pointer;
  }

  .btn-primary-submit-diagnostic {
    background: linear-gradient(135deg, #404040 0%, #525252 100%);
    border: none;
    color: #ffffff;
    box-shadow: 0 10px 20px -10px rgba(0, 0, 0, 0.55);
  }

  .btn-primary-submit-diagnostic:hover:not(:disabled) {
    background: linear-gradient(135deg, #525252 0%, #666666 100%);
    box-shadow: 0 12px 24px -10px rgba(0, 0, 0, 0.65);
    opacity: 1;
    transform: translateY(-1px);
  }

  .btn-apply-period {
    background: #f0f0f0;
    border-color: #d4d4d4;
    color: #0a0a0a;
  }

  .btn-apply-period:hover:not(:disabled) {
    background: #ffffff;
    border-color: #ffffff;
    color: #000000;
  }

  .btn-add-item {
    background-color: #f0f0f0;
    color: #0a0a0a;
  }

  .btn-add-item:hover:not(:disabled) {
    background-color: #ffffff;
  }
}

.history-checkbox-all,
.history-checkbox-row {
  width: 16px;
  height: 16px;
  cursor: pointer;
  accent-color: var(--accent);
}

.history-table-row-premium.row-selected {
  background-color: var(--bg-hover) !important;
}

.history-table-row-premium.row-selected td {
  background-color: var(--bg-hover) !important;
}

/* Offline Banner styling */
.offline-banner {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  background: rgba(239, 68, 68, 0.95);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  color: #ffffff;
  padding: 0.65rem 1rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  font-size: 0.88rem;
  font-weight: 600;
  z-index: 10000;
  box-shadow: 0 4px 12px rgba(239, 68, 68, 0.15);
  text-align: center;
}

.offline-banner-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  transform-origin: center;
}

.offline-banner-icon--pulse {
  animation: offline-wifi-blink 1.75s ease-in-out infinite;
}

.offline-banner-icon--restored {
  animation: restored-icon-pop 0.85s cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
}

.offline-banner-check-mark {
  stroke-dasharray: 24;
  stroke-dashoffset: 24;
  animation: checkmark-draw 0.75s cubic-bezier(0.65, 0, 0.35, 1) 0.25s forwards;
}

@keyframes offline-wifi-blink {
  0%, 100% {
    opacity: 0.4;
    transform: scale(0.94);
  }
  50% {
    opacity: 1;
    transform: scale(1.06);
  }
}

@keyframes restored-icon-pop {
  0% {
    opacity: 0;
    transform: scale(0.45) rotate(-14deg);
  }
  70% {
    transform: scale(1.12) rotate(0deg);
  }
  100% {
    opacity: 1;
    transform: scale(1) rotate(0deg);
  }
}

@keyframes checkmark-draw {
  to {
    stroke-dashoffset: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
  .offline-banner-icon--pulse,
  .offline-banner-icon--restored,
  .offline-banner-check-mark {
    animation: none;
    opacity: 1;
    transform: none;
    stroke-dashoffset: 0;
  }
}

.online-restored-banner {
  background: rgba(16, 185, 129, 0.95);
  box-shadow: 0 4px 12px rgba(16, 185, 129, 0.15);
}

/* Slide down transition */
.slide-down-enter-active,
.slide-down-leave-active {
  transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.4s cubic-bezier(0.16, 1, 0.3, 1);
}

.slide-down-enter-from,
.slide-down-leave-to {
  transform: translateY(-100%);
  opacity: 0;
}

.slide-down-enter-to,
.slide-down-leave-from {
  transform: translateY(0);
  opacity: 1;
}

</style>
