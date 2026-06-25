<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch, nextTick } from 'vue'
import { Notivue, Notifications, push, darkTheme, lightTheme } from 'notivue'
import { FilterMatchMode, FilterService } from '@primevue/core/api'
import DataTable, { type DataTableFilterEvent } from 'primevue/datatable'
import Column from 'primevue/column'
import Select from 'primevue/select'
import AppBrand from './components/AppBrand.vue'
import ConfirmModal from './components/ConfirmModal.vue'
import { API_BASE, apiUrl } from './services/api'
import forbiddenHtml from '../public/403.html?raw'
import unauthorizedHtml from '../public/401.html?raw'
import { createConnectivityMonitor, type ConnectivityMonitor } from './connectivityMonitor'
import Cap from 'cap-widget'
import './App.css'
import ApexCharts from 'apexcharts'

// --- Cap CAPTCHA system ---
const CAP_SITE_KEY = import.meta.env.VITE_CAP_SITE_KEY || 'f31d5d6959'

let activeCapToken: string | null = sessionStorage.getItem('og_cap_token')
let capTokenExpiresAt = parseInt(sessionStorage.getItem('og_cap_token_expires') || '0', 10)

function clearCapCache() {
  activeCapToken = null
  capTokenExpiresAt = 0
  sessionStorage.removeItem('og_cap_token')
  sessionStorage.removeItem('og_cap_token_expires')
}

async function injectCapHeaders(headers: Record<string, string>, endpoint: string): Promise<void> {
  const now = Date.now()
  if (activeCapToken && now < capTokenExpiresAt - 60000) {
    headers['X-Cap-Token'] = activeCapToken
    return
  }

  try {
    const capInstance = new Cap({
      apiEndpoint: `${window.location.protocol}//cap.${window.location.host}/${CAP_SITE_KEY}/`
    })
    const solution = await capInstance.solve()
    if (!solution || !solution.token) {
      throw new Error('Cap challenge could not be solved')
    }

    activeCapToken = solution.token
    // Set local cache expiration to 15 minutes
    const expiresAt = now + 15 * 60 * 1000
    capTokenExpiresAt = expiresAt
    sessionStorage.setItem('og_cap_token', solution.token)
    sessionStorage.setItem('og_cap_token_expires', String(expiresAt))

    headers['X-Cap-Payload'] = solution.token
  } catch (err) {
    console.error('Cap solver error:', err)
    throw err
  }
}

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
const onAdminRoute = ref(false)
const adminBootstrapLoading = ref(false)
const adminBootstrapFailed = ref(false)
const authConfig = ref<{ enabled: boolean; authority: string; clientId: string; redirectUri?: string } | null>(null)
const OAUTH_REDIRECT_URI_KEY = 'oauth_redirect_uri'
const OAUTH_STATE_KEY = 'oauth_state'
let adminSessionCheckInterval: ReturnType<typeof setInterval> | null = null
let adminSessionCheckInFlight = false

function isAdminPath(): boolean {
  const path = window.location.pathname
  return path === '/admin' || path === '/admin/'
}

function createOAuthState(): string {
  const value = window.crypto?.randomUUID?.()
    ?? `st_${Math.random().toString(36).slice(2)}_${Date.now()}`
  sessionStorage.setItem(OAUTH_STATE_KEY, value)
  return value
}

function consumeOAuthState(received: string | null): boolean {
  const expected = sessionStorage.getItem(OAUTH_STATE_KEY)
  sessionStorage.removeItem(OAUTH_STATE_KEY)
  return !!received && !!expected && received === expected
}

function isOAuthCallbackPending(): boolean {
  const params = new URLSearchParams(window.location.search)
  const code = params.get('code')
  const state = params.get('state')
  if (!code || !state) return false
  const expected = sessionStorage.getItem(OAUTH_STATE_KEY)
  return !!expected && state === expected
}

/** Завершает админ-сессию и возвращает на главную без автоматического OAuth (ломает цикл SSO). */
async function exitAdminAfterSessionLoss(message: string) {
  await clearAdminSession()
  if (isAdminPath()) {
    window.history.replaceState({}, document.title, '/')
  }
  activeTab.value = 'diagnostics'
  showNotification(message, 'warning')
}

function replaceDocumentWithHtml(html: string) {
  document.open('text/html', 'replace')
  document.write(html)
  document.close()
}

function stopAdminSessionPolling() {
  if (adminSessionCheckInterval) {
    clearInterval(adminSessionCheckInterval)
    adminSessionCheckInterval = null
  }
}

function showForbiddenPage() {
  isAdmin.value = false
  onAdminRoute.value = false
  stopAdminSessionPolling()
  replaceDocumentWithHtml(forbiddenHtml)
}

async function showUnauthorizedPage() {
  isAdmin.value = false
  onAdminRoute.value = false
  stopAdminSessionPolling()
  await clearAdminSession()
  replaceDocumentWithHtml(unauthorizedHtml)
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

async function copyDiagnosticId(id: string) {
  if (!id) return
  try {
    await navigator.clipboard.writeText(id)
    showNotification('ID диагностики скопирован', 'success')
  } catch {
    showNotification('Не удалось скопировать ID диагностики', 'error')
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
const tableFilterOptions = ref({
  dates: [] as string[],
  diagnosticIds: [] as string[],
  sessionIds: [] as string[],
  complaints: [] as string[],
  symptoms: [] as string[],
  diseases: [] as string[],
})

function createDefaultHistoryTableFilters() {
  return {
    timestamp: { value: null as string | null, matchMode: 'historyTimestampContains' },
    id: { value: null as string | null, matchMode: FilterMatchMode.CONTAINS },
    sessionId: { value: null as string | null, matchMode: FilterMatchMode.CONTAINS },
    complaintText: { value: null as string | null, matchMode: FilterMatchMode.CONTAINS },
    detectedSymptoms: { value: null as string | null, matchMode: 'historySymptomContains' },
    results: { value: null as string | null, matchMode: 'historyDiseaseContains' },
  }
}

const historyTableFilters = ref(createDefaultHistoryTableFilters())
const filteredAdminHistoryCount = ref(0)
const selectedHistoryRecords = ref<SessionHistoryRecord[]>([])

// --- Analytics Dashboard State & Logic ---
const showAnalytics = ref(false)
const showMobileFilters = ref(false)
const filteredHistoryRecords = ref<SessionHistoryRecord[]>([])

const avgMatchPercentage = computed(() => {
  const recs = filteredHistoryRecords.value
  if (recs.length === 0) return 0
  let sum = 0
  let count = 0
  recs.forEach(r => {
    if (r.results && r.results.length > 0) {
      const topResults = r.results.slice(0, 5)
      const primary = [...topResults].sort((a, b) => (b.matchPercentage || 0) - (a.matchPercentage || 0))[0]
      if (primary) {
        sum += primary.matchPercentage || 0
        count++
      }
    }
  })
  return count > 0 ? Math.round(sum / count) : 0
})

const avgSymptomsCount = computed(() => {
  const recs = filteredHistoryRecords.value
  if (recs.length === 0) return '0'
  const sum = recs.reduce((acc, r) => acc + (r.detectedSymptoms?.length || 0), 0)
  return (sum / recs.length).toFixed(1)
})

const criticalThreatsCount = computed(() => {
  return filteredHistoryRecords.value.filter(r => 
    r.results?.slice(0, 5).some(res => (res.threatLevel || 0) === 3)
  ).length
})

let threatChartInstance: any = null
let diagnosesChartInstance: any = null
let symptomsChartInstance: any = null
let activityChartInstance: any = null

function destroyCharts() {
  if (threatChartInstance) {
    threatChartInstance.destroy()
    threatChartInstance = null
  }
  if (diagnosesChartInstance) {
    diagnosesChartInstance.destroy()
    diagnosesChartInstance = null
  }
  if (symptomsChartInstance) {
    symptomsChartInstance.destroy()
    symptomsChartInstance = null
  }
  if (activityChartInstance) {
    activityChartInstance.destroy()
    activityChartInstance = null
  }
}

async function renderCharts() {
  destroyCharts()
  
  const records = filteredHistoryRecords.value
  if (!records || records.length === 0) return
  
  const isDarkTheme = isDark.value
  const themeMode: 'light' | 'dark' = isDarkTheme ? 'dark' : 'light'
  
  // Russian localization configuration for ApexCharts
  const ruLocale = {
    name: 'ru',
    options: {
      months: ['Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь'],
      shortMonths: ['Янв', 'Фев', 'Мар', 'Апр', 'Май', 'Июн', 'Июл', 'Авг', 'Сен', 'Окт', 'Ноя', 'Дек'],
      days: ['Воскресенье', 'Понедельник', 'Вторник', 'Среда', 'Четверг', 'Пятница', 'Суббота'],
      shortDays: ['Вс', 'Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб'],
      toolbar: {
        download: 'Скачать SVG',
        selection: 'Выбор',
        selectionZoom: 'Масштаб выбора',
        zoomIn: 'Приблизить',
        zoomOut: 'Отдалить',
        pan: 'Панорамирование',
        reset: 'Сбросить масштаб'
      }
    }
  }

  // Element selectors
  const elThreat = document.getElementById('chart-threat')
  const elDiagnoses = document.getElementById('chart-diagnoses')
  const elSymptoms = document.getElementById('chart-symptoms')
  const elActivity = document.getElementById('chart-activity')
  
  if (!elThreat || !elDiagnoses || !elSymptoms || !elActivity) return
  
  const fontStack = "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"

  // 1. Threat Levels (donut)
  const threatCounts = [0, 0, 0, 0] as number[] // 0: Нет угрозы, 1: Низкий, 2: Средний, 3: Критический
  records.forEach(r => {
    let maxLvl = 0
    if (r.results && r.results.length > 0) {
      maxLvl = Math.max(...r.results.slice(0, 5).map(res => res.threatLevel || 0))
    }
    if (maxLvl >= 0 && maxLvl <= 3) {
      threatCounts[maxLvl] = (threatCounts[maxLvl] ?? 0) + 1
    }
  })
  
  const threatOptions = {
    chart: {
      type: 'donut' as const,
      height: 280,
      background: 'transparent',
      foreColor: 'var(--text-muted)',
      fontFamily: fontStack,
      toolbar: { show: false },
      locales: [ruLocale],
      defaultLocale: 'ru'
    },
    series: threatCounts,
    labels: ['Нет угрозы', 'Низкий', 'Средний', 'Критический'],
    colors: ['#10b981', '#3b82f6', '#f59e0b', '#ef4444'],
    theme: { mode: themeMode },
    stroke: {
      show: true,
      width: 2,
      colors: ['var(--bg-card)']
    },
    dataLabels: {
      enabled: true,
      formatter: function(val: number) {
        return val.toFixed(0) + '%'
      }
    },
    legend: {
      position: 'bottom' as const,
      horizontalAlign: 'center' as const,
      fontSize: '11px',
      markers: { strokeWidth: 0 },
      itemMargin: { horizontal: 8, vertical: 4 }
    },
    tooltip: {
      y: {
        formatter: function(val: number) {
          return `${val} сессий`
        }
      }
    },
    plotOptions: {
      pie: {
        donut: {
          size: '65%',
          labels: {
            show: true,
            total: {
              show: true,
              label: 'Всего сессий',
              color: 'var(--text-muted)',
              formatter: function(w: any) {
                return w.globals.seriesTotals.reduce((a: number, b: number) => a + b, 0)
              }
            }
          }
        }
      }
    }
  }
  
  threatChartInstance = new ApexCharts(elThreat, threatOptions)
  threatChartInstance.render()
  
  // 2. Top Diagnoses (horizontal bar)
  const diagCounts: Record<string, number> = {}
  records.forEach(r => {
    if (r.results && r.results.length > 0) {
      const topResults = r.results.slice(0, 5)
      const primary = [...topResults].sort((a, b) => (b.matchPercentage || 0) - (a.matchPercentage || 0))[0]
      if (primary && primary.disease) {
        diagCounts[primary.disease] = (diagCounts[primary.disease] || 0) + 1
      }
    } else {
      diagCounts['Нет патологии'] = (diagCounts['Нет патологии'] || 0) + 1
    }
  })
  
  const sortedDiags = Object.entries(diagCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    
  const diagLabels = sortedDiags.map(d => d[0])
  const diagValues = sortedDiags.map(d => d[1])
  
  const diagOptions = {
    chart: {
      type: 'bar' as const,
      height: 280,
      background: 'transparent',
      foreColor: 'var(--text-muted)',
      fontFamily: fontStack,
      toolbar: { show: false },
      locales: [ruLocale],
      defaultLocale: 'ru'
    },
    plotOptions: {
      bar: {
        horizontal: true,
        barHeight: '55%',
        borderRadius: 4
      }
    },
    colors: ['#0284c7'],
    series: [{
      name: 'Сессий',
      data: diagValues
    }],
    xaxis: {
      categories: diagLabels,
      labels: {
        show: true,
        style: { fontSize: '10px' },
        formatter: function(val: number) {
          return val % 1 === 0 ? val.toFixed(0) : '';
        }
      },
      axisBorder: { show: false },
      axisTicks: { show: false }
    },
    yaxis: {
      labels: {
        show: true,
        style: { fontSize: '10px', fontWeight: 500 },
        maxWidth: 160
      }
    },
    grid: {
      borderColor: 'var(--border-color)',
      xaxis: { lines: { show: true } },
      yaxis: { lines: { show: false } }
    },
    theme: { mode: themeMode },
    dataLabels: {
      enabled: true,
      textAnchor: 'start' as const,
      style: {
        colors: ['#fff'],
        fontSize: '10px',
        fontWeight: 600
      },
      offsetX: 8
    },
    tooltip: {
      y: {
        formatter: function(val: number) {
          return `${val} сессий`
        }
      }
    }
  }
  
  diagnosesChartInstance = new ApexCharts(elDiagnoses, diagOptions)
  diagnosesChartInstance.render()
  
  // 3. Process Top Symptoms (vertical column)
  const symCounts: Record<string, number> = {}
  records.forEach(r => {
    if (r.detectedSymptoms) {
      r.detectedSymptoms.forEach(s => {
        symCounts[s] = (symCounts[s] || 0) + 1
      })
    }
  })
  
  const sortedSyms = Object.entries(symCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    
  const symLabels = sortedSyms.map(s => s[0])
  const symValues = sortedSyms.map(s => s[1])
  
  const symOptions = {
    chart: {
      type: 'bar' as const,
      height: 280,
      background: 'transparent',
      foreColor: 'var(--text-muted)',
      fontFamily: fontStack,
      toolbar: { show: false },
      locales: [ruLocale],
      defaultLocale: 'ru'
    },
    plotOptions: {
      bar: {
        horizontal: false,
        columnWidth: '45%',
        borderRadius: 4
      }
    },
    colors: ['#8b5cf6'],
    series: [{
      name: 'Случаев',
      data: symValues
    }],
    xaxis: {
      categories: symLabels,
      labels: {
        show: true,
        style: { fontSize: '9px' },
        trim: true,
        hideOverlappingLabels: true
      },
      axisBorder: { show: false },
      axisTicks: { show: false }
    },
    yaxis: {
      labels: {
        show: true,
        style: { fontSize: '10px' },
        formatter: function(val: number) {
          return val % 1 === 0 ? val.toFixed(0) : '';
        }
      }
    },
    grid: {
      borderColor: 'var(--border-color)',
      xaxis: { lines: { show: false } },
      yaxis: { lines: { show: true } }
    },
    theme: { mode: themeMode },
    dataLabels: {
      enabled: true,
      style: {
        colors: ['var(--text-main)'],
        fontSize: '10px',
        fontWeight: 600
      },
      offsetY: -18
    },
    tooltip: {
      y: {
        formatter: function(val: number) {
          return `${val} раз(а)`
        }
      }
    }
  }
  
  symptomsChartInstance = new ApexCharts(elSymptoms, symOptions)
  symptomsChartInstance.render()
  
  // 4. Process Diagnostic Activity Over Time (datetime area chart)
  const dateCounts: Record<string, number> = {}
  records.forEach(r => {
    const d = new Date(r.timestamp)
    if (!isNaN(d.getTime())) {
      const year = d.getFullYear()
      const month = String(d.getMonth() + 1).padStart(2, '0')
      const day = String(d.getDate()).padStart(2, '0')
      const dateStr = `${year}-${month}-${day}`
      dateCounts[dateStr] = (dateCounts[dateStr] || 0) + 1
    }
  })
  
  const sortedDates = Object.entries(dateCounts)
    .sort((a, b) => new Date(a[0]).getTime() - new Date(b[0]).getTime())
    
  const seriesData = sortedDates.map(item => {
    const parts = item[0].split('-').map(Number)
    const year = parts[0] ?? 0
    const month = parts[1] ?? 1
    const day = parts[2] ?? 1
    const localTimestamp = new Date(year, month - 1, day).getTime()
    return [localTimestamp, item[1]]
  })
  
  const activityOptions = {
    chart: {
      type: 'area' as const,
      height: 280,
      background: 'transparent',
      foreColor: 'var(--text-muted)',
      fontFamily: fontStack,
      toolbar: { show: false },
      zoom: { enabled: false },
      locales: [ruLocale],
      defaultLocale: 'ru'
    },
    dataLabels: { enabled: false },
    stroke: {
      curve: 'smooth' as const,
      width: 3,
      colors: ['#0284c7']
    },
    fill: {
      type: 'gradient',
      gradient: {
        shadeIntensity: 1,
        opacityFrom: 0.35,
        opacityTo: 0.05,
        stops: [0, 100],
        colorStops: [
          { offset: 0, color: '#0284c7', opacity: 0.35 },
          { offset: 100, color: '#0284c7', opacity: 0.05 }
        ]
      }
    },
    series: [{
      name: 'Сессий диагностики',
      data: seriesData
    }],
    xaxis: {
      type: 'datetime' as const,
      labels: {
        datetimeUTC: false,
        style: { fontSize: '9px' }
      },
      axisBorder: { show: false },
      axisTicks: { show: false }
    },
    yaxis: {
      labels: {
        show: true,
        style: { fontSize: '10px' },
        formatter: function(val: number) {
          return val % 1 === 0 ? val.toFixed(0) : '';
        }
      },
      min: 0,
      forceNiceScale: true
    },
    grid: {
      borderColor: 'var(--border-color)',
      xaxis: { lines: { show: false } },
      yaxis: { lines: { show: true } }
    },
    theme: { mode: themeMode },
    tooltip: {
      x: { format: 'dd.MM.yyyy' },
      y: {
        formatter: function(val: number) {
          return `${val} сессий`
        }
      }
    }
  }
  
  activityChartInstance = new ApexCharts(elActivity, activityOptions)
  activityChartInstance.render()
}

watch([showAnalytics, filteredHistoryRecords, isDark], async () => {
  if (showAnalytics.value) {
    await nextTick()
    renderCharts()
  } else {
    destroyCharts()
  }
}, { deep: true })

onUnmounted(() => {
  destroyCharts()
})

// Watch both filter configurations and underlying history data to sync results across devices
watch([historyTableFilters, adminHistory], () => {
  const filters = historyTableFilters.value
  let result = [...adminHistory.value]
  
  if (filters.timestamp?.value) {
    const val = filters.timestamp.value.toLowerCase()
    result = result.filter(r => {
      if (!r.timestamp) return false
      return formatDate(r.timestamp).toLowerCase().includes(val) || r.timestamp.toLowerCase().includes(val)
    })
  }
  
  if (filters.id?.value) {
    const val = filters.id.value.toLowerCase()
    result = result.filter(r => r.id?.toLowerCase().includes(val))
  }
  
  if (filters.sessionId?.value) {
    const val = filters.sessionId.value.toLowerCase()
    result = result.filter(r => r.sessionId?.toLowerCase().includes(val))
  }
  
  if (filters.complaintText?.value) {
    const val = filters.complaintText.value.toLowerCase()
    result = result.filter(r => r.complaintText?.toLowerCase().includes(val))
  }
  
  if (filters.detectedSymptoms?.value) {
    const val = filters.detectedSymptoms.value.toLowerCase()
    result = result.filter(r => 
      Array.isArray(r.detectedSymptoms) && r.detectedSymptoms.some(s => s.toLowerCase().includes(val))
    )
  }
  
  if (filters.results?.value) {
    const val = filters.results.value.toLowerCase()
    result = result.filter(r => 
      Array.isArray(r.results) && r.results.slice(0, 5).some(res => res.disease.toLowerCase().includes(val))
    )
  }
  
  filteredHistoryRecords.value = result
  filteredAdminHistoryCount.value = result.length
}, { deep: true, immediate: true })

const expandedHistoryDiseases = ref<Record<string, boolean>>({})
const loadedRecordId = ref<string | null>(null)
function toggleHistoryDiseaseExpand(recordId: string, diseaseName: string) {
  const key = `${recordId}_${diseaseName}`
  expandedHistoryDiseases.value[key] = !expandedHistoryDiseases.value[key]
}

function clearHistoryTableFilters() {
  historyTableFilters.value = createDefaultHistoryTableFilters()
}

function rebuildTableFilterOptions(records: SessionHistoryRecord[]) {
  tableFilterOptions.value = {
    dates: [...new Set(records.map(record => record.timestamp).filter(Boolean))]
      .sort((left, right) => new Date(right).getTime() - new Date(left).getTime()),
    diagnosticIds: [...new Set(records.map(record => record.id).filter(Boolean))].sort(),
    sessionIds: [...new Set(records.map(record => record.sessionId).filter((id): id is string => Boolean(id)))].sort(),
    complaints: [...new Set(records.map(record => record.complaintText).filter(Boolean))].sort(),
    symptoms: [...new Set(records.flatMap(record => record.detectedSymptoms || []).filter(Boolean))].sort(),
    diseases: [...new Set(records.flatMap(record => record.results?.map(result => result.disease) || []).filter(Boolean))].sort(),
  }
}

function truncateFilterLabel(text: string, maxLength = 72) {
  if (text.length <= maxLength) return text
  return `${text.slice(0, maxLength)}…`
}

function onHistoryTableFilter(event: DataTableFilterEvent) {
  filteredHistoryRecords.value = Array.isArray(event.filteredValue)
    ? event.filteredValue
    : [...adminHistory.value]
  filteredAdminHistoryCount.value = filteredHistoryRecords.value.length
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
      ? `https://auth.${currentHost}/application/o/ophthalmoguide/` 
      : `http://auth.${currentHost}/application/o/ophthalmoguide/`,
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

type AdminSessionStatus = 'ok' | 'unauthorized' | 'forbidden' | 'error'

let isRefreshingPromise: Promise<boolean> | null = null

async function refreshAdminToken(): Promise<boolean> {
  if (isRefreshingPromise) {
    return isRefreshingPromise
  }

  isRefreshingPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({}),
      })
      return res.ok
    } catch (e) {
      console.error('[OIDC] Failed to refresh token:', e)
      return false
    }
  })()

  try {
    return await isRefreshingPromise
  } finally {
    isRefreshingPromise = null
  }
}

async function resolveAdminSession(): Promise<AdminSessionStatus> {
  try {
    const fetchSession = () => fetch(`${API_BASE}/admin/session`, { credentials: 'include' })
    let res = await fetchSession()
    if (res.status === 401) {
      const refreshed = await refreshAdminToken()
      if (!refreshed) return 'unauthorized'
      res = await fetchSession()
    }
    if (res.ok) return 'ok'
    if (res.status === 403) return 'forbidden'
    if (res.status === 401) return 'unauthorized'
    return 'error'
  } catch {
    return 'error'
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
      state: createOAuthState(),
    })
    window.location.assign(`${authorityBase}/application/o/authorize/?${params.toString()}`)
  }
}

function resetAdminUIState() {
  isAdmin.value = false
  adminBootstrapLoading.value = false
  adminBootstrapFailed.value = false
}

async function clearAdminSession() {
  resetAdminUIState()
  try {
    await fetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
  } catch {
    // best-effort cookie cleanup on the server
  }
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
    sessionStorage.removeItem(OAUTH_STATE_KEY)
    return
  }

  const code = urlParams.get('code')
  const state = urlParams.get('state')

  if (!code) return

  if (!consumeOAuthState(state)) {
    showNotification('Не удалось войти. Попробуйте ещё раз.', 'error')
    window.history.replaceState({}, document.title, window.location.pathname)
    return
  }

  try {
    const redirectUri = sessionStorage.getItem(OAUTH_REDIRECT_URI_KEY) || getOAuthRedirectUri()
    const res = await fetch(`${API_BASE}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ code, redirectUri })
    })
    if (res.ok) {
      sessionStorage.removeItem(OAUTH_REDIRECT_URI_KEY)
      window.location.replace(`${window.location.origin}/admin/`)
      return
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

  try {
    await fetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
  } catch {
    // logout notification to backend is best-effort
  }

  resetAdminUIState()
  sessionStorage.removeItem(OAUTH_REDIRECT_URI_KEY)
  sessionStorage.removeItem(OAUTH_STATE_KEY)
  sessionStorage.setItem('logged_out_notification', 'true')
  window.location.href = '/'
}

/** Лёгкая проверка сессии без перезагрузки базы знаний и без сброса UI. */
async function validateAdminSessionOnly() {
  if (!isAdmin.value || !isAdminPath() || isOAuthCallbackPending()) return

  const status = await resolveAdminSession()
  if (status === 'ok') return
  if (status === 'forbidden') {
    showForbiddenPage()
  } else if (status === 'unauthorized') {
    await showUnauthorizedPage()
  } else {
    void exitAdminAfterSessionLoss('Сессия истекла – авторизуйтесь повторно')
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

      if (code) {
        onAdminRoute.value = true
        return // handleAuthentikCallback обрабатывает OAuth callback
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

      let sessionStatus: AdminSessionStatus = 'error'
      try {
        adminBootstrapLoading.value = true
        sessionStatus = await resolveAdminSession()
      } catch {
        onAdminRoute.value = true
        adminBootstrapFailed.value = true
        return
      } finally {
        adminBootstrapLoading.value = false
      }

      if (sessionStatus !== 'ok') {
        onAdminRoute.value = true
        if (sessionStatus === 'forbidden') {
          showForbiddenPage()
        } else if (sessionStatus === 'unauthorized') {
          await showUnauthorizedPage()
        } else {
          void exitAdminAfterSessionLoss('Сессия истекла – авторизуйтесь повторно')
        }
        return
      }

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
      adminBootstrapFailed.value = false
      adminBootstrapLoading.value = false
      activeTab.value = 'diagnostics'
      onAdminRoute.value = false
    }
  } finally {
    adminSessionCheckInFlight = false
  }
}
// Вспомогательная функция для генерации безопасного ID с многоуровневым фолбеком
function generateSecureId(): string {
  if (typeof window !== 'undefined' && window.crypto) {
    // 1. Современный и быстрый стандарт
    if (typeof window.crypto.randomUUID === 'function') {
      return window.crypto.randomUUID();
    }
    
    // 2. Безопасный фолбек для старых браузеров (поддерживается с 2013-2015 годов)
    if (typeof window.crypto.getRandomValues === 'function') {
      const typedArray = new Uint32Array(4);
      window.crypto.getRandomValues(typedArray);
      // Преобразуем массив случайных чисел в строку в 36-ричной системе
      return Array.from(typedArray).map(val => val.toString(36)).join('-');
    }
  }

  // 3. Самый крайний случай – математический фолбек с использованием микросекунд (performance.now) для минимизации коллизий
  const timePart = typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? Math.floor(performance.now()).toString(36)
    : '';
  return Math.random().toString(36).substring(2, 15) + '_' + Date.now().toString(36) + timePart;
}

function initSession() {
  let id = localStorage.getItem('og_session_id')
  if (!id) {
    id = 'sess_' + generateSecureId()
    localStorage.setItem('og_session_id', id)
  }
  sessionId.value = id
}

// Global API Fetch helper with headers
async function apiFetch(endpoint: string, options: Omit<RequestInit, 'body'> & { body?: any } = {}) {
  const useAdminCredentials = isAdmin.value || isAdminPath()

  const headers: Record<string, string> = {
    'Session-Id': sessionId.value,
    ...(options.headers as Record<string, string> || {})
  }

  const heavyEndpoints = ['/analyze', '/speech/recognize', '/speech/synthesize', '/history']
  if (heavyEndpoints.includes(endpoint)) {
    try {
      await injectCapHeaders(headers, endpoint)
    } catch (err) {
      console.error('Failed to inject Cap headers:', err)
      if (endpoint !== '/history') {
        showNotification('Не удалось запустить проверку безопасности. Проверьте соединение с сервером.', 'error')
      }
      throw new Error('cap_solve_failed')
    }
  }

  let fetchBody: any = options.body
  if (fetchBody && !(fetchBody instanceof Blob) && !(fetchBody instanceof FormData) && typeof fetchBody === 'object') {
    fetchBody = JSON.stringify(fetchBody)
    headers['Content-Type'] = 'application/json'
  }

  const doFetch = () => fetch(apiUrl(endpoint), {
    ...options,
    body: fetchBody,
    headers,
    credentials: useAdminCredentials ? 'include' : options.credentials,
  })

  let response = await doFetch()

  // Transparent self-healing / auto-retry: if the 15-minute session expired or was revoked for rate limits,
  // clear local cache, generate a fresh challenge solution, and retry the request.
  if (response.status === 400 && heavyEndpoints.includes(endpoint)) {
    try {
      const errJson = await response.clone().json()
      if (errJson && (errJson.code === 'cap_failed' || errJson.code === 'cap_required' || errJson.code === 'cap_invalid' || errJson.code === 'cap_used')) {
        clearCapCache()
        delete headers['X-Cap-Token']
        await injectCapHeaders(headers, endpoint)
        response = await doFetch()
      }
    } catch (err) {
      console.error('Cap auto-retry failed:', err)
    }
  }

  if (response.status === 401 && useAdminCredentials) {
    const refreshed = await refreshAdminToken()
    if (refreshed) {
      response = await doFetch()
    }
  }

  if (!response.ok) {
    if (response.status === 400) {
      try {
        const errJson = await response.clone().json()
        if (errJson && (errJson.code === 'cap_failed' || errJson.code === 'cap_required' || errJson.code === 'cap_invalid' || errJson.code === 'cap_used')) {
          clearCapCache()
          showNotification('Не удалось пройти фоновую проверку безопасности (защита от спама). Пожалуйста, повторите попытку.', 'error')
        }
      } catch {}
    }
    if (response.status === 401 && (isAdmin.value || isAdminPath())) {
      void showUnauthorizedPage()
    } else if (response.status === 403 && (isAdmin.value || isAdminPath())) {
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
    const res = await apiFetch('/history')
    history.value = await res.json()
  } catch {
    // history is optional for diagnostics UI
  } finally {
    loadingHistory.value = false
  }
}

async function loadAdminHistory() {
  loadingHistory.value = true
  selectedHistoryRecords.value = []
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
    const res = await apiFetch(`/admin/history${query ? `?${query}` : ''}`)
    adminHistory.value = await res.json()
    rebuildTableFilterOptions(adminHistory.value)
    clearHistoryTableFilters()
    filteredHistoryRecords.value = [...adminHistory.value]
    filteredAdminHistoryCount.value = adminHistory.value.length
    selectedHistoryRecords.value = []
  } catch {
    adminHistory.value = []
    rebuildTableFilterOptions([])
    clearHistoryTableFilters()
    filteredHistoryRecords.value = []
    filteredAdminHistoryCount.value = 0
    selectedHistoryRecords.value = []
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
  if (selectedHistoryRecords.value.length === 0) return
  showConfirm(
    'Удалить выбранные сессии',
    `Вы уверены, что хотите безвозвратно удалить выбранные сессии (${selectedHistoryRecords.value.length})? Действие нельзя отменить.`,
    async () => {
      confirmModal.value.open = false
      try {
        const selectedIds = selectedHistoryRecords.value.map(record => record.id)
        await apiFetch('/admin/history/bulk', { 
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(selectedIds)
        })
        const deletedSet = new Set(selectedIds)
        adminHistory.value = adminHistory.value.filter(r => !deletedSet.has(r.id))
        history.value = history.value.filter(r => !deletedSet.has(r.id))
        rebuildTableFilterOptions(adminHistory.value)
        filteredHistoryRecords.value = filteredHistoryRecords.value.filter(r => !deletedSet.has(r.id))
        selectedHistoryRecords.value = []
        filteredAdminHistoryCount.value = filteredHistoryRecords.value.length
        showNotification('Выбранные записи удалены', 'success')
      } catch (err) {
        showSafeError('Не удалось удалить выбранные записи, попробуйте ещё раз')
      }
    },
    'Удалить'
  )
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
    const res = await apiFetch('/analyze', {
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
    if (err?.name === 'AbortError' || err?.message === 'cap_solve_failed') {
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
    if (!navigator.mediaDevices?.getUserMedia) {
      showNotification('Голосовой ввод недоступен в этом браузере', 'error')
      return
    }

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
  } catch (err: unknown) {
    const error = err as DOMException
    if (error?.name === 'NotAllowedError' || error?.name === 'SecurityError') {
      showNotification('Нет доступа к микрофону – проверьте разрешения в браузере', 'error')
      return
    }
    showNotification('Не удалось начать запись с микрофона', 'error')
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
    const res = await apiFetch('/speech/recognize', {
      method: 'POST',
      headers: {
        'Content-Type': blob.type
      },
      body: blob
    })
    
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
  } catch (err: any) {
    if (err?.message === 'cap_solve_failed') {
      return
    }
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
      const res = await apiFetch('/speech/synthesize', {
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
  } catch (err: any) {
    isSynthesizing.value = false
    if (err?.message === 'cap_solve_failed') {
      return
    }
    // Игнорируем NotAllowedError (блокировка автоплея браузером) и AbortError (прерывание загрузкой, при котором звук часто все равно воспроизводится)
    if (err?.name === 'NotAllowedError' || err?.name === 'AbortError') {
      console.warn('Audio play was prevented or aborted, but may still be playing:', err)
      return
    }
    showSafeError('Не удалось воспроизвести голосовое сообщение')
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

  try {
    await injectCapHeaders(headers, '/report/pdf')
  } catch (err) {
    console.error('Failed to obtain Cap payload for PDF download:', err)
    showNotification('Не удалось запустить проверку безопасности для скачивания PDF.', 'error')
    throw new Error('cap_solve_failed')
  }

  let url = `${API_BASE}/report/pdf`
  const targetId = options.recordId || loadedRecordId.value
  if (targetId) {
    url += `?id=${encodeURIComponent(targetId)}`
  }

  let response = await fetch(url, { method: 'GET', headers })
  if (!response.ok) {
    if (response.status === 400) {
      try {
        const errJson = await response.clone().json()
        if (errJson && (errJson.code === 'cap_failed' || errJson.code === 'cap_required' || errJson.code === 'cap_invalid' || errJson.code === 'cap_used')) {
          clearCapCache()
          delete headers['X-Cap-Token']
          await injectCapHeaders(headers, '/report/pdf')
          response = await fetch(url, { method: 'GET', headers })
        }
      } catch (err) {
        console.error('Cap PDF auto-retry failed:', err)
      }
    }
  }

  if (!response.ok) {
    if (response.status === 400) {
      try {
        const errJson = await response.clone().json()
        if (errJson && (errJson.code === 'cap_failed' || errJson.code === 'cap_required' || errJson.code === 'cap_invalid' || errJson.code === 'cap_used')) {
          clearCapCache()
          showNotification('Не удалось пройти фоновую проверку безопасности (защита от спама). Пожалуйста, повторите попытку.', 'error')
        }
      } catch {}
    }
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
    const symRes = await apiFetch('/symptoms')
    const loadedSymptoms = await symRes.json()
    symptoms.value = loadedSymptoms
    originalSymptoms.value = JSON.parse(JSON.stringify(loadedSymptoms))

    const disRes = await apiFetch('/diseases')
    const loadedDiseases = await disRes.json()
    diseases.value = loadedDiseases.map((d: any) => ({
      name: d.name,
      threatLevel: d.threatLevel ?? 1,
      symptoms: d.symptoms?.length
        ? d.symptoms
        : (d.activeSymptoms || []).map((name: string) => ({ name, redFlag: false }))
    }))
    originalDiseases.value = JSON.parse(JSON.stringify(loadedDiseases))

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
  if (selectedDisease.value && selectedDisease.value.name === disease.name) {
    selectedDisease.value = null
  } else {
    selectedDisease.value = JSON.parse(JSON.stringify(disease))
  }
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
    const res = await apiFetch('/update-data', {
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

const importReport = ref<{
  isValid: boolean
  errors: string[]
  warnings: string[]
  log: string
  dataToApply: { symptoms: string[]; diseases: DiseaseRecord[] } | null
} | null>(null)

async function handleJsonFileImport(event: Event) {
  const input = event.target as HTMLInputElement
  if (!input.files || input.files.length === 0) return

  const file = input.files[0]
  if (!file) return

  // Frontend check for JSON file type
  const isJson = file.type === 'application/json' || file.name.toLowerCase().endsWith('.json')
  if (!isJson) {
    importReport.value = {
      isValid: false,
      errors: ['Неверный формат файла. Разрешены только файлы .json'],
      warnings: [],
      log: 'Ошибка: Выбранный файл не является файлом JSON (.json)',
      dataToApply: null
    }
    showSafeError('Выбранный файл должен иметь формат JSON')
    input.value = ''
    return
  }

  const reader = new FileReader()
  reader.onload = async (e) => {
    try {
      const text = e.target?.result as string
      
      // Call backend validator endpoint
      const res = await apiFetch('/admin/knowledge/validate', {
        method: 'POST',
        body: {
          json: text
        }
      })
      
      const validation = await res.json()
      
      const logLines: string[] = []
      if (validation.errors && validation.errors.length) {
        validation.errors.forEach((err: string) => logLines.push(err))
      }
      if (validation.warnings && validation.warnings.length) {
        validation.warnings.forEach((warn: string) => logLines.push(warn))
      }
      
      let dataToApply = null
      if (validation.isValid) {
        try {
          dataToApply = JSON.parse(text)
        } catch (parseErr: any) {
          validation.isValid = false
          validation.errors = validation.errors || []
          validation.errors.push(`Внутренняя ошибка парсинга: ${parseErr.message}`)
          logLines.push(`Внутренняя ошибка парсинга: ${parseErr.message}`)
        }
      }
      
      importReport.value = {
        isValid: validation.isValid,
        errors: validation.errors || [],
        warnings: validation.warnings || [],
        log: logLines.join("\r\n"),
        dataToApply
      }
      
      if (validation.isValid) {
        showNotification('Файл успешно прошел проверку структуры на сервере', 'success')
      } else {
        showSafeError('Обнаружены ошибки в структуре JSON')
      }
    } catch (err: any) {
      importReport.value = {
        isValid: false,
        errors: [`Сбой при обращении к серверу валидации: ${err?.message || 'Неизвестная ошибка'}`],
        warnings: [],
        log: `Сбой при обращении к серверу валидации: ${err?.message || 'Неизвестная ошибка'}. Убедитесь, что сервер доступен.`,
        dataToApply: null
      }
      showSafeError('Не удалось выполнить проверку файла на сервере')
    } finally {
      input.value = ''
    }
  }
  reader.readAsText(file)
}

function downloadImportValidationLog() {
  if (!importReport.value) return
  const blob = new Blob([importReport.value.log], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'validation_log.txt'
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

function applyImportedData() {
  if (!importReport.value || !importReport.value.dataToApply) return
  
  symptoms.value = [...importReport.value.dataToApply.symptoms]
  diseases.value = JSON.parse(JSON.stringify(importReport.value.dataToApply.diseases))
  
  selectedDisease.value = null
  importReport.value = null
  showNotification('Данные импортированы. Не забудьте сохранить изменения', 'info')
}

function exportKnowledgeToJsonFile() {
  const data = {
    symptoms: symptoms.value,
    diseases: diseases.value
  }
  const jsonString = JSON.stringify(data, null, 2)
  const blob = new Blob([jsonString], { type: 'application/json;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'ophthalmology_knowledge.json'
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
  showNotification('Начало загрузки файла базы знаний', 'success')
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

const historyDateFilterOptions = computed(() =>
  tableFilterOptions.value.dates.map(timestamp => ({
    label: formatDate(timestamp),
    value: timestamp,
  }))
)

const historyComplaintFilterOptions = computed(() =>
  tableFilterOptions.value.complaints.map(complaint => ({
    label: truncateFilterLabel(complaint),
    value: complaint,
  }))
)

const isDateFilterDisabled = computed(() => !historyDateFilterOptions.value || historyDateFilterOptions.value.length === 0)
const isDiagnosticIdFilterDisabled = computed(() => !tableFilterOptions.value.diagnosticIds || tableFilterOptions.value.diagnosticIds.length === 0)
const isSessionIdFilterDisabled = computed(() => !tableFilterOptions.value.sessionIds || tableFilterOptions.value.sessionIds.length === 0)
const isDiseaseFilterDisabled = computed(() => !tableFilterOptions.value.diseases || tableFilterOptions.value.diseases.length === 0)
const isSymptomFilterDisabled = computed(() => !tableFilterOptions.value.symptoms || tableFilterOptions.value.symptoms.length === 0)
const isComplaintFilterDisabled = computed(() => !historyComplaintFilterOptions.value || historyComplaintFilterOptions.value.length === 0)

const hasActiveHistoryTableFilters = computed(() => {
  const filters = historyTableFilters.value
  return Boolean(
    filters.timestamp.value ||
    filters.id.value ||
    filters.sessionId.value ||
    filters.complaintText.value ||
    filters.detectedSymptoms.value ||
    filters.results.value
  )
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

function ensureMicrophonePermissionsPolicy() {
  const policy = 'microphone=(self)'
  let meta = document.querySelector('meta[http-equiv="Permissions-Policy"]') as HTMLMetaElement | null
  if (!meta) {
    meta = document.createElement('meta')
    meta.httpEquiv = 'Permissions-Policy'
    document.head.appendChild(meta)
  }
  meta.content = policy
}

onMounted(async () => {
  FilterService.register('historyTimestampContains', (value: string | null | undefined, filter: string | null) => {
    if (filter == null || filter === '') return true
    if (!value) return false
    const needle = filter.toLowerCase()
    return formatDate(value).toLowerCase().includes(needle) || value.toLowerCase().includes(needle)
  })
  FilterService.register('historySymptomContains', (value: string[] | undefined, filter: string | null) => {
    if (filter == null || filter === '') return true
    const needle = filter.toLowerCase()
    return Array.isArray(value) && value.some(symptom => symptom.toLowerCase().includes(needle))
  })
  FilterService.register('historyDiseaseContains', (value: DiseaseMatch[] | undefined, filter: string | null) => {
    if (filter == null || filter === '') return true
    const needle = filter.toLowerCase()
    return Array.isArray(value) && value.some(result => result.disease.toLowerCase().includes(needle))
  })

  ensureMicrophonePermissionsPolicy()
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
    <div v-if="!isAdmin" class="admin-entry-corner">
      <a 
        href="/admin/" 
        class="btn-admin-login" 
        aria-label="Открыть панель управления"
        @click="navigateToAdmin"
      >
        <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="3" width="7" height="9" rx="1"></rect>
          <rect x="14" y="3" width="7" height="5" rx="1"></rect>
          <rect x="14" y="12" width="7" height="9" rx="1"></rect>
          <rect x="3" y="16" width="7" height="5" rx="1"></rect>
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


    <!-- Header Block (Only visible to Admin) -->
    <header v-if="isAdmin" class="app-header-premium">
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

      <!-- Mobile: settings / logout only (main tabs move to bottom bar) -->
      <div v-if="isAdmin && authConfig?.enabled" class="app-admin-mobile-actions">
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
      :class="{ 'with-admin-nav': isAdmin }"
    >
      <Transition name="admin-panel-slide" mode="out-in">

        <!-- Tab 1: Centered Diagnostic Form -->
        <section
          v-if="activeTab === 'diagnostics'"
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
              <div class="textarea-field-wrap">
                <textarea 
                  ref="textareaRef"
                  v-model="complaintText" 
                  placeholder="Расскажите, что Вы чувствуете? Например: зуд и жжение век, покраснение, помутнение зрения..."
                  rows="5"
                  :disabled="isAnalyzing"
                  :class="{ 'textarea-with-status': isRecording || speechRecognizing }"
                  @input="resizeTextarea"
                ></textarea>
                <div
                  v-if="isRecording || speechRecognizing"
                  class="textarea-status-overlay"
                  :class="{
                    'status-recording': isRecording,
                    'status-recognizing': !isRecording && speechRecognizing
                  }"
                  aria-live="polite"
                >
                  <span v-if="isRecording">Идет запись...</span>
                  <span v-else>Распознавание...</span>
                </div>
              </div>

              
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

                </div>

                <!-- Clear text button (ONLY the input field).
                     Click the eye logo in the header for full reset (text + analysis result). -->
                <button
                  type="button"
                  class="btn-clean-text"
                  @click="clearComplaintText"
                  :disabled="!complaintText || isAnalyzing"
                  title="Очистить текст жалобы"
                  aria-label="Очистить текст жалобы"
                >
                  <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2.5" fill="none" aria-hidden="true">
                    <line x1="18" y1="6" x2="6" y2="18"></line>
                    <line x1="6" y1="6" x2="18" y2="18"></line>
                  </svg>
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
              
              <div class="cap-protection-badge">
                <svg class="cap-badge-icon" viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="2.5" fill="none">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
                <span>Под защитой <a href="https://trycap.dev/" target="_blank" rel="noopener">Cap</a></span>
              </div>
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
            v-if="history.length > 0" 
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
                      <span class="threat-micro-badge" :class="getThreatColorClass(d.threatLevel)">
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
              <div class="editor-header-row" style="display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem;">
                <div>
                  <h2 style="margin: 0; font-size: 1.25rem; font-weight: 700; color: var(--text-main);">
                    Настройка патологии: <span class="focused-disease-title">{{ selectedDisease.name }}</span>
                  </h2>
                  <p style="margin: 0.25rem 0 0 0; font-size: 0.8rem; color: var(--text-muted);">
                    Свяжите симптомы и настройте уровень угрозы для этой патологии
                  </p>
                </div>
                <button
                  type="button"
                  class="btn-bulk-action"
                  style="padding: 4px 8px; font-size: 0.75rem; height: auto; background: transparent; border-color: var(--border-color); color: var(--text-main); display: inline-flex; align-items: center; gap: 0.25rem;"
                  @click="selectedDisease = null"
                  title="Закрыть редактор патологии"
                >
                  <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="2" fill="none">
                    <line x1="18" y1="6" x2="6" y2="18"></line>
                    <line x1="6" y1="6" x2="18" y2="18"></line>
                  </svg>
                  Свернуть
                </button>
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
          <div v-else class="symptom-editor-card-premium symptom-editor-empty" style="display: flex; flex-direction: column; justify-content: center; gap: 2rem;">
            <div style="text-align: center;">
              <div class="knowledge-empty-icon knowledge-empty-icon--info" aria-hidden="true" style="margin: 0 auto 1rem auto;">
                <svg viewBox="0 0 24 24" width="32" height="32" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M9 18h6"></path>
                  <path d="M10 22h4"></path>
                  <path d="M12 2a7 7 0 0 0-4 12.74V17h8v-2.26A7 7 0 0 0 12 2z"></path>
                </svg>
              </div>
              <h3 class="knowledge-empty-title">Патология не выбрана</h3>
              <p class="knowledge-empty-text">
                Выберите патологию из списка слева, чтобы настроить её симптомы и уровень угрозы, либо воспользуйтесь инструментами обмена данными ниже.
              </p>
            </div>

            <!-- Import/Export Tools Panel -->
            <div class="knowledge-backup-panel" style="width: 100%; max-width: 500px; margin: 0 auto; padding-top: 1.5rem; border-top: 1px solid var(--border-color); display: flex; flex-direction: column; gap: 1.25rem; text-align: left;">
              <h4 style="margin: 0; font-size: 1.05rem; font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 0.5rem;">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                  <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
                  <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
                  <line x1="12" y1="22.08" x2="12" y2="12"></line>
                </svg>
                Обмен базой знаний
              </h4>
              
              <div style="display: flex; gap: 1rem;">
                <button
                  type="button"
                  class="btn-bulk-action"
                  @click="exportKnowledgeToJsonFile"
                  style="flex: 1; display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem; height: 38px; cursor: pointer; background: var(--bg-input); color: var(--text-main); border: 1px solid var(--border-color); font-weight: 600; font-size: 0.8rem;"
                >
                  <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2.5" fill="none">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="7 10 12 15 17 10"></polyline>
                    <line x1="12" y1="15" x2="12" y2="3"></line>
                  </svg>
                  Экспорт в файл
                </button>

                <label
                  class="btn-bulk-action"
                  style="flex: 1; display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem; height: 38px; cursor: pointer; background: var(--bg-input); color: var(--text-main); border: 1px solid var(--border-color); font-weight: 600; font-size: 0.8rem; margin-bottom: 0;"
                >
                  <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2.5" fill="none">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="17 8 12 3 7 8"></polyline>
                    <line x1="12" y1="3" x2="12" y2="15"></line>
                  </svg>
                  Импорт из файла
                  <input
                    type="file"
                    accept=".json"
                    @change="handleJsonFileImport"
                    style="display: none;"
                  />
                </label>
              </div>

              <!-- Validator Report Area -->
              <div v-if="importReport" class="import-validation-report" style="display: flex; flex-direction: column; gap: 0.75rem; padding: 1rem; border-radius: 8px; border: 1px solid;" :style="importReport.isValid ? 'background-color: rgba(16,185,129,0.06); border-color: rgba(16,185,129,0.25);' : 'background-color: rgba(239,68,68,0.06); border-color: rgba(239,68,68,0.25);'">
                
                <!-- SUCCESS CASE -->
                <div v-if="importReport.isValid" style="display: flex; flex-direction: column; gap: 0.75rem;">
                  <div style="display: flex; align-items: center; justify-content: space-between;">
                    <span style="font-weight: 700; font-size: 0.85rem; color: var(--color-green);">
                      Валидация пройдена успешно
                    </span>
                    <button
                      v-if="importReport.log.length"
                      type="button"
                      class="btn-copy-table-diagnostic-id"
                      style="font-size: 0.75rem; padding: 2px 6px; height: auto;"
                      @click="downloadImportValidationLog"
                      title="Скачать лог проверок"
                    >
                      Скачать лог
                    </button>
                  </div>
                  
                  <div v-if="importReport.warnings.length" style="font-size: 0.8rem; color: var(--color-orange); max-height: 100px; overflow-y: auto;">
                    <strong>Предупреждения ({{ importReport.warnings.length }}):</strong>
                    <ul style="margin: 0.25rem 0 0 0; padding-left: 1.25rem; list-style-type: disc;">
                      <li v-for="(warn, wIdx) in importReport.warnings" :key="wIdx">{{ warn }}</li>
                    </ul>
                  </div>

                  <div style="display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 0.25rem;">
                    <button
                      type="button"
                      class="btn-validation-apply"
                      @click="applyImportedData"
                    >
                      Применить и обновить
                    </button>
                    <button
                      type="button"
                      class="btn-validation-close"
                      @click="importReport = null"
                    >
                      Отмена
                    </button>
                  </div>
                </div>

                <!-- ERROR CASE (INVALID JSON) -->
                <div v-else style="display: flex; flex-direction: column; gap: 0.85rem; align-items: center; text-align: center; padding: 0.25rem 0;">
                  <span style="font-weight: 700; font-size: 0.9rem; color: var(--color-red);">
                    Ошибка валидации структуры JSON
                  </span>
                  
                  <textarea
                    v-if="importReport.log"
                    readonly
                    style="width: 100%; height: 120px; font-family: monospace; font-size: 0.75rem; background: var(--bg-input); color: var(--text-main); border: 1px solid var(--border-color); border-radius: 6px; padding: 0.5rem; resize: none; overflow-y: auto; text-align: left;"
                    :value="importReport.log"
                  ></textarea>

                  <button
                    type="button"
                    class="btn-validation-download"
                    @click="downloadImportValidationLog"
                    title="Скачать лог ошибок в текстовом файле"
                  >
                    <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2.5" fill="none">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                      <polyline points="7 10 12 15 17 10"></polyline>
                      <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                    Скачать лог ошибок
                  </button>

                  <button
                    type="button"
                    class="btn-validation-close"
                    style="width: 100%; max-width: 280px; height: 38px;"
                    @click="importReport = null"
                  >
                    Закрыть
                  </button>
                </div>
              </div>
            </div>

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
              <button
                class="btn-analytics-toggle"
                :class="{ active: showAnalytics }"
                @click="showAnalytics = !showAnalytics"
              >
                <svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" stroke-width="2.5" fill="none">
                  <line x1="18" y1="20" x2="18" y2="10"></line>
                  <line x1="12" y1="20" x2="12" y2="4"></line>
                  <line x1="6" y1="20" x2="6" y2="14"></line>
                </svg>
                Аналитика
              </button>
              <button
                class="btn-analytics-toggle mobile-only-btn"
                :class="{ active: showMobileFilters }"
                @click="showMobileFilters = !showMobileFilters"
              >
                <svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" stroke-width="2.5" fill="none">
                  <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon>
                </svg>
                Фильтры
              </button>
              <span class="history-stat-chip">{{ filteredAdminHistoryCount }} из {{ adminHistory.length }} записей</span>
              <button
                class="btn-delete-history"
                @click="deleteSelectedHistory"
                :disabled="loadingHistory || selectedHistoryRecords.length === 0"
              >
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                  <polyline points="3 6 5 6 21 6"></polyline>
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                  <line x1="10" y1="11" x2="10" y2="17"></line>
                  <line x1="14" y1="11" x2="14" y2="17"></line>
                </svg>
                Удалить выбранные ({{ selectedHistoryRecords.length }})
              </button>
            </div>
          </div>

          <!-- Analytics Dashboard -->
          <div v-show="showAnalytics" class="analytics-dashboard-premium">
            <div v-if="filteredHistoryRecords.length === 0" class="analytics-empty-state">
              <svg viewBox="0 0 24 24" width="40" height="40" stroke="currentColor" stroke-width="1.75" fill="none" class="analytics-empty-icon" aria-hidden="true">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
              </svg>
              <span class="analytics-empty-text">Нет данных для отображения аналитики по текущим фильтрам</span>
            </div>

            <div v-else>
              <!-- Stats cards -->
              <div class="analytics-stats-grid">
                <div class="analytics-stat-card">
                  <div class="analytics-stat-icon-wrapper">
                    <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none">
                      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                      <circle cx="9" cy="7" r="4"></circle>
                      <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
                      <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
                    </svg>
                  </div>
                  <div class="analytics-stat-content">
                    <span class="analytics-stat-label">Всего обращений</span>
                    <span class="analytics-stat-value">{{ filteredHistoryRecords.length }}</span>
                  </div>
                </div>
                
                <div class="analytics-stat-card accuracy-green">
                  <div class="analytics-stat-icon-wrapper">
                    <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                      <path d="m9 11 2 2 4-4"></path>
                    </svg>
                  </div>
                  <div class="analytics-stat-content">
                    <span class="analytics-stat-label">Среднее совпадение</span>
                    <span class="analytics-stat-value">{{ avgMatchPercentage }}%</span>
                  </div>
                </div>

                <div class="analytics-stat-card threat-red">
                  <div class="analytics-stat-icon-wrapper">
                    <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
                      <circle cx="12" cy="12" r="10"></circle>
                      <line x1="12" y1="8" x2="12" y2="12"></line>
                      <line x1="12" y1="16" x2="12.01" y2="16"></line>
                    </svg>
                  </div>
                  <div class="analytics-stat-content">
                    <span class="analytics-stat-label">Критические угрозы</span>
                    <span class="analytics-stat-value">{{ criticalThreatsCount }}</span>
                  </div>
                </div>

                <div class="analytics-stat-card symptoms-purple">
                  <div class="analytics-stat-icon-wrapper">
                    <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none">
                      <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                      <line x1="12" y1="11" x2="12" y2="17"></line>
                      <line x1="9" y1="14" x2="15" y2="14"></line>
                    </svg>
                  </div>
                  <div class="analytics-stat-content">
                    <span class="analytics-stat-label">Симптомов на сессию</span>
                    <span class="analytics-stat-value">{{ avgSymptomsCount }}</span>
                  </div>
                </div>
              </div>

              <!-- Charts Grid -->
              <div class="analytics-charts-grid">
                <div class="analytics-chart-container">
                  <div class="analytics-chart-title">
                    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                      <circle cx="12" cy="12" r="10"></circle>
                      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                      <path d="M2 12h20"></path>
                    </svg>
                    Распределение сессий по уровню угрозы
                  </div>
                  <div id="chart-threat" class="analytics-chart-canvas"></div>
                </div>

                <div class="analytics-chart-container">
                  <div class="analytics-chart-title">
                    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                      <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>
                      <line x1="16" y1="2" x2="16" y2="6"></line>
                      <line x1="8" y1="2" x2="8" y2="6"></line>
                      <line x1="3" y1="10" x2="21" y2="10"></line>
                    </svg>
                    Динамика обращений за выбранный период
                  </div>
                  <div id="chart-activity" class="analytics-chart-canvas"></div>
                </div>

                <div class="analytics-chart-container">
                  <div class="analytics-chart-title">
                    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                      <line x1="18" y1="20" x2="18" y2="10"></line>
                      <line x1="12" y1="20" x2="12" y2="4"></line>
                      <line x1="6" y1="20" x2="6" y2="14"></line>
                    </svg>
                    Топ частых предварительных диагнозов
                  </div>
                  <div id="chart-diagnoses" class="analytics-chart-canvas"></div>
                </div>

                <div class="analytics-chart-container">
                  <div class="analytics-chart-title">
                    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                      <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
                    </svg>
                    Топ часто встречающихся симптомов
                  </div>
                  <div id="chart-symptoms" class="analytics-chart-canvas"></div>
                </div>
              </div>
            </div>
          </div>

          <!-- Mobile Filters Panel -->
          <div v-show="showMobileFilters" class="mobile-filters-panel-premium">
            <div class="mobile-filters-header">
              <h4>Фильтрация сессий</h4>
              <button type="button" class="btn-clear-filters-mobile" @click="clearHistoryTableFilters">
                Сбросить
              </button>
            </div>
            
            <div class="mobile-filters-grid">
              <div class="mobile-filter-item">
                <label>Дата и время</label>
                <Select
                  v-model="historyTableFilters.timestamp.value"
                  :options="historyDateFilterOptions"
                  optionLabel="label"
                  optionValue="value"
                  placeholder="Все даты"
                  editable
                  showClear
                  overlay-class="history-filter-select-panel"
                  class="history-filter-select"
                  :disabled="isDateFilterDisabled"
                />
              </div>

              <div class="mobile-filter-item">
                <label>ID диагностики</label>
                <Select
                  v-model="historyTableFilters.id.value"
                  :options="tableFilterOptions.diagnosticIds"
                  placeholder="Все ID"
                  editable
                  showClear
                  overlay-class="history-filter-select-panel"
                  class="history-filter-select"
                  :disabled="isDiagnosticIdFilterDisabled"
                />
              </div>

              <div class="mobile-filter-item">
                <label>ID сессии</label>
                <Select
                  v-model="historyTableFilters.sessionId.value"
                  :options="tableFilterOptions.sessionIds"
                  placeholder="Все сессии"
                  editable
                  showClear
                  overlay-class="history-filter-select-panel"
                  class="history-filter-select"
                  :disabled="isSessionIdFilterDisabled"
                />
              </div>

              <div class="mobile-filter-item">
                <label>Диагноз</label>
                <Select
                  v-model="historyTableFilters.results.value"
                  :options="tableFilterOptions.diseases"
                  placeholder="Все диагнозы"
                  editable
                  showClear
                  overlay-class="history-filter-select-panel"
                  class="history-filter-select"
                  :disabled="isDiseaseFilterDisabled"
                />
              </div>

              <div class="mobile-filter-item">
                <label>Симптом</label>
                <Select
                  v-model="historyTableFilters.detectedSymptoms.value"
                  :options="tableFilterOptions.symptoms"
                  placeholder="Все симптомы"
                  editable
                  showClear
                  overlay-class="history-filter-select-panel"
                  class="history-filter-select"
                  :disabled="isSymptomFilterDisabled"
                />
              </div>

              <div class="mobile-filter-item">
                <label>Жалоба (текст)</label>
                <Select
                  v-model="historyTableFilters.complaintText.value"
                  :options="historyComplaintFilterOptions"
                  optionLabel="label"
                  optionValue="value"
                  placeholder="Все жалобы"
                  editable
                  showClear
                  overlay-class="history-filter-select-panel"
                  class="history-filter-select"
                  :disabled="isComplaintFilterDisabled"
                />
              </div>
            </div>
          </div>

          <div class="history-table-wrapper-premium">
            <DataTable
              v-model:filters="historyTableFilters"
              v-model:selection="selectedHistoryRecords"
              :value="adminHistory"
              dataKey="id"
              filterDisplay="row"
              :loading="loadingHistory"
              class="history-datatable"
              rowHover
              @filter="onHistoryTableFilter"
            >
              <template #empty>
                <div class="history-datatable-empty">
                  Записи, удовлетворяющие условиям фильтра, не найдены.
                </div>
              </template>

              <Column selectionMode="multiple" headerStyle="width: 3rem" />

              <Column field="timestamp" header="Дата и время" bodyClass="history-col-time" :showFilterMenu="false" style="min-width: 11rem">
                <template #body="{ data }">
                  <span class="td-time">{{ formatDate(data.timestamp) }}</span>
                </template>
                <template #filter="{ filterModel, filterCallback }">
                  <Select
                    v-model="filterModel.value"
                    :options="historyDateFilterOptions"
                    optionLabel="label"
                    optionValue="value"
                    placeholder="Все"
                    editable
                    showClear
                    overlay-class="history-filter-select-panel"
                    class="history-filter-select"
                    :disabled="isDateFilterDisabled"
                    @update:modelValue="filterCallback()"
                    @change="filterCallback()"
                  />
                </template>
              </Column>

              <Column field="id" header="ID диагностики" bodyClass="history-col-diagnostic-id td-diagnostic-id" :showFilterMenu="false" style="min-width: 12rem">
                <template #body="{ data }">
                  <div class="table-diagnostic-id-row">
                    <span class="table-diagnostic-id-text">{{ data.id }}</span>
                    <button
                      type="button"
                      class="btn-copy-table-diagnostic-id"
                      title="Копировать ID диагностики"
                      aria-label="Копировать ID диагностики"
                      @click.stop="copyDiagnosticId(data.id)"
                    >
                      <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                      </svg>
                    </button>
                  </div>
                </template>
                <template #filter="{ filterModel, filterCallback }">
                  <Select
                    v-model="filterModel.value"
                    :options="tableFilterOptions.diagnosticIds"
                    placeholder="Все"
                    editable
                    showClear
                    overlay-class="history-filter-select-panel"
                    class="history-filter-select"
                    :disabled="isDiagnosticIdFilterDisabled"
                    @update:modelValue="filterCallback()"
                    @change="filterCallback()"
                  />
                </template>
              </Column>

              <Column field="sessionId" header="ID сессии" bodyClass="history-col-session td-session" :showFilterMenu="false" style="min-width: 12rem">
                <template #body="{ data }">
                  <div v-if="data.sessionId" class="table-diagnostic-id-row">
                    <span class="table-session-id-text">{{ data.sessionId }}</span>
                    <button
                      type="button"
                      class="btn-copy-table-session-id"
                      title="Копировать ID сессии"
                      aria-label="Копировать ID сессии"
                      @click.stop="copySessionId(data.sessionId)"
                    >
                      <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" aria-hidden="true">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                      </svg>
                    </button>
                  </div>
                  <span v-else class="table-session-id-text">—</span>
                </template>
                <template #filter="{ filterModel, filterCallback }">
                  <Select
                    v-model="filterModel.value"
                    :options="tableFilterOptions.sessionIds"
                    placeholder="Все"
                    editable
                    showClear
                    overlay-class="history-filter-select-panel"
                    class="history-filter-select"
                    :disabled="isSessionIdFilterDisabled"
                    @update:modelValue="filterCallback()"
                    @change="filterCallback()"
                  />
                </template>
              </Column>

              <Column field="complaintText" header="Текст жалобы" bodyClass="history-col-complaint" :showFilterMenu="false" style="min-width: 10rem">
                <template #body="{ data }">
                  <span class="td-complaint" :title="data.complaintText">{{ data.complaintText || '—' }}</span>
                </template>
                <template #filter="{ filterModel, filterCallback }">
                  <Select
                    v-model="filterModel.value"
                    :options="historyComplaintFilterOptions"
                    optionLabel="label"
                    optionValue="value"
                    placeholder="Все"
                    editable
                    showClear
                    overlay-class="history-filter-select-panel"
                    class="history-filter-select"
                    :disabled="isComplaintFilterDisabled"
                    @update:modelValue="filterCallback()"
                    @change="filterCallback()"
                  />
                </template>
              </Column>

              <Column field="detectedSymptoms" header="Симптомы" bodyClass="history-col-symptoms td-symptoms" :showFilterMenu="false" style="min-width: 14rem">
                <template #body="{ data }">
                  <div class="table-symptoms-group">
                    <span
                      v-for="symptom in data.detectedSymptoms"
                      :key="symptom"
                      class="symptom-pill-premium direct-pill"
                      style="margin: 2px;"
                    >
                      <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" stroke-width="3" fill="none" class="check-symptom-svg">
                        <polyline points="20 6 9 17 4 12"></polyline>
                      </svg>
                      <span class="symptom-pill-text">{{ symptom }}</span>
                    </span>
                    <span
                      v-for="symptom in data.assumedSymptoms"
                      :key="symptom"
                      class="symptom-pill-premium assumed-pill"
                      style="margin: 2px;"
                    >
                      <svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" stroke-width="2.5" fill="none" class="assumed-symptom-svg">
                        <polyline points="20 6 9 17 4 12"></polyline>
                      </svg>
                      <span class="symptom-pill-text">{{ symptom }}</span>
                    </span>
                    <span v-if="!data.detectedSymptoms?.length && !data.assumedSymptoms?.length" class="text-muted">—</span>
                  </div>
                </template>
                <template #filter="{ filterModel, filterCallback }">
                  <Select
                    v-model="filterModel.value"
                    :options="tableFilterOptions.symptoms"
                    placeholder="Все"
                    editable
                    showClear
                    overlay-class="history-filter-select-panel"
                    class="history-filter-select"
                    :disabled="isSymptomFilterDisabled"
                    @update:modelValue="filterCallback()"
                    @change="filterCallback()"
                  />
                </template>
              </Column>

              <Column field="results" header="Диагнозы" bodyClass="history-col-diseases td-diseases" :showFilterMenu="false" style="min-width: 16rem">
                <template #body="{ data }">
                  <div class="table-diseases-group" style="display: flex; flex-direction: column; gap: 0.5rem; align-items: flex-start; max-width: none;">
                    <div
                      v-for="res in data.results"
                      :key="res.disease"
                      class="history-disease-item"
                      style="display: flex; flex-direction: column; align-items: flex-start; gap: 4px; width: 100%; padding-bottom: 6px;"
                    >
                      <div
                        class="history-disease-header"
                        style="display: flex; align-items: center; gap: 0.35rem; flex-wrap: wrap; cursor: pointer; user-select: none;"
                        @click="toggleHistoryDiseaseExpand(data.id, res.disease)"
                      >
                        <span class="disease-name-bold">{{ res.disease }}</span>
                        <span class="threat-micro-badge" :class="getThreatColorClass(res.threatLevel || 0)">
                          {{ getThreatLabel(res.threatLevel || 0) }}
                        </span>
                        <span class="disease-chevron-icon" :class="{ 'chevron-rotated': expandedHistoryDiseases[`${data.id}_${res.disease}`] }">
                          <svg viewBox="0 0 24 24" width="11" height="11" stroke="currentColor" stroke-width="3" fill="none">
                            <polyline points="6 9 12 15 18 9"></polyline>
                          </svg>
                        </span>
                      </div>
                      <div
                        v-if="expandedHistoryDiseases[`${data.id}_${res.disease}`]"
                        class="history-disease-details"
                        style="width: 100%; padding-left: 0.5rem; margin-top: 4px; color: var(--text-muted);"
                      >
                        <div style="margin-bottom: 6px; display: flex; flex-direction: column; gap: 4px;">
                          <div style="display: flex; align-items: center; gap: 0.35rem;">
                            <span class="priority-label">Дифференциальный вес:</span>
                            <div class="diagnosis-priority-badge" :class="priorityClassForRecord(data, res)" title="Относительный дифференциальный вес">
                              <span class="priority-value" style="font-weight: 800;">{{ formatDifferentialWeightForRecord(data, res) }}</span>
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
                            class="symptom-pill-premium direct-pill history-disease-symptom-pill"
                          >
                            <svg viewBox="0 0 24 24" width="7" height="7" stroke="currentColor" stroke-width="3" fill="none" class="check-symptom-svg">
                              <polyline points="20 6 9 17 4 12"></polyline>
                            </svg>
                            <span class="symptom-pill-text">{{ symptom }}</span>
                          </span>
                        </div>
                      </div>
                    </div>
                    <span v-if="!data.results?.length" class="text-muted">—</span>
                  </div>
                </template>
                <template #filter="{ filterModel, filterCallback }">
                  <Select
                    v-model="filterModel.value"
                    :options="tableFilterOptions.diseases"
                    placeholder="Все"
                    editable
                    showClear
                    overlay-class="history-filter-select-panel"
                    class="history-filter-select"
                    :disabled="isDiseaseFilterDisabled"
                    @update:modelValue="filterCallback()"
                    @change="filterCallback()"
                  />
                </template>
              </Column>

              <Column header="" bodyClass="history-col-actions td-actions" :showFilterMenu="false" style="width: 3rem; text-align: center">
                <template #filter>
                  <button
                    v-if="hasActiveHistoryTableFilters"
                    type="button"
                    class="btn-clear-table-filters"
                    title="Сбросить все фильтры"
                    aria-label="Сбросить все фильтры"
                    @click="clearHistoryTableFilters"
                  >
                    <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2.5" fill="none" aria-hidden="true">
                      <line x1="18" y1="6" x2="6" y2="18"></line>
                      <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                  </button>
                </template>
                <template #body="{ data }">
                  <button
                    class="btn-download-history-pdf"
                    @click.stop="downloadPdfReport(data)"
                    title="Скачать отчёт"
                    aria-label="Скачать отчёт"
                  >
                    <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2.5" fill="none" style="display: block;">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                      <polyline points="7 10 12 15 17 10"></polyline>
                      <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                  </button>
                </template>
              </Column>
            </DataTable>
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
        Представленные сведения не являются диагнозом, назначением или руководством к самолечению и не заменяют очную консультацию квалифицированного специалиста.<br>
        Полнота и точность представленной информации не гарантируются; ответственность за её самостоятельную интерпретацию и принятые на её основе решения несёт пользователь.<br>
        При любых симптомах обратитесь к врачу соотвествующего профиля, а в неотложных случаях – вызовите скорую медицинскую помощь (112/103).
      </p>
    </footer>
  </div>
</template>
