<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, reactive, ref } from 'vue'
import Icon from './components/AppIcon.vue'
import DomainReference from './components/DomainReference.vue'
import { backend, type Snapshot, type ProxyProfile, type ManagedSession } from './api'
import { mergeApplicationPaths, type SubmittedPath } from './application-drafts'

type Page = 'overview' | 'applications' | 'proxies' | 'validation' | 'diagnostics'
const page = ref<Page>('overview')
const navigation = [
 { id: 'overview' as Page, name: '连接概览', icon: 'grid', description: '启动 Claude Desktop 隔离会话，查看守护状态并设置固定出口。' },
 { id: 'applications' as Page, name: '应用管理', icon: 'apps', description: '查看保护范围并登记应用程序路径。' },
 { id: 'proxies' as Page, name: '代理配置', icon: 'proxy', description: '管理常用代理入口。隔离会话使用 v2rayN 的本地 HTTP 入口。' },
 { id: 'validation' as Page, name: '本机验证', icon: 'shield', description: '使用独立 Chrome 窗口验证当前代理、TUN 和固定出口。' },
 { id: 'diagnostics' as Page, name: '诊断与日志', icon: 'activity', description: '核对退出原因、出口观测和本机环境。' },
]
const currentPage = computed(() => navigation.find(item => item.id === page.value)!)
const snapshot = ref<Snapshot | null>(null)
type SessionAction = 'start' | 'stop' | 'recover'
type CookieKind = 'chrome' | 'flash'
const cookieActions = {
 chrome: {
  label: '清除 Cookies',
  detail: '清除当前 Windows 用户的 Google Chrome 标准个人资料中的网站 Cookies。请先完全退出 Chrome。',
  effect: '清除后，部分网站需要重新登录。',
 },
 flash: {
  label: '清除 Flash Cookies',
  detail: '清除当前 Windows 用户的旧 Flash 共享对象，以及 Chrome 个人资料里的 Flash 残留。请先关闭 Chrome 和使用 Flash 的程序。',
  effect: '清除后，旧 Flash 应用的网站偏好和本地存档可能丢失。',
 },
}
const cookieToolsAvailable = ref(false)
const cookieDialog = ref<HTMLDialogElement | null>(null)
const cookieSelection = ref<CookieKind | null>(null)
const cleaningCookies = ref<CookieKind | null>(null)
const cookieFeedback = ref<{ message: string; failed: boolean } | null>(null)
const managed = ref<ManagedSession | null>(null)
const managedBusy = ref<SessionAction | null>(null)
const statusIssue = ref(false)
const stopRequested = ref(false)
const expectedExit = ref('')
const exitInput = ref<HTMLInputElement | null>(null)
let statusTimer: ReturnType<typeof setInterval> | undefined
let statusRead = 0
let pollInProgress = false
const status = computed(() => managed.value?.state ?? 'idle')
const managedActive = computed(() => ['preparing', 'monitoring', 'blocking'].includes(status.value))
const needsRecovery = computed(() => status.value === 'cleanup_required')
const abnormalStop = computed(() => status.value === 'stopped' &&
 !['user_stopped', 'application_exited', 'desktop_exited', 'recovered'].includes(managed.value?.reason ?? ''))
const statusLabels: Record<string, string> = {
 idle: '未受保护', unavailable: '保护不可用', preparing: '正在准备',
 monitoring: '会话保护中', blocking: '正在阻断并结束',
 stopped: '已停止', failed: '启动失败', cleanup_required: '需要恢复',
}
const managedLabel = computed(() => {
 if (statusIssue.value) return '状态读取失败'
 if (stopRequested.value && status.value !== 'blocking') return '正在结束会话'
 if (abnormalStop.value) return '会话异常结束'
 return statusLabels[status.value] ?? '未受保护'
})
const sessionTone = computed(() => {
 if (statusIssue.value || needsRecovery.value || abnormalStop.value || status.value === 'failed') return 'warning'
 if (stopRequested.value) return 'working'
 if (status.value === 'monitoring') return 'good'
 if (managedActive.value) return 'working'
 return 'neutral'
})
const managedTarget = computed(() => applications.value.find(app => app.id === 'chrome'))
const claudeSession = computed(() => managed.value?.applicationId === 'claude')
const savedExit = computed(() => snapshot.value?.config.expectedProxyIPv4 ?? '')
const exitDirty = computed(() => expectedExit.value !== savedExit.value)
const waitingForSetup = computed(() => !!managed.value?.available && (!savedExit.value || exitDirty.value || !managedTarget.value?.executable))
const sessionStartUnavailable = computed(() => !managed.value?.available || statusIssue.value || busy.value ||
 !!managedBusy.value || managedActive.value || needsRecovery.value || !!cleaningCookies.value)
const startBlocked = computed(() => sessionStartUnavailable.value || waitingForSetup.value)
const claudeStartBlocked = computed(() => sessionStartUnavailable.value || !savedExit.value || exitDirty.value)
const sessionConfigLocked = computed(() => managedActive.value || !!managedBusy.value || needsRecovery.value)
const sessionDescription = computed(() => {
 if (statusIssue.value) return '正在重试读取守护状态。'
 if (stopRequested.value && status.value !== 'blocking') return '已请求结束会话，正在核对清理状态。'
 if (!managed.value) return '正在读取本机守护程序状态。'
 if (!managed.value.available || status.value !== 'idle') return managed.value.detail
 if (!managedTarget.value?.executable) return '请先登记 Google Chrome 的程序路径。'
 if (!savedExit.value) return '请保存 v2rayN 节点的固定公网 IPv4。'
 if (exitDirty.value) return '有尚未保存的出口 IPv4，请先保存。'
 return '已准备启动隔离窗口。启动时将核对 v2rayN、TUN 和固定出口。'
})
const observedExit = computed(() => managed.value?.exitCheckedAt
 ? managed.value.lastObservedExit || '查询失败'
 : '尚未核验')
const sessionChecks = computed(() => {
 const active = !statusIssue.value && status.value === 'monitoring'
 const dns = statusIssue.value ? '状态未知' : managed.value?.dns === 'system_blocked' ? '全机临时限制' : managed.value?.dns === 'restored' ? '限制已解除' : '待启动'
 return [
  {id:'exit',name:'代理出口',state:active && managed.value?.proxyExit ? '已核对':'未运行',detail:active ? `本次出口 ${managed.value?.proxyExit || '待核对'}；变化或无法核对时结束会话。`:'启动后核对本次代理的公网 IPv4 出口。'},
  {id:'rules',name:'连接限制',state:active && (managed.value?.filterCount ?? 0)>0 ? '已安装':'未运行',detail:active ? `本次 ${managed.value?.filterCount} 条限制，只允许指定代理入口；IPv6 和 UDP 阻断。`:'启动应用前安装独立限制，故障时先阻断再终止。'},
  {id:'dns',name:'系统 DNS',state:dns,detail:'保护期间限制全机传统 DNS 和 Windows DNS 服务出站。异常残留可在概览执行恢复。'},
  {id:'webrtc',name:'WebRTC',state:active && managed.value?.applicationId === 'chrome' ? '浏览器策略已核对' : '待启动',detail:'限制本地 IP 候选，阻断受管程序的非代理 UDP 和 IPv6 连接。'},
 ]
})
async function refreshManaged() {
 const read = ++statusRead
 try {
  const result = await backend.ManagedStatus()
  if (read === statusRead) {
   managed.value = result
   statusIssue.value = false
   if (!managedActive.value) stopRequested.value = false
  }
 } catch {
  if (read === statusRead) statusIssue.value = true
 }
}
async function pollManaged() {
 if (managedBusy.value || pollInProgress) return
 pollInProgress = true
 try { await refreshManaged() }
 finally { pollInProgress = false }
}
async function managedAction(kind: SessionAction, action: () => Promise<ManagedSession>) {
 if (managedBusy.value) return
 ++statusRead
 managedBusy.value = kind
 error.value = ''; notice.value = ''
 try {
  managed.value = await action()
  if (kind === 'stop' && managedActive.value) stopRequested.value = true
 }
 catch (cause) { error.value = messageOf(cause) }
 finally { await refreshManaged(); managedBusy.value = null }
}
const loading = ref(true), busy = ref(false), error = ref(''), notice = ref(''), dialog = ref(false)
const formName = ref<HTMLInputElement | null>(null)
const form = reactive<ProxyProfile>({ id: '', name: '', protocol: 'http', host: '', port: 7890 })
const paths = reactive<Record<string, string>>({})
const resetConfirmed = ref(false)
const profiles = computed(() => snapshot.value?.config.profiles ?? [])
const applications = computed(() => snapshot.value?.config.applications ?? [])
const orderedApps = computed(() => ['claude', 'chrome'].flatMap(id => applications.value.filter(app => app.id === id)))
const selected = computed(() => profiles.value.find(item => item.id === snapshot.value?.config.selectedProfileId))
async function openExitSetup() {
 page.value = 'overview'
 await nextTick()
 exitInput.value?.focus()
}
async function openChromePath() {
 page.value = 'applications'
 await nextTick()
 document.getElementById('path-chrome')?.focus()
}
function accept(value: Snapshot, submitted?: SubmittedPath) {
 const previousExit = snapshot.value?.config.expectedProxyIPv4 ?? ''
 if (!snapshot.value || expectedExit.value === previousExit) expectedExit.value = value.config.expectedProxyIPv4 ?? ''
 mergeApplicationPaths(paths, snapshot.value?.config.applications ?? [], value.config.applications ?? [], submitted)
 snapshot.value = value
}
function messageOf(value: unknown) { return value instanceof Error ? value.message : String(value) }
async function confirmCookieCleanup(kind: CookieKind) {
 if (sessionConfigLocked.value || cleaningCookies.value) return
 cookieSelection.value = kind
 await nextTick()
 cookieDialog.value?.showModal()
}
async function clearCookies() {
 const kind = cookieSelection.value
 if (!kind || cleaningCookies.value || sessionConfigLocked.value) return
 cookieDialog.value?.close()
 cleaningCookies.value = kind
 cookieFeedback.value = null
 try {
  const deleted = Number(await backend.ClearBrowserCookies(kind, true))
  const label = kind === 'chrome' ? 'Chrome Cookie' : 'Flash Cookie'
  cookieFeedback.value = { message: deleted ? `已清除 ${deleted} 个 ${label} 文件。` : `未找到可清除的 ${label} 文件。`, failed: false }
 } catch (cause) { cookieFeedback.value = { message: messageOf(cause), failed: true } }
 finally { cleaningCookies.value = null }
}
async function run(action: () => Promise<Snapshot>, success = '', submitted?: SubmittedPath) {
 if (busy.value) return
 busy.value = true; error.value = ''; notice.value = ''
 try { accept(await action(), submitted); notice.value = success } catch (cause) { error.value = messageOf(cause) }
 finally { busy.value = false }
}
async function load() { loading.value = true; await run(() => backend.Snapshot()); loading.value = false }
async function editProxy(profile?: ProxyProfile) {
 error.value = ''; notice.value = ''
 Object.assign(form, profile ?? { id: '', name: '', protocol: 'http', host: '', port: 7890 })
 dialog.value = true; await nextTick(); formName.value?.focus()
}
async function saveProxy() {
 await run(() => backend.SaveProxy({ ...form, port: Number(form.port) }), '代理入口已保存，尚未进行连接测试。')
 if (!error.value) dialog.value = false
}
async function chooseApp(id: string) {
 if (busy.value) return
 error.value = ''
 try { const path = await backend.ChooseExecutable(); if (path) paths[id] = path }
 catch (cause) { error.value = messageOf(cause) }
}
async function saveApplication(id: string) {
 if (id === 'chrome' && sessionConfigLocked.value) return
 const path = paths[id] ?? ''
 await run(() => backend.ConfigureApplication(id, path), '应用路径已保存。', { id, path })
}
async function saveExpectedExit() {
 if (sessionConfigLocked.value || !exitDirty.value) return
 const submitted = expectedExit.value
 await run(() => backend.SaveExpectedProxyIPv4(submitted), '固定代理出口已保存。')
 if (!error.value && expectedExit.value === submitted) expectedExit.value = snapshot.value?.config.expectedProxyIPv4 ?? ''
}
async function openConfigDirectory() {
 if (busy.value) return
 busy.value = true; error.value = ''
 try { await backend.OpenConfigDirectory() } catch (cause) { error.value = messageOf(cause) }
 finally { busy.value = false }
}
async function resetConfiguration() {
 await run(() => backend.ResetConfiguration(resetConfirmed.value), '原配置已备份，已恢复默认配置。')
 if (!error.value) {
  resetConfirmed.value = false
  for (const app of snapshot.value?.config.applications ?? []) paths[app.id] = app.executable
 }
}
async function reloadConfiguration() {
 resetConfirmed.value = false
 await run(() => backend.ReloadConfiguration())
}
function downloadReport() {
 if (!snapshot.value) return
 const report = { formatVersion: 2, exportedAt: new Date().toISOString(), ...snapshot.value, managedSession: managed.value }
 const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }))
 const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'proxy-harbor-report.json'; anchor.click()
 setTimeout(() => URL.revokeObjectURL(url), 1000)
 notice.value = '报告已导出，其中包含本机地址和应用路径，请按需分享。'
}
function localTime(value: string) { return new Date(value).toLocaleTimeString('zh-CN', { hour12: false }) }
function localDateTime(value: string) {
 return new Date(value).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
}
onMounted(() => {
 void load()
 void pollManaged()
 backend.CookieCleanupAvailable().then(value => { cookieToolsAvailable.value = value }, () => {})
 statusTimer = setInterval(pollManaged, 1000)
})
onUnmounted(() => { if (statusTimer) clearInterval(statusTimer) })
</script>

<template>
 <div class="shell">
  <aside class="sidebar">
   <div class="brand">
    <span class="brand-symbol"><Icon name="shield" :size="23" /></span>
    <div><strong>Proxy Harbor</strong><small>Claude 桌面隔离</small></div>
   </div>
   <nav aria-label="主导航">
    <button v-for="item in navigation" :key="item.id"
     :class="['nav-item', { active: page === item.id }]"
     :aria-current="page === item.id ? 'page' : undefined" @click="page = item.id">
     <Icon :name="item.icon" :size="19" /><span>{{ item.name }}</span>
    </button>
   </nav>
   <div class="sidebar-version"><span>桌面版</span><span class="mono">v{{ snapshot?.version ?? '0.1.0' }}</span></div>
  </aside>

  <main>
   <header class="page-heading">
    <div><h1>{{ currentPage.name }}</h1><p>{{ currentPage.description }}</p></div>
    <button v-if="page === 'proxies'" class="button primary" :disabled="!snapshot || !!snapshot.startup.error || busy" @click="editProxy()">
     <Icon name="plus" :size="17" />添加代理
    </button>
    <button v-else-if="page === 'diagnostics'" class="button" :disabled="!snapshot || !!snapshot.startup.error || busy" @click="downloadReport">
     <Icon name="download" :size="17" />导出报告
    </button>
    <button v-else-if="page === 'validation' && snapshot && !snapshot.startup.error" class="button" @click="page = 'diagnostics'">
     <Icon name="activity" :size="17" />查看会话诊断
    </button>
   </header>

   <div v-if="error" class="feedback error" role="alert">
    <Icon name="info" /><span>{{ error }}</span>
    <button class="icon-button" aria-label="关闭错误提示" @click="error = ''"><Icon name="close" :size="16" /></button>
   </div>
   <div v-if="notice" class="feedback success" role="status">
    <Icon name="check" /><span>{{ notice }}<template v-if="snapshot?.startup.backupPath"> 备份位置 {{ snapshot.startup.backupPath }}</template></span>
    <button class="icon-button" aria-label="关闭提示" @click="notice = ''"><Icon name="close" :size="16" /></button>
   </div>

   <div v-if="loading" class="empty-state panel"><span class="loading-ring"></span><h2>正在读取本机配置</h2></div>
   <div v-else-if="!snapshot" class="empty-state panel">
    <Icon name="info" :size="30" /><h2>无法读取本机服务</h2>
    <button class="button" @click="load">重新连接</button>
   </div>
   <section v-else-if="snapshot.startup.error" class="panel recovery-panel" aria-labelledby="recovery-title">
    <Icon name="info" :size="28" /><h2 id="recovery-title">配置暂时无法加载</h2>
    <p>可以修复文件后重新读取，或先备份原文件再恢复默认配置。</p>
    <p class="recovery-error" role="alert">{{ snapshot.startup.error }}</p>
    <div class="config-location"><span>配置文件</span><code>{{ snapshot.configPath }}</code></div>
    <div class="inline-actions">
     <button class="button" :disabled="busy" @click="reloadConfiguration"><Icon name="refresh" :size="16" />重新读取配置</button>
     <button class="button" :disabled="busy" @click="openConfigDirectory"><Icon name="folder" :size="16" />打开配置目录</button>
    </div>
    <template v-if="snapshot.startup.canReset">
     <label class="reset-confirmation"><input v-model="resetConfirmed" type="checkbox" :disabled="busy" />我确认备份原文件，并重置当前代理配置和应用路径</label>
     <button class="button primary" :disabled="busy || !resetConfirmed" @click="resetConfiguration">备份并重置配置</button>
    </template>
    <p v-else>当前错误无法通过重置恢复，请检查文件访问权限后重试。</p>
   </section>

   <template v-else-if="page === 'overview'">
    <section class="session-hero claude-hero" :data-tone="claudeSession ? sessionTone : undefined" aria-labelledby="claude-title">
     <div class="session-intro">
      <div class="session-label"><Icon name="shield" :size="18" />隔离保护</div>
      <h2 id="claude-title">Claude Desktop</h2>
      <p v-if="claudeSession || needsRecovery" aria-live="polite">{{ managedLabel }} · {{ sessionDescription }}</p>
      <p v-else>通过固定代理出口启动本机安装的 Claude Desktop。</p>
      <div class="inline-actions">
       <button v-if="needsRecovery" class="button session-primary" :disabled="!!managedBusy || !managed?.available"
        @click="managedAction('recover', () => backend.RecoverManagedSession())">
        <Icon name="refresh" :size="16" />{{ managedBusy === 'recover' ? '正在发起恢复…' : '核对并恢复限制' }}
       </button>
       <button v-else-if="claudeSession && managedActive" class="button session-primary"
        :disabled="!!managedBusy || stopRequested || status === 'blocking'" @click="managedAction('stop', () => backend.StopManagedApplication())">
        <Icon name="close" :size="16" />{{ stopRequested || status === 'blocking' ? '正在结束…' : '结束 Claude 会话' }}
       </button>
       <button v-else class="button session-primary" :disabled="claudeStartBlocked"
        @click="managedAction('start', () => backend.StartManagedApplication('claude'))">
        <Icon name="shield" :size="16" />{{ managedBusy === 'start' ? '正在请求管理员授权…' : managed?.takeoverAvailable ? '接管并重启 Claude' : '启动 Claude 并保护' }}
       </button>
       <button v-if="!savedExit || exitDirty" class="button hero-secondary" :disabled="sessionConfigLocked" @click="openExitSetup">配置固定出口</button>
      </div>
     </div>
     <div class="session-mark" aria-hidden="true"><Icon name="shield" :size="76" /></div>
     <dl class="session-metrics">
      <div><dt>固定公网 IPv4</dt><dd><span :class="{ mono: savedExit }">{{ savedExit || '待保存' }}</span></dd></div>
      <div><dt>v2rayN HTTP 入口</dt><dd class="mono">127.0.0.1:10808</dd></div>
     </dl>
    </section>

    <section v-if="!claudeSession && managedActive" class="panel current-validation">
     <div><h2>Chrome 本机验证</h2><p class="muted-copy">{{ managedLabel }} · {{ sessionDescription }}</p></div>
     <button class="button" @click="page = 'validation'">查看验证会话<Icon name="arrow" :size="16" /></button>
    </section>

    <div class="dashboard-grid">
     <section class="panel panel-body" aria-labelledby="setup-title">
      <h2 id="setup-title">固定出口配置</h2>
      <form class="exit-form" @submit.prevent="saveExpectedExit">
       <label for="expected-exit">固定代理出口 IPv4</label>
       <div class="field-actions">
        <input id="expected-exit" ref="exitInput" v-model.trim="expectedExit" class="mono" maxlength="15"
         autocomplete="off" spellcheck="false" placeholder="填写节点的公网 IPv4"
         :disabled="sessionConfigLocked || busy" aria-describedby="exit-hint" />
        <button class="button" type="submit" :disabled="sessionConfigLocked || busy || !exitDirty">保存出口 IP</button>
       </div>
       <p v-if="exitDirty" id="exit-hint" class="field-note pending-text">有尚未保存的 IPv4 修改。</p>
       <p v-else id="exit-hint" class="field-note">填写 v2rayN 节点的公网 IPv4，供启动隔离会话前核对。</p>
      </form>
     </section>

     <section class="panel panel-body" aria-labelledby="scope-title">
      <h2 id="scope-title">隔离范围</h2>
      <ul class="scope-list">
       <li><Icon name="apps" /><div>
        <strong>{{ managed?.takeoverAvailable ? '沿用现有 Claude 登录' : '独立 Claude 窗口' }}</strong>
        <p v-if="managed?.takeoverAvailable">请先保存工作。开启保护时会退出并重开 Claude，继续使用当前 Windows 用户的配置和登录状态。</p>
        <p v-else>由 Windows 自动识别官方 x64 安装。受管窗口使用临时 Windows 账户，请在其中登录 Claude。</p>
       </div></li>
       <li><Icon name="proxy" /><div><strong>固定代理出口</strong><p>沿用 v2rayN 全局和 TUN，绑定指定代理入口并核对公网 IPv4。</p></div></li>
       <li><Icon name="globe" /><div><strong>系统 DNS 临时限制</strong><p>启动需要管理员授权。保护期间，其他程序的传统 DNS 查询也可能受影响。</p></div></li>
      </ul>
     </section>
    </div>
   </template>

   <template v-else-if="page === 'validation'">
    <section class="session-hero" :data-tone="sessionTone" aria-labelledby="session-title">
     <div class="session-intro">
      <div class="session-label"><Icon name="shield" :size="18" />{{ claudeSession && (managedActive || needsRecovery) ? 'Claude 会话' : 'Google Chrome 验证' }}</div>
      <h2 id="session-title" aria-live="polite"><span class="signal-dot"></span>{{ managedLabel }}</h2>
      <p>{{ sessionDescription }}</p>
      <div class="inline-actions">
       <button v-if="needsRecovery" class="button session-primary" :disabled="!!managedBusy || !managed?.available"
        @click="managedAction('recover', () => backend.RecoverManagedSession())">
        <Icon name="refresh" :size="16" />{{ managedBusy === 'recover' ? '正在发起恢复…' : '核对并恢复限制' }}
       </button>
       <button v-else-if="managedActive" class="button session-primary" :disabled="!!managedBusy || stopRequested || status === 'blocking'"
        @click="managedAction('stop', () => backend.StopManagedApplication())">
        <Icon name="close" :size="16" />{{ managedBusy === 'stop' || stopRequested || status === 'blocking' ? '正在结束…' : '结束本次应用' }}
       </button>
       <template v-else>
        <button class="button session-primary" :disabled="startBlocked"
         @click="managedAction('start', () => backend.StartManagedApplication('chrome'))">
         <Icon name="shield" :size="16" />{{ managedBusy === 'start' ? '正在请求管理员授权…' : '启动隔离应用并保护' }}
        </button>
        <button v-if="waitingForSetup && !statusIssue" class="button hero-secondary"
         @click="!managedTarget?.executable ? openChromePath() : openExitSetup()">完善启动配置<Icon name="arrow" :size="16" /></button>
       </template>
      </div>
     </div>
     <div class="session-mark" aria-hidden="true"><Icon name="shield" :size="76" /></div>
     <dl class="session-metrics">
      <div><dt>代理入口</dt><dd><span class="mono">127.0.0.1:10808</span><small>v2rayN · HTTP</small></dd></div>
      <div><dt>固定公网 IPv4</dt><dd><span :class="{ mono: savedExit }">{{ savedExit || '待保存' }}</span><small>会话启动时核对</small></dd></div>
      <div><dt>最近出口观测</dt><dd><span :class="{ mono: managed?.lastObservedExit }">{{ observedExit }}</span>
       <small>{{ managed?.exitCheckedAt ? localDateTime(managed.exitCheckedAt) : '启动后显示检测结果' }}</small></dd>
      </div>
     </dl>
    </section>

    <div class="dashboard-grid">
     <section class="panel panel-body" aria-labelledby="setup-title">
      <h2 id="setup-title">验证配置</h2>
      <div class="setup-app validation-exit">
       <div><h3>固定出口 IPv4</h3><p>{{ exitDirty ? '有尚未保存的 IPv4 修改' : savedExit || '尚未保存' }}</p></div>
       <button class="button small" :disabled="sessionConfigLocked" @click="openExitSetup">修改出口</button>
      </div>
      <div class="setup-app">
       <div><h3>Google Chrome 路径</h3><p v-if="managedTarget?.executable" class="mono" :title="managedTarget.executable">{{ managedTarget.executable }}</p>
        <p v-else>尚未登记</p>
       </div>
       <button class="button small" @click="openChromePath">{{ managedTarget?.executable ? '查看或修改' : '登记路径' }}</button>
      </div>
     </section>

     <section class="panel panel-body" aria-labelledby="scope-title">
      <h2 id="scope-title">使用提醒</h2>
      <ul class="scope-list">
       <li><Icon name="proxy" /><div><strong>启动前准备</strong><p>开启 v2rayN 全局和 TUN，完全退出已有 Chrome。启动保护需要 Windows 管理员授权。</p></div></li>
       <li><Icon name="apps" /><div><strong>隔离的 Chrome 窗口</strong><p>保护覆盖本次新开的 Chrome 会话。窗口使用临时配置，退出后会清理该配置。</p></div></li>
       <li><Icon name="globe" /><div><strong>系统 DNS 临时限制</strong><p>保护期间，其他程序的传统 DNS 查询也可能受影响。</p></div></li>
      </ul>
     </section>
    </div>
    <section v-if="cookieToolsAvailable" class="panel panel-body" aria-labelledby="cookie-tools-title">
     <h2 id="cookie-tools-title">浏览器数据清理</h2>
     <p class="muted-copy">隔离 Chrome 的临时配置在会话结束时自动清理。</p>
     <div v-for="(action, kind) in cookieActions" :key="kind" class="setup-app">
      <div><h3>{{ kind === 'chrome' ? 'Chrome Cookies' : 'Flash Cookies' }}</h3><p>{{ action.detail }}</p></div>
      <button class="button small" :disabled="sessionConfigLocked || !!cleaningCookies" @click="confirmCookieCleanup(kind)">
       {{ cleaningCookies === kind ? '正在清理…' : action.label }}
      </button>
     </div>
     <p v-if="cookieFeedback" :class="['feedback', cookieFeedback.failed ? 'error' : 'success']"
      :role="cookieFeedback.failed ? 'alert' : 'status'">{{ cookieFeedback.message }}</p>
    </section>
   </template>

   <template v-else-if="page === 'applications'">
    <div class="application-grid">
     <article v-for="app in orderedApps" :key="app.id" :class="['panel', 'app-card', { 'main-app': app.id === 'claude' }]">
      <header class="section-topline">
       <div class="app-title"><span class="tile-icon"><Icon :name="app.id === 'claude' ? 'shield' : 'globe'" /></span><h2>{{ app.id === 'claude' ? 'Claude Desktop' : app.name }}</h2></div>
       <span :class="['pill', app.id === 'claude' ? 'clay-pill' : 'neutral']">{{ app.id === 'claude' ? '自动识别' : '本机验证' }}</span>
      </header>
      <p v-if="app.id === 'claude'" class="muted-copy">从「连接概览」启动时，Windows 会查找当前账户安装的官方 Claude Desktop x64。</p>
      <template v-else>
      <p class="muted-copy">用于核对本机代理和隔离能力。启动、停止和恢复位于「本机验证」。</p>
      <form @submit.prevent="saveApplication(app.id)">
       <label :for="'path-' + app.id">{{ app.name }} 程序路径</label>
       <div class="field-actions">
        <input :id="'path-' + app.id" v-model="paths[app.id]" placeholder="选择或粘贴 .exe 文件的完整路径" autocomplete="off" spellcheck="false"
         :disabled="busy || (app.id === 'chrome' && sessionConfigLocked)" />
        <button class="button square" type="button" :disabled="busy || (app.id === 'chrome' && sessionConfigLocked)"
         :aria-label="'选择 ' + app.name + ' 程序'" @click="chooseApp(app.id)"><Icon name="folder" :size="19" /></button>
       </div>
       <div class="application-footer">
        <span :class="{ 'pending-text': paths[app.id] !== app.executable }">{{ paths[app.id] !== app.executable ? '有未保存的修改' : app.executable ? '路径已登记' : '尚未登记路径' }}</span>
        <button class="button small" type="submit" :disabled="busy || paths[app.id] === app.executable || (app.id === 'chrome' && sessionConfigLocked)">保存路径</button>
       </div>
      </form>
      </template>
     </article>
    </div>
    <DomainReference />
   </template>

   <template v-else-if="page === 'proxies'">
    <section v-if="!profiles.length" class="panel empty-state">
     <span class="tile-icon"><Icon name="proxy" :size="25" /></span>
     <h2>还没有保存的代理入口</h2>
     <p>支持 HTTP、HTTPS 和 SOCKS5。保存配置时不发起连接。</p>
    </section>
    <section v-else class="proxy-list" aria-label="已保存的代理">
     <article v-for="profile in profiles" :key="profile.id" :class="['panel', 'proxy-card', { selected: selected?.id === profile.id }]">
      <span class="tile-icon"><Icon name="proxy" :size="22" /></span>
      <div class="proxy-details">
       <div><h2>{{ profile.name }}</h2><span class="protocol-label">{{ profile.protocol.toUpperCase() }}</span>
        <span v-if="selected?.id === profile.id" class="pill teal-pill">配置已选中</span></div>
       <p class="mono">{{ profile.host }}:{{ profile.port }}</p>
      </div>
      <div class="inline-actions">
       <button v-if="selected?.id !== profile.id" class="button small" :disabled="busy"
        @click="run(() => backend.SelectProxy(profile.id), '已选择代理配置。')">选中配置</button>
       <button class="icon-button" :aria-label="'编辑 ' + profile.name" :disabled="busy" @click="editProxy(profile)"><Icon name="edit" :size="17" /></button>
       <button class="icon-button danger" :aria-label="'删除 ' + profile.name" :disabled="busy"
        @click="run(() => backend.DeleteProxy(profile.id), '代理配置已删除。')"><Icon name="trash" :size="17" /></button>
      </div>
     </article>
    </section>
    <details class="panel detail-panel">
     <summary>代理类型说明</summary>
     <dl class="protocol-explainer">
      <div><dt>HTTP</dt><dd>通过 CONNECT 建立到目标的 TCP 连接。</dd></div>
      <div><dt>HTTPS</dt><dd>先加密连接代理入口，再建立到目标的连接。</dd></div>
      <div><dt>SOCKS5</dt><dd>可以使用远端域名解析，具体能力取决于代理服务。</dd></div>
     </dl>
    </details>
   </template>

   <template v-else>
    <section class="panel panel-body diagnostics-panel">
     <div class="section-topline">
      <div><h2>{{ claudeSession ? '最近 Claude 会话' : '最近 Chrome 验证会话' }}</h2><p class="muted-copy">{{ sessionDescription }}</p></div>
      <span class="pill" :data-tone="sessionTone">{{ managedLabel }}</span>
     </div>
     <div class="check-grid">
      <div v-for="check in sessionChecks" :key="check.id" class="check-card">
       <div><Icon :name="check.id === 'exit' ? 'globe' : check.id === 'dns' ? 'proxy' : 'shield'" :size="18" /><span class="pill neutral">{{ check.state }}</span></div>
       <h4>{{ check.name }}</h4><p>{{ check.detail }}</p>
      </div>
     </div>
     <dl v-if="managed?.directory" class="diagnostic-facts">
      <div><dt>最近出口观测</dt><dd>{{ observedExit }} <span v-if="managed.exitCheckedAt">· {{ localDateTime(managed.exitCheckedAt) }}</span></dd></div>
      <div><dt>会话状态更新</dt><dd>{{ managed.updatedAt ? localDateTime(managed.updatedAt) : '暂无记录' }}</dd></div>
      <div><dt>状态代码</dt><dd><code>{{ managed.reason || '暂无记录' }}</code><span v-if="managed.error"> · Windows {{ managed.error }}</span></dd></div>
     </dl>
     <details v-if="managed?.directory" class="log-detail">
      <summary>查看会话文件与阻断详情</summary>
      <dl class="diagnostic-facts">
       <div><dt>会话目录</dt><dd><code>{{ managed.directory }}</code></dd></div>
       <div v-if="managed.unexpectedPeerPid"><dt>异常 TCP 对端</dt><dd>PID {{ managed.unexpectedPeerPid }} · {{ managed.unexpectedPeerFamily === 2 ? 'IPv4' : 'IPv6' }} · 端口 {{ managed.unexpectedPeerPort }}</dd></div>
       <div v-if="managed.blockedAt"><dt>最近阻断</dt><dd>{{ localDateTime(managed.blockedAt) }} · {{ managed.blockDirection === 'outbound' ? '出站' : '入站' }} · {{ managed.blockedProtocol === 17 ? 'UDP' : managed.blockedProtocol === 6 ? 'TCP' : '协议号 ' + managed.blockedProtocol }}<span v-if="managed.blockedRemotePort"> · 对端端口 {{ managed.blockedRemotePort }}</span> · WFP 规则 {{ managed.blockedFilterId }}</dd></div>
      </dl>
     </details>
    </section>

    <section class="panel panel-body">
     <div class="section-topline">
      <div><h2>本机环境</h2><p class="muted-copy">本机网络接口与运行平台</p></div>
      <button class="button small" :disabled="busy" @click="run(() => backend.RefreshEnvironment(), '本机信息已刷新。')"><Icon name="refresh" :size="15" />刷新本机信息</button>
     </div>
     <dl class="environment-meta">
      <div><dt>主机名称</dt><dd>{{ snapshot.environment.hostname || '无法读取' }}</dd></div>
      <div><dt>运行平台</dt><dd>{{ snapshot.environment.os }} / {{ snapshot.environment.architecture }}</dd></div>
      <div><dt>读取时间</dt><dd>{{ localTime(snapshot.environment.collectedAt) }}</dd></div>
     </dl>
     <div v-for="item in snapshot.environment.interfaces" :key="item.name" class="interface-row">
      <div><strong>{{ item.name }}</strong><span v-if="item.loopback" class="protocol-label">回环</span></div>
      <span class="mono">{{ item.addresses?.join(' · ') || '未读取到地址' }}</span>
     </div>
     <p v-for="warning in snapshot.environment.warnings" :key="warning" class="warning-text">{{ warning }}</p>
    </section>

    <section class="panel panel-body">
     <h2>操作日志</h2>
     <div class="log-list">
      <div v-for="(entry, index) in [...(snapshot.logs ?? [])].reverse()" :key="index" class="log-row">
       <time class="mono">{{ localTime(entry.time) }}</time>
       <span :class="['log-level', entry.level]">{{ entry.level === 'warning' ? '提示' : '信息' }}</span><span>{{ entry.message }}</span>
      </div>
     </div>
     <div class="config-location"><span>配置文件</span><code>{{ snapshot.configPath }}</code>
      <button class="button small" :disabled="busy" @click="reloadConfiguration">重新读取配置</button>
     </div>
    </section>
   </template>
  </main>

  <dialog v-if="cookieToolsAvailable" ref="cookieDialog" class="modal cookie-dialog" aria-labelledby="cookie-dialog-title"
   aria-describedby="cookie-dialog-detail" @close="cookieSelection = null">
   <template v-if="cookieSelection">
    <h2 id="cookie-dialog-title">{{ cookieActions[cookieSelection].label }}</h2>
    <p id="cookie-dialog-detail" class="muted-copy">{{ cookieActions[cookieSelection].detail }}{{ cookieActions[cookieSelection].effect }}</p>
    <div class="modal-actions">
     <button type="button" class="button" autofocus @click="cookieDialog?.close()">取消</button>
     <button type="button" class="button primary" :disabled="sessionConfigLocked" @click="clearCookies">确认清除</button>
    </div>
   </template>
  </dialog>

  <div v-if="dialog" class="modal-backdrop" @click.self="!busy && (dialog = false)" @keydown.esc="!busy && (dialog = false)">
   <section class="modal" role="dialog" aria-modal="true" aria-labelledby="proxy-dialog-title">
    <div class="section-topline">
     <h2 id="proxy-dialog-title">{{ form.id ? '编辑代理' : '添加代理' }}</h2>
     <button class="icon-button" :disabled="busy" aria-label="关闭对话框" @click="dialog = false"><Icon name="close" /></button>
    </div>
    <form @submit.prevent="saveProxy">
     <label for="proxy-name">配置名称</label>
     <input id="proxy-name" ref="formName" v-model="form.name" required maxlength="80" placeholder="例如：开发专用代理" />
     <fieldset>
      <legend>代理类型</legend>
      <div class="protocol-selector">
       <label v-for="protocol in ['http', 'https', 'socks5']" :key="protocol" :class="{ chosen: form.protocol === protocol }">
        <input v-model="form.protocol" type="radio" name="protocol" :value="protocol" />{{ protocol.toUpperCase() }}
       </label>
      </div>
     </fieldset>
     <div class="host-port">
      <div><label for="proxy-host">代理地址</label><input id="proxy-host" v-model="form.host" required maxlength="253" placeholder="127.0.0.1 或 proxy.example.com" autocomplete="off" /></div>
      <div><label for="proxy-port">端口</label><input id="proxy-port" v-model.number="form.port" type="number" min="1" max="65535" required /></div>
     </div>
     <p class="field-note">地址只填写 IPv4 或域名。保存配置时不发起连接。</p>
     <p v-if="error" class="form-error" role="alert">{{ error }}</p>
     <div class="modal-actions">
      <button type="button" class="button" :disabled="busy" @click="dialog = false">取消</button>
      <button type="submit" class="button primary" :disabled="busy">{{ busy ? '正在保存…' : '保存配置' }}</button>
     </div>
    </form>
   </section>
  </div>
 </div>
</template>
