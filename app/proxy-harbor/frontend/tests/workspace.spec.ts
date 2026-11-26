import { test, expect } from '@playwright/test'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

test('real backend: configuration persists, diagnostics stay unverified, no protected launch', async ({ page }) => {
 const errors: string[] = []
 const externalRequests: string[] = []
 page.on('pageerror', error => errors.push(error.message))
 page.on('request', request => { if (!request.url().startsWith('http://127.0.0.1:19345') && !request.url().startsWith('data:')) externalRequests.push(request.url()) })
 await page.goto('/')
 await expect(page.getByRole('heading', { name: 'Claude Desktop', exact: true })).toBeVisible()
 await expect(page.getByRole('button', { name: '启动 Claude 并保护', exact: true })).toBeDisabled()
 await expect(page.getByRole('button', { name: '本机验证', exact: true })).toHaveCount(0)
 await page.getByRole('button', { name: '配置固定出口', exact: true }).click()
 await expect(page.getByLabel('固定代理出口 IPv4')).toBeFocused()
 await page.getByLabel('固定代理出口 IPv4').fill('131.103.130.202')
 await expect(page.getByText('有尚未保存的 IPv4 修改。')).toBeVisible()
 await page.getByRole('button', { name: '保存出口 IP', exact: true }).click()
 await expect(page.getByRole('status')).toContainText('固定代理出口已保存')
 await page.reload()
 await expect(page.getByLabel('固定代理出口 IPv4')).toHaveValue('131.103.130.202')
 await expect(page.getByRole('button', { name: '启动 Claude 并保护', exact: true })).toBeDisabled()
 await page.getByRole('button', { name: '应用管理', exact: true }).click()
 await expect(page.locator('article').getByRole('heading', { name: 'Claude Desktop', exact: true })).toBeVisible()
 await expect(page.getByRole('heading', { name: 'Google Chrome', exact: true })).toHaveCount(0)
 await expect(page.getByRole('heading', { name: 'Codex', exact: true })).toHaveCount(0)
 await page.getByRole('button', { name: '连接概览', exact: true }).click()
 const scratch = resolve(process.cwd(), '../../../.local')
 mkdirSync(scratch, { recursive: true })
 await page.screenshot({ path: resolve(scratch, 'preview-overview.png'), fullPage: true })
 // Rasterize our code-native SVG mark for Windows resource generation.
 const png = await page.evaluate(async () => {
  const image = new Image(); image.src = '/harbor.svg'; await image.decode()
  const canvas = document.createElement('canvas'); canvas.width = 256; canvas.height = 256
  canvas.getContext('2d')!.drawImage(image, 0, 0, 256, 256)
  return canvas.toDataURL('image/png').split(',')[1]!
 })
 writeFileSync(resolve(process.cwd(), '../build/appicon.png'), Buffer.from(png, 'base64'))

 await page.getByRole('button', { name: /^代理配置/ }).click()
 for (const protocol of ['HTTP', 'HTTPS', 'SOCKS5']) {
  await page.getByRole('button', { name: '添加代理', exact: true }).first().click()
  const modal = page.getByRole('dialog')
  await modal.getByLabel('配置名称').fill(`${protocol} 测试入口`)
  await modal.getByRole('radio', { name: protocol, exact: true }).check()
  await modal.getByLabel('代理地址').fill('127.0.0.1')
  await modal.getByLabel('端口').fill('7890')
  await modal.getByRole('button', { name: '保存配置' }).click()
  await expect(modal).toBeHidden()
  await expect(page.getByRole('heading', { name: `${protocol} 测试入口`, exact: true })).toBeVisible()
 }
 await page.getByRole('button', { name: '编辑 HTTP 测试入口', exact: true }).click()
 await page.getByRole('dialog').getByLabel('配置名称').fill('HTTP 已编辑')
 await page.getByRole('dialog').getByRole('button', { name: '保存配置' }).click()
 await expect(page.getByRole('heading', { name: 'HTTP 已编辑', exact: true })).toBeVisible()
 await page.reload()
 await expect(page.getByRole('heading', { name: 'Claude Desktop', exact: true })).toBeVisible()
 await page.getByRole('button', { name: /代理配置/ }).first().click()
 await expect(page.getByRole('heading', { name: 'HTTP 已编辑', exact: true })).toBeVisible()

 await page.getByRole('button', { name: '添加代理', exact: true }).first().click()
 const modal = page.getByRole('dialog')
 await modal.getByLabel('配置名称').fill('不应保存')
 await modal.getByLabel('代理地址').fill('user:do-not-store@proxy.example.com')
 await modal.getByRole('button', { name: '保存配置' }).click()
 await expect(modal.getByRole('alert')).toContainText('不含协议、端口、账号和密码')
 await modal.getByRole('button', { name: '取消', exact: true }).click()
 await expect(page.getByRole('heading', { name: '不应保存', exact: true })).toHaveCount(0)
 await page.getByRole('button', { name: '删除 SOCKS5 测试入口', exact: true }).click()
 await expect(page.getByRole('heading', { name: 'SOCKS5 测试入口', exact: true })).toHaveCount(0)

 await page.getByRole('button', { name: '诊断与日志', exact: true }).click()
 await expect(page.getByText('未运行', { exact: true })).toHaveCount(2)
 await expect(page.locator('.check-card').filter({ has: page.getByRole('heading', { name: '系统 DNS', exact: true }) })).toContainText('待启动')
 await expect(page.getByRole('heading', { name: 'WebRTC', exact: true })).toHaveCount(0)
 await page.getByRole('button', { name: '刷新本机信息', exact: true }).click()
 await expect(page.getByRole('status')).toContainText('本机信息已刷新')
 const downloadPromise = page.waitForEvent('download')
 await page.getByRole('button', { name: '导出报告', exact: true }).click()
 expect((await downloadPromise).suggestedFilename()).toBe('proxy-harbor-report.json')
 await page.screenshot({ path: resolve(scratch, 'preview-diagnostics.png'), fullPage: true })
 await page.getByRole('button', { name: '连接概览', exact: true }).click()
 await expect(page.getByRole('button', { name: '本机验证', exact: true })).toHaveCount(0)
 await page.setViewportSize({ width: 960, height: 760 })
 expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy()
 expect(errors).toEqual([])
 expect(externalRequests).toEqual([])
})

test('diagnostics distinguish an exit retry from an expired verification', async ({ page }) => {
 let state = {
  available: true, state: 'monitoring', applicationId: 'fixture', reason: 'proxy_only',
  directory: 'fixture', proxyExit: '1.1.1.1', lastExitSuccessAt: '2026-11-26T03:42:00Z',
  exitState: 'retrying', exitStopCause: '', detail: '本轮出口核验失败，正在复核固定代理出口。',
 }
 await page.route('**/wails/runtime', async route => {
  const { args } = route.request().postDataJSON()
  if (args?.methodID === 3747138472) return route.fulfill({ json: state })
  return route.continue()
 })
 await page.goto('/')
 await page.getByRole('button', { name: '诊断与日志', exact: true }).click()
 await expect(page.getByText('正在复核出口', { exact: true })).toBeVisible()
 await expect(page.getByText('上次核验通过', { exact: true })).toBeVisible()
 state = {
  ...state, state: 'stopped', exitState: 'failed', reason: 'exit_unverified',
  exitStopCause: 'verification_expired', detail: '距上次成功核验已满 30 秒，已触发断开。',
 }
 await expect(page.getByText('距上次成功核验已满 30 秒，已触发断开。', { exact: true })).toBeVisible()
})

test('an existing legacy session can still be stopped from the overview', async ({ page }) => {
 let stops = 0
 let state = {
  available: true, state: 'monitoring', applicationId: 'chrome', detail: '会话保护中。',
 }
 await page.route('**/wails/runtime', async route => {
  const { args } = route.request().postDataJSON()
  if (args?.methodID === 3747138472) return route.fulfill({ json: state })
  if (args?.methodID === 1340240764) {
   stops++
   state = { ...state, state: 'stopped', detail: '会话已停止。' }
   return route.fulfill({ json: state })
  }
  return route.continue()
 })
 await page.goto('/')
 const stop = page.getByRole('button', { name: '结束当前会话', exact: true })
 await stop.click()
 await expect(stop).toHaveCount(0)
 expect(stops).toBe(1)
})

test('the approved takeover action starts Claude from the overview', async ({ page }) => {
 const starts: unknown[] = []
 let state = {
  available: true, takeoverAvailable: true, state: 'idle', applicationId: '', detail: '',
 }
 await page.route('**/wails/runtime', async route => {
  const { args } = route.request().postDataJSON()
  if (args?.methodID === 3747138472) return route.fulfill({ json: state })
  if (args?.methodID === 1302663074) {
   starts.push(args.args[0])
   state = { ...state, state: 'preparing', applicationId: 'claude' }
   return route.fulfill({ json: state })
  }
  return route.continue()
 })
 await page.goto('/')
 const takeover = page.getByRole('button', { name: '接管并重启 Claude', exact: true })
 await expect(takeover).toBeVisible()
 await expect(page.getByText('沿用现有 Claude 登录', { exact: true })).toBeVisible()
 await page.getByLabel('固定代理出口 IPv4').fill('131.103.130.202')
 const save = page.getByRole('button', { name: '保存出口 IP', exact: true })
 if (await save.isEnabled()) await save.click()
 await expect(takeover).toBeEnabled()
 await takeover.click()
 await expect(page.getByText(/正在准备/)).toBeVisible()
 expect(starts).toEqual(['claude'])
})
