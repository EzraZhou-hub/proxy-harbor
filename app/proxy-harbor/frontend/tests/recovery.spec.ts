import { test, expect, type Page } from '@playwright/test'
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { isolatedData, startBackend } from './backend-host'

for (const [label, content] of [['malformed JSON', 'invalid configuration\r\n'], ['unsupported version', '{"version":99}']]) {
 test(`configuration recovery: ${label}`, async ({ page }) => {
  const directory = isolatedData('e2e-recovery-')
  const configPath = join(directory, 'config.json')
  writeFileSync(configPath, content)
  const host = await startBackend(directory, 19346)
  try {
   await page.goto(host.url)
   await expect(page.getByRole('heading', { name: '配置暂时无法加载' })).toBeVisible()
   expect(readFileSync(configPath, 'utf8')).toBe(content)
   await expect(page.getByRole('button', { name: '打开配置目录', exact: true })).toBeVisible()
   await expect(page.getByRole('button', { name: '导出报告', exact: true })).toHaveCount(0)
   const reset = page.getByRole('button', { name: '备份并重置配置', exact: true })
   await expect(reset).toBeDisabled()
   await page.getByRole('checkbox', { name: '我确认备份原文件，并重置当前代理配置和应用路径' }).check()
   await page.getByRole('button', { name: '重新读取配置', exact: true }).click()
   await expect(reset).toBeDisabled()
   await page.getByRole('checkbox').check()
   await reset.click()
   await expect(page.getByRole('heading', { name: 'Claude Desktop', exact: true })).toBeVisible()
   const backups = readdirSync(directory).filter(name => name.startsWith('config.backup-'))
   expect(backups).toHaveLength(1)
   expect(readFileSync(join(directory, backups[0]), 'utf8')).toBe(content)
   await expect(page.getByRole('status')).toContainText(join(directory, backups[0]))
   expect(JSON.parse(readFileSync(configPath, 'utf8')).profiles).toEqual([])
   await page.reload()
   await expect(page.getByRole('heading', { name: 'Claude Desktop', exact: true })).toBeVisible()
  } finally { await host.stop() }
 })
}

async function addProxy(page: Page, name: string) {
 await page.getByRole('button', { name: /^代理配置/ }).click()
 await page.getByRole('button', { name: '添加代理', exact: true }).first().click()
 const modal = page.getByRole('dialog')
 await modal.getByLabel('配置名称').fill(name)
 await modal.getByLabel('代理地址').fill('127.0.0.1')
 await modal.getByRole('button', { name: '保存配置', exact: true }).click()
 return modal
}

test('separate backend processes refuse stale saves and retain both entries after reload', async ({ browser }) => {
 const directory = isolatedData('e2e-conflict-')
 const first = await startBackend(directory, 19346)
 let second: Awaited<ReturnType<typeof startBackend>> | undefined
 const a = await browser.newPage(), b = await browser.newPage()
 try {
  second = await startBackend(directory, 19347)
  await a.goto(first.url)
  await b.goto(second.url)
  await expect(a.getByRole('heading', { name: 'Claude Desktop', exact: true })).toBeVisible()
  await expect(b.getByRole('heading', { name: 'Claude Desktop', exact: true })).toBeVisible()
  await expect(await addProxy(a, 'Window A')).toBeHidden()
  const modal = await addProxy(b, 'Window B')
  await expect(modal.getByRole('alert')).toContainText('配置已被其他窗口或程序修改')
  const configPath = join(directory, 'config.json')
  expect(JSON.parse(readFileSync(configPath, 'utf8')).profiles.map((item: { name: string }) => item.name)).toEqual(['Window A'])
  await modal.getByRole('button', { name: '取消', exact: true }).click()
  await b.getByRole('button', { name: '诊断与日志', exact: true }).click()
  await b.getByRole('button', { name: '重新读取配置', exact: true }).click()
  await expect(await addProxy(b, 'Window B')).toBeHidden()
  expect(JSON.parse(readFileSync(configPath, 'utf8')).profiles.map((item: { name: string }) => item.name)).toEqual(['Window A', 'Window B'])
 } finally {
  await a.close(); await b.close()
  if (second) await second.stop()
  await first.stop()
 }
})
