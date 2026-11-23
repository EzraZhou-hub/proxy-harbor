import { expect, test } from '@playwright/test'

test('browser cleanup requires confirmation and reports each action independently', async ({ page }) => {
 const calls: unknown[] = []
 let chromeBusy = false
 await page.route('**/wails/runtime', async route => {
  const { args } = route.request().postDataJSON()
  // Use the IDs from the generated DesktopService bindings.
  if (args?.methodID === 1531451108) return route.fulfill({ json: true })
  if (args?.methodID !== 26190173) return route.continue()
  calls.push(args.args)
  if (args.args[0] === 'chrome' && chromeBusy) {
   return route.fulfill({ status: 500, json: { kind: 'RuntimeError', message: '请完全退出 Google Chrome（包括后台进程），然后重试' } })
  }
  return route.fulfill({ json: args.args[0] === 'chrome' ? 2 : 0 })
 })
 await page.goto('/')
 await page.getByRole('button', { name: '本机验证', exact: true }).click()
 const tools = page.getByRole('region', { name: '浏览器数据清理' })
 const dialog = page.getByRole('dialog')
 const chrome = tools.getByRole('button', { name: '清除 Cookies', exact: true })
 await chrome.click()
 await expect(dialog).toContainText('部分网站需要重新登录')
 await expect(dialog.getByRole('button', { name: '取消' })).toBeFocused()
 await page.keyboard.press('Escape')
 await expect(dialog).toBeHidden()
 expect(calls).toEqual([])

 await chrome.click()
 await dialog.getByRole('button', { name: '确认清除' }).click()
 await expect(tools.getByRole('status')).toHaveText('已清除 2 个 Chrome Cookie 文件。')

 await tools.getByRole('button', { name: '清除 Flash Cookies', exact: true }).click()
 await expect(dialog).toContainText('本地存档可能丢失')
 await dialog.getByRole('button', { name: '确认清除' }).click()
 await expect(tools.getByRole('status')).toHaveText('未找到可清除的 Flash Cookie 文件。')

 chromeBusy = true
 await chrome.click()
 await dialog.getByRole('button', { name: '确认清除' }).click()
 await expect(tools.getByRole('alert')).toContainText('请完全退出 Google Chrome')
 expect(calls).toEqual([['chrome', true], ['flash', true], ['chrome', true]])
})
