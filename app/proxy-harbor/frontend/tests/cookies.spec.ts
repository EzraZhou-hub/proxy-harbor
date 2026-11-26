import { expect, test } from '@playwright/test'

test('standalone Flash cleanup requires confirmation and reports the result', async ({ page }) => {
 const calls: unknown[] = []
 let flashBusy = false
 let deleted = 2
 await page.route('**/wails/runtime', async route => {
  const { args } = route.request().postDataJSON()
  // Use the IDs from the generated DesktopService bindings.
  if (args?.methodID === 1531451108) return route.fulfill({ json: true })
  if (args?.methodID !== 26190173) return route.continue()
  calls.push(args.args)
  if (flashBusy) {
   return route.fulfill({ status: 500, json: { kind: 'RuntimeError', message: '请关闭仍在运行的 Flash 程序，然后重试' } })
  }
  return route.fulfill({ json: deleted })
 })
 await page.goto('/')
 await page.getByRole('button', { name: '诊断与日志', exact: true }).click()
 const tools = page.getByRole('region', { name: 'Flash 数据清理' })
 const dialog = page.getByRole('dialog')
 const flash = tools.getByRole('button', { name: '清除 Flash Cookies', exact: true })
 await expect(tools.getByRole('button', { name: '清除 Cookies', exact: true })).toHaveCount(0)
 await flash.click()
 await expect(dialog).toContainText('本地存档可能丢失')
 await expect(dialog.getByRole('button', { name: '取消' })).toBeFocused()
 await page.keyboard.press('Escape')
 await expect(dialog).toBeHidden()
 expect(calls).toEqual([])

 await flash.click()
 await dialog.getByRole('button', { name: '确认清除' }).click()
 await expect(tools.getByRole('status')).toHaveText('已清除 2 个 Flash Cookie 文件。')

 deleted = 0
 await flash.click()
 await dialog.getByRole('button', { name: '确认清除' }).click()
 await expect(tools.getByRole('status')).toHaveText('未找到可清除的 Flash Cookie 文件。')

 flashBusy = true
 await flash.click()
 await dialog.getByRole('button', { name: '确认清除' }).click()
 await expect(tools.getByRole('alert')).toContainText('请关闭仍在运行的 Flash 程序')
 expect(calls).toEqual([['flash', true], ['flash', true], ['flash', true]])
})
