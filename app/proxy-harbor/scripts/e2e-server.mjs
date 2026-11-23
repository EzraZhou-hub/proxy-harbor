// This test host uses the real Go backend with isolated configuration data.
import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync } from 'node:fs'
import { dirname, resolve, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const scratch = resolve(project, '../../.local')
mkdirSync(scratch, { recursive: true })
const data = mkdtempSync(join(scratch, 'e2e-'))
const child = spawn(join(project, 'bin/proxy-harbor-server.exe'), [], {
  cwd: project, windowsHide: true, stdio: 'inherit',
  env: { ...process.env, WAILS_SERVER_HOST: '127.0.0.1', WAILS_SERVER_PORT: '19345', PROXY_HARBOR_DATA_DIR: data },
})
child.on('error', error => { console.error(error.message); process.exit(1) })
child.on('exit', code => process.exit(code ?? 0))
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill())
process.on('exit', () => { if (!child.killed) child.kill() })
