import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'

export function isolatedData(prefix: string) {
 const scratch = resolve(process.cwd(), '../../../.local')
 mkdirSync(scratch, { recursive: true })
 return mkdtempSync(join(scratch, prefix))
}

export async function startBackend(directory: string, port: number) {
 const child = spawn(resolve(process.cwd(), '../bin/proxy-harbor-server.exe'), [], {
  windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  env: { ...process.env, PROXY_HARBOR_DATA_DIR: directory, WAILS_SERVER_HOST: '127.0.0.1', WAILS_SERVER_PORT: String(port) },
 })
 let output = '', failure: Error | undefined
 child.stdout.on('data', data => { output += data })
 child.stderr.on('data', data => { output += data })
 child.on('error', error => { failure = error })
 const stop = async () => {
  if (child.exitCode !== null || child.signalCode !== null) return
  const exited = new Promise<void>(accept => child.once('exit', () => accept()))
  child.kill()
  await exited
 }
 const url = `http://127.0.0.1:${port}`
 try {
  for (let attempt = 0; attempt < 100; attempt++) {
   if (failure) throw failure
   if (child.exitCode !== null) throw new Error(output)
   try { if ((await fetch(url, { signal: AbortSignal.timeout(1000) })).ok) return { url, stop } } catch {}
   await delay(100)
  }
  throw new Error(`Backend did not become ready: ${output}`)
 } catch (error) { await stop(); throw error }
}
