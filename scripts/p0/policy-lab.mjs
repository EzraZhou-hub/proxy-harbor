// Apply is an explicit, elevated lab action. No mode loads a third-party driver,
// changes DNS/system proxy, or accesses an installed desktop application.
import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import { createSocket } from 'node:dgram'
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const binaryDirectory = join(root, '.local/p0/bin')
const policy = join(binaryDirectory, 'p0-wfp.exe')
const probe = join(binaryDirectory, 'proxy-harbor-p0-probe.exe')
const control = join(root, '.local/p0/control/proxy-harbor-p0-probe.exe')
const reportPath = join(root, '.local/p0/policy-report.json')
const report = { schemaVersion: 1, generatedAt: new Date().toISOString(), overall: 'not_accepted',
 scope: 'Only project-built disposable probe, four loopback endpoints, no installed application', checks: [], cleanup: 'not_needed' }
const action = process.argv[2] ?? '--inspect'
if (!['--inspect', '--baseline', '--apply', '--cleanup'].includes(action) || process.argv.length > 3) throw new Error('Use --inspect, --baseline, --apply or --cleanup')
report.action = action
const check = (id, status, detail) => report.checks.push({ id, status, detail })

async function command(executable, args) {
 const child = spawn(executable, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
 let stdout = '', stderr = ''
 child.stdout.on('data', data => { stdout += data })
 child.stderr.on('data', data => { stderr += data })
 const timer = setTimeout(() => child.kill(), 10_000)
 try {
  const code = await new Promise((accept, reject) => { child.once('error', reject); child.once('exit', accept) })
  let value
  try { value = JSON.parse(stdout.trim()) } catch { throw new Error(`Invalid lab response (${code}): ${stderr || stdout}`) }
  return { code, ...value }
 } finally { clearTimeout(timer) }
}

async function endpoint(network) {
 const host = network.endsWith('6') ? '::1' : '127.0.0.1'
 if (network.startsWith('tcp')) {
  const sockets = new Set()
  const server = createServer(socket => {
   sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket))
   socket.on('data', data => socket.write(data))
  })
  await new Promise((accept, reject) => { server.once('error', reject); server.listen({ host, port: 0 }, accept) })
  return { network, address: `${network.endsWith('6') ? `[${host}]` : host}:${server.address().port}`,
   close: () => new Promise(accept => { for (const socket of sockets) socket.destroy(); server.close(accept) }) }
 }
 const socket = createSocket(network)
 socket.on('message', (data, peer) => socket.send(data, peer.port, peer.address))
 await new Promise((accept, reject) => { socket.once('error', reject); socket.bind(0, host, accept) })
 return { network, address: `${network.endsWith('6') ? `[${host}]` : host}:${socket.address().port}`, close: () => new Promise(accept => socket.close(accept)) }
}

const endpoints = []
let mayHaveInstalled = false
try {
 const before = await command(policy, ['inspect'])
 report.preflight = before
 if (action === '--cleanup') {
  const removed = await command(policy, ['remove-fixture-only'])
  report.cleanup = removed.code === 0 && removed.rulesPresent === 0 ? 'verified' : 'failed'
  report.cleanupResult = removed
  if (report.cleanup !== 'verified') throw new Error('Owned rule cleanup failed')
 } else if (action === '--inspect') {
  check('wfp_access', before.code === 0 ? 'passed' : 'not_run', before.code === 0 ? 'Read-only inventory succeeded' : `Windows error ${before.windowsError}; no rules changed`)
 } else {
  if (action === '--apply' && (before.code !== 0 || !before.elevated)) throw new Error('An elevated isolated test session is required before installing fixture rules')
  if (before.code !== 0 || before.rulesPresent !== 0) throw new Error('A successful inventory with no existing lab rules is required before baseline tests')
  for (const network of ['tcp4', 'tcp6', 'udp4', 'udp6']) {
   const listener = await endpoint(network)
   endpoints.push(listener)
   for (const [label, executable] of [['probe', probe], ['control', control]]) {
    const result = await command(executable, ['-network', network, '-address', listener.address])
    if (result.code !== 0 || !result.success) throw new Error(`Baseline ${label}/${network} failed: ${result.detail}`)
   }
   check(`baseline_${network}`, 'passed', 'Both disposable executables exchanged an echo before any rule changes')
  }
  if (action === '--apply') {
  const recovery = { createdAt: new Date().toISOString(), scope: probe,
   toolSHA256: createHash('sha256').update(readFileSync(policy)).digest('hex'),
   probeSHA256: createHash('sha256').update(readFileSync(probe)).digest('hex'),
   sublayerKey: '78c0ad12-2bd0-47bd-b5ec-0132d73b3e8c',
   filterKeys: ['c7abcf31-e42f-4276-894c-6ba6ab0803e1', 'c7abcf32-e42f-4276-894c-6ba6ab0803e1'],
   recoveryCommand: 'node scripts/p0/policy-lab.mjs --cleanup' }
  const recoveryPath = join(root, '.local/p0/recovery.json')
  writeFileSync(recoveryPath, JSON.stringify(recovery, null, 2))
  report.recoveryPath = recoveryPath
  mayHaveInstalled = true
  const installed = await command(policy, ['install-fixture-only'])
  if (installed.code !== 0 || installed.rulesPresent !== 2) throw new Error(`Fixture policy installation failed: ${installed.windowsError}`)
  // The policy command has exited and its BFE handle is closed before these
  // clients run. This is not a claim about engine crash, reboot or redirection.
  for (const listener of endpoints) {
   const blocked = await command(probe, ['-network', listener.network, '-address', listener.address])
   const unaffected = await command(control, ['-network', listener.network, '-address', listener.address])
   const passed = blocked.code !== 0 && !blocked.success && unaffected.code === 0 && unaffected.success
   check(`block_after_command_exit_${listener.network}`, passed ? 'passed' : 'failed',
    'Target must fail; identical executable at another path must still exchange an echo')
   if (!passed) throw new Error(`Policy observation failed for ${listener.network}`)
  }
  }
 }
} catch (error) {
 report.error = String(error.message ?? error)
 process.exitCode = 1
} finally {
 if (mayHaveInstalled) {
  try {
   const removed = await command(policy, ['remove-fixture-only'])
   report.cleanupResult = removed
   report.cleanup = removed.code === 0 && removed.rulesPresent === 0 ? 'verified' : 'failed'
   if (report.cleanup !== 'verified') process.exitCode = 1
  } catch (error) { report.cleanup = 'failed'; report.cleanupError = String(error); process.exitCode = 1 }
 }
 for (const listener of endpoints) await listener.close()
 for (const network of ['tcp4', 'tcp6', 'udp4', 'udp6']) {
  const id = `block_after_command_exit_${network}`
  if (!report.checks.some(item => item.id === id)) check(id, 'not_run', 'No independent block claim until elevated isolated policy tests complete')
 }
 for (const id of ['transparent_forwarding', 'application_dns_interception', 'public_ipv6_udp', 'dual_stack_mapped_ipv4', 'engine_service_crash', 'boot_recovery']) {
  check(id, 'not_run', 'Requires separate evidence; loopback laboratory results do not satisfy this criterion')
 }
 writeFileSync(reportPath, JSON.stringify(report, null, 2))
 console.log(JSON.stringify({ reportPath, ...report }, null, 2))
}
