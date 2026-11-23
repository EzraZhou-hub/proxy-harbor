// Ordinary browser baseline only. Does not install policy or inspect an
// existing browser profile, proxy credentials, or authentication data.
import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { randomUUID } from 'node:crypto';
const root = resolve('.local/p0/local-chrome', new Date().toISOString().replace(/[:.]/g, '-') + '-' + randomUUID());
await mkdir(root, { recursive: true });
const executable = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const args = ['--headless=new', '--disable-gpu', '--no-first-run', '--disable-background-networking', '--disable-component-update', '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--user-data-dir=' + join(root, 'profile'), '--proxy-server=http://127.0.0.1:10808', '--dump-dom', 'https://api.ipify.org/'];
const child = spawn(executable, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
let output = '', stderr = '', timedOut = false;
child.stdout.on('data', b => { if (output.length < 1024 * 1024) output += b; });
child.stderr.on('data', b => { if (stderr.length < 1024 * 1024) stderr += b; });
const timeout = setTimeout(() => { timedOut = true; child.kill(); }, 45000);
const code = await new Promise((accept, reject) => { child.once('error', reject); child.once('close', accept); }).finally(() => clearTimeout(timeout));
const body = output.match(/<body[^>]*>([\s\S]*?)<\/body>/i)?.[1].replace(/<[^>]*>/g, '').trim();
const match = body?.match(/^(\d{1,3}(?:\.\d{1,3}){3})$/);
const report = { schemaVersion: 1, generatedAt: new Date().toISOString(), scope: 'Local Chrome explicit HTTP proxy and real HTTPS baseline only; independent blocking and termination not exercised', executable, processId: child.pid, profile: join(root, 'profile'), exitCode: code, timedOut, observedExit: match?.[1] ?? null, passed: code === 0 && !!match && !timedOut, browserSandboxDisabled: false, certificateValidationBypassed: false, hostPolicyChanged: false, existingProfilesRead: false };
await writeFile(join(root, 'result.json'), JSON.stringify(report, null, 2));
await writeFile(join(root, 'stdout.html'), output);
await writeFile(join(root, 'stderr.log'), stderr);
console.log(JSON.stringify({ ...report, report: join(root, 'result.json') }));
if (!report.passed) process.exitCode = 1;
