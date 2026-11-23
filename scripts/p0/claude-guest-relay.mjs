import fs from 'node:fs';
import net from 'node:net';

const marker = 'C:\\P0Lab\\transport-down';
if (process.cwd().toLowerCase() !== 'c:\\p0lab' || process.env.PROXY_HARBOR_P0_GUEST !== 'offline-lab') {
  throw new Error('Disposable Claude guest required');
}

const auditDomains = new Set();
if (process.argv[2] === 'domain-audit') {
  const catalog = JSON.parse(fs.readFileSync('claude-code-domains.json', 'utf8').replace(/^\uFEFF/, ''));
  for (const group of catalog.groups) for (const domain of group.domains) auditDomains.add(`${domain}:443`);
}

const active = new Set();
const timer = setInterval(() => {
  if (fs.existsSync(marker)) {
    for (const socket of active) socket.destroy();
  }
}, 25);
timer.unref();

const relay = net.createServer(client => {
  if (fs.existsSync(marker)) {
    client.destroy();
    return;
  }
  const upstream = net.createConnection(10809, '127.0.0.1');
  for (const [socket, peer] of [[client, upstream], [upstream, client]]) {
    active.add(socket);
    socket.on('error', () => peer.destroy());
    socket.on('close', () => {
      active.delete(socket);
      peer.destroy();
    });
  }
  const port = client.remotePort;
  let authority;
  let status;
  observeHeader(client, bytes => {
    const firstLine = bytes.toString('latin1').split('\r\n', 1)[0];
    const hostname = /^CONNECT ([a-z0-9.-]+:443) HTTP\/1\.[01]$/i.exec(firstLine)?.[1]?.toLowerCase();
    if (hostname && (auditDomains.has(hostname) || /(^|\.)(claude\.ai|claude\.com|anthropic\.com|api\.ipify\.org):443$/.test(hostname))) authority = hostname;
    if (authority) log({event: 'connect', authority, port});
  });
  observeHeader(upstream, (bytes, rest) => {
    status = /^HTTP\/1\.[01] ([0-9]{3})\b/.exec(bytes.toString('latin1'))?.[1];
    if (!authority || !status) return;
    log({event: 'proxy_response', authority, port, status: Number(status)});
    if (status === '200') {
      const tunnelData = chunk => log({event: 'tunnel_data', authority, port, bytes: chunk.length});
      if (rest.length) tunnelData(rest);
      else upstream.once('data', tunnelData);
    }
  });
  client.pipe(upstream).pipe(client);
});

function observeHeader(socket, callback) {
  let buffer = Buffer.alloc(0);
  const receive = chunk => {
    const remaining = 8192 - buffer.length;
    const sample = Buffer.concat([buffer, chunk.subarray(0, remaining)]);
    const end = sample.indexOf('\r\n\r\n');
    if (end !== -1) {
      socket.off('data', receive);
      callback(sample.subarray(0, end), chunk.subarray(end + 4 - buffer.length));
      buffer = Buffer.alloc(0);
    } else if (sample.length === 8192) {
      socket.off('data', receive);
      buffer = Buffer.alloc(0);
    } else buffer = sample;
  };
  socket.on('data', receive);
}

function log(row) {
  console.log(JSON.stringify({time: new Date().toISOString(), ...row}));
}

relay.listen(10808, '127.0.0.1', () => log({event: 'listening'}));
