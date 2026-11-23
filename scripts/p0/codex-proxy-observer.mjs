// Offline observer: records only HTTP method/authority, never headers or bodies.
// It rejects every request; no TLS interception and no public forwarding.
import net from 'node:net';
const sockets = new Set();
const server = net.createServer(socket => {
  sockets.add(socket);
  socket.setTimeout(3000, () => socket.destroy());
  socket.on('error', () => {});
  socket.on('close', () => sockets.delete(socket));
  let prefix = Buffer.alloc(0);
  socket.on('data', chunk => {
    prefix = Buffer.concat([prefix, chunk]);
    const end = prefix.indexOf('\r\n');
    if (end < 0 && prefix.length <= 4096) return;
    socket.removeAllListeners('data');
    const line = prefix.subarray(0, Math.min(end < 0 ? prefix.length : end, 4096)).toString('ascii');
    const match = /^(CONNECT|GET|POST|HEAD|OPTIONS) ([^ ]{1,2048}) HTTP\/1\.[01]$/.exec(line);
    let authority = null;
    if (match?.[1] === 'CONNECT' && /^[A-Za-z0-9.:[\]-]+$/.test(match[2])) authority = match[2];
    else if (match) { try { authority = new URL(match[2]).host; } catch {} }
    console.log(JSON.stringify({event:'request',method:match?.[1] ?? 'unrecognized',authority,at:new Date().toISOString()}));
    socket.end('HTTP/1.1 502 P0 offline observer\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
  });
});
server.listen(0, '127.0.0.1', () => console.log(JSON.stringify({event:'listening',address:`127.0.0.1:${server.address().port}`})));
process.on('SIGINT', () => { for (const socket of sockets) socket.destroy(); server.close(); });
