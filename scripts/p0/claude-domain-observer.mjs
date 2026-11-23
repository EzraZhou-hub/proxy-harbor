import dgram from 'node:dgram';
import net from 'node:net';

if (process.cwd().toLowerCase() !== 'c:\\p0lab' || process.env.PROXY_HARBOR_P0_GUEST !== 'offline-lab') {
  throw new Error('Disposable domain audit guest required');
}

function log(row) {
  console.log(JSON.stringify(row));
}

function dnsReply(packet, transport) {
  if (packet.length < 17 || packet.readUInt16BE(4) !== 1) return;
  const labels = [];
  let offset = 12;
  for (;;) {
    const length = packet[offset++];
    if (length === 0) break;
    if (!length || length > 63 || offset + length >= packet.length) return;
    labels.push(packet.toString('ascii', offset, offset + length));
    offset += length;
  }
  if (offset + 4 > packet.length) return;
  log({event: 'dns', transport, name: labels.join('.').toLowerCase()});
  const response = Buffer.from(packet.subarray(0, offset + 4));
  response.writeUInt16BE(0x8183, 2); // A valid NXDOMAIN with the original question.
  response.fill(0, 6, 12);
  return response;
}

const udp = dgram.createSocket('udp4');
udp.on('message', (packet, peer) => {
  const response = dnsReply(packet, 'udp');
  if (response) udp.send(response, peer.port, peer.address);
});
udp.bind(53, '127.0.0.1', () => log({event: 'dns-udp-ready'}));

const tcp = net.createServer(socket => {
  let packet = Buffer.alloc(0);
  socket.setTimeout(3000, () => socket.destroy());
  socket.on('error', () => socket.destroy());
  socket.on('data', chunk => {
    packet = Buffer.concat([packet, chunk]);
    if (packet.length > 4098) return socket.destroy();
    if (packet.length < 2 || packet.length < packet.readUInt16BE(0) + 2) return;
    const response = dnsReply(packet.subarray(2, packet.readUInt16BE(0) + 2), 'tcp');
    if (!response) return socket.end();
    const size = Buffer.alloc(2);
    size.writeUInt16BE(response.length);
    socket.end(Buffer.concat([size, response]));
  });
});
tcp.listen(53, '127.0.0.1', () => log({event: 'dns-tcp-ready'}));

net.createServer(socket => {
  log({event: 'direct-accepted'});
  socket.destroy();
}).listen(18085, '127.0.0.1', () => log({event: 'direct-ready'}));
