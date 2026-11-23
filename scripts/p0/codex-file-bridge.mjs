// Temporary lab transport. Host opens only the authorized loopback proxy.
// Guest NIC stays disabled. Payload bytes are never printed or interpreted.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
const [mode, suppliedRoot, leaseArgument='240000', portArgument='0'] = process.argv.slice(2);
const leaseMs=Number(leaseArgument),listenPort=Number(portArgument);
if(![240000,300000,900000].includes(leaseMs)||!Number.isInteger(listenPort)||listenPort<0||listenPort>65535)throw Error('Invalid bounded lease/port');
const connectionLimit=leaseMs===900000?1024:256;
const root = path.resolve(suppliedRoot ?? '.');
if (!['host','guest'].includes(mode)) throw Error('Expected host or guest');
if (mode === 'host') {
  const allowed = path.resolve('.local/p0/sandbox') + path.sep;
  if (!root.startsWith(allowed) || !/[\\/]results[\\/]proxy-bridge(?:-[a-f0-9]{8})?$/.test(root)) throw Error('Project temporary results required');
} else if (!/^c:\\p0results\\proxy-bridge(?:-[a-f0-9]{8})?$/.test(root.toLowerCase()) || process.env.PROXY_HARBOR_P0_GUEST !== 'offline-lab') throw Error('Fixed offline guest required');
fs.mkdirSync(root,{recursive:true});
const states = new Map();
let token, activeAt = 0, totalBytes = 0, connections = 0, stopped = false, server;
const born = performance.now();
function publish(file, value) {
  const temporary = file + '.tmp-' + crypto.randomBytes(4).toString('hex');
  fs.writeFileSync(temporary,value,{flag:'wx'});fs.renameSync(temporary,file);
}
function json(file, value) { publish(path.join(root,file),JSON.stringify(value)); }
function readJSON(file) { const p=path.join(root,file);if(!fs.existsSync(p))return null;if(fs.lstatSync(p).isSymbolicLink()||fs.statSync(p).size>2048)throw Error('Invalid metadata');return JSON.parse(fs.readFileSync(p,'utf8')); }
function finish(reason) {
  if(stopped)return;stopped=true;
  for(const state of states.values())state.socket.destroy();
  if(server)server.close();
  if(mode==='host')json('host-stopped.json',{reason,connections,totalBytes});
  console.log(JSON.stringify({event:'stopped',mode,reason,connections,totalBytes}));
  clearInterval(timer);
}
function attach(id, socket, folder) {
  const state={socket,folder,send:0,receive:0,pending:[],published:[],canWrite:true,ended:false,remoteEnd:false,bytes:0};
  const outgoing=mode==='host'?'h':'g',incoming=mode==='host'?'g':'h';
  state.tick=()=>{
    state.published=state.published.filter(file=>fs.existsSync(file));
    while(state.pending.length && state.published.length<4){
      const file=path.join(folder,outgoing+String(state.send++).padStart(8,'0')+'.bin');
      publish(file,state.pending.shift());state.published.push(file);
    }
    if(state.pending.length||state.published.length>=4)socket.pause();else socket.resume();
    if(state.ended&&!state.pending.length&&!state.endWritten){publish(path.join(folder,outgoing+'-end.json'),JSON.stringify({next:state.send}));state.endWritten=true;}
    for(let count=0;count<4&&state.canWrite&&!socket.destroyed;count++){
      const file=path.join(folder,incoming+String(state.receive).padStart(8,'0')+'.bin');
      if(!fs.existsSync(file))break;
      const info=fs.lstatSync(file);if(!info.isFile()||info.isSymbolicLink()||info.size>65536)throw Error('Invalid packet');
      const data=fs.readFileSync(file);fs.unlinkSync(file);state.receive++;
      state.canWrite=socket.write(data);
    }
    const end=path.join(folder,incoming+'-end.json');
    if(!state.remoteEnd&&fs.existsSync(end)&&fs.statSync(end).size<128){const next=JSON.parse(fs.readFileSync(end,'utf8')).next;if(next===state.receive){state.remoteEnd=true;socket.end();}}
    if(fs.existsSync(path.join(folder,'abort-'+(mode==='host'?'guest':'host'))))socket.destroy();
  };
  socket.on('data',data=>{
    state.bytes+=data.length;totalBytes+=data.length;
    if(totalBytes>256*1024*1024){finish('byte_limit');return;}
    if(state.bytes>32*1024*1024){
      console.log(JSON.stringify({event:'connection_byte_limit',mode}));socket.destroy();return;
    }
    for(let offset=0;offset<data.length;offset+=65536)state.pending.push(data.subarray(offset,offset+65536));
    if(state.pending.length>32){socket.destroy();return;}
    state.tick();
  });
  socket.on('drain',()=>{state.canWrite=true;});
  socket.on('end',()=>{state.ended=true;});
  socket.on('error',()=>{});
  socket.on('close',()=>{try{publish(path.join(folder,'abort-'+mode),'closed');}catch{}states.delete(id);});
  socket.setTimeout(45000,()=>socket.destroy());
  states.set(id,state);
}
if(mode==='host'){
  if(fs.existsSync(path.join(root,'control.json')))throw Error('Fresh bridge root required');
  token=crypto.randomBytes(32).toString('hex');json('control.json',{schemaVersion:1,token,leaseMs});
  console.log(JSON.stringify({event:'waiting',mode,upstream:'127.0.0.1:10808',leaseMs}));
}
const seen=new Set();
const timer=setInterval(()=>{
  try{
    if(stopped)return;
    if(!activeAt&&performance.now()-born>900000){finish('readiness_timeout');return;}
    if(mode==='host'&&!activeAt){const ready=readJSON('guest-ready.json');if(ready?.token===token){activeAt=performance.now();json('host-active.json',{leaseMs});}}
    if(mode==='guest'&&!server){
      const control=readJSON('control.json');if(!control)return;
      if(!/^[a-f0-9]{64}$/.test(control.token)||control.leaseMs!==leaseMs)throw Error('Invalid control');
      token=control.token;
      if(!fs.existsSync(path.join(root,'guest-ready.json')))json('guest-ready.json',{token});
      if(!readJSON('host-active.json'))return;
      activeAt=performance.now();
      server=net.createServer({allowHalfOpen:true},socket=>{
        if(states.size>=32||connections>=connectionLimit){socket.destroy();return;}
        connections++;
        const id=crypto.randomBytes(12).toString('hex'),folder=path.join(root,id);fs.mkdirSync(folder);
        publish(path.join(folder,'open.json'),JSON.stringify({token}));attach(id,socket,folder);
      });
      server.listen(listenPort,'127.0.0.1',()=>console.log(JSON.stringify({event:'listening',address:'127.0.0.1:'+server.address().port,leaseMs})));
    }
    if(mode==='guest'&&readJSON('host-stopped.json')){finish('host_stopped');return;}
    if(activeAt&&performance.now()-activeAt>=leaseMs){finish('lease_expired');return;}
    if(mode==='host'&&activeAt){
      for(const entry of fs.readdirSync(root,{withFileTypes:true})){
        if(!/^[a-f0-9]{24}$/.test(entry.name)||seen.has(entry.name)||!entry.isDirectory()||entry.isSymbolicLink())continue;
        const folder=path.join(root,entry.name),open=path.join(folder,'open.json');if(!fs.existsSync(open))continue;
        if(!fs.realpathSync(folder).startsWith(fs.realpathSync(root)+path.sep)||fs.lstatSync(open).isSymbolicLink()||fs.statSync(open).size>256)throw Error('Invalid connection path');
        seen.add(entry.name);
        if(JSON.parse(fs.readFileSync(open,'utf8')).token!==token)throw Error('Wrong session');
        if(states.size>=32||connections>=connectionLimit){publish(path.join(folder,'abort-host'),'limit');continue;}
        connections++;
        const socket=net.connect({host:'127.0.0.1',port:10808,allowHalfOpen:true});attach(entry.name,socket,folder);
      }
    }
    for(const state of states.values())state.tick();
  }catch{finish('bridge_error');}
},20);
process.on('SIGINT',()=>finish('interrupted'));
