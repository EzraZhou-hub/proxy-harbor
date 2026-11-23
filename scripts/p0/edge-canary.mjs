import http from 'node:http';
import {execFile} from 'node:child_process';
if(process.cwd().toLowerCase()!=='c:\\p0lab'||process.env.PROXY_HARBOR_P0_GUEST!=='offline-lab')throw Error('Guest only');
function handle(request,response){
  const match=/^\/(edge|control)-([a-f0-9]{16})$/.exec(request.url);
  if(!match){response.writeHead(404);response.end();return;}
  const client=request.socket.remotePort,local=request.socket.localPort;
  const source='$r=Get-NetTCPConnection -LocalPort '+client+' -RemotePort '+local+' -ErrorAction Stop|Select-Object -First 1;$p=Get-CimInstance Win32_Process -Filter ("ProcessId = "+$r.OwningProcess) -Property ProcessId,ParentProcessId,ExecutablePath;@{pid=$p.ProcessId;parentPid=$p.ParentProcessId;path=$p.ExecutablePath}|ConvertTo-Json -Compress';
  execFile('powershell.exe',['-NoProfile','-Command',source],{windowsHide:true,timeout:10000,maxBuffer:4096},(error,stdout)=>{
    let owner=null;try{owner=JSON.parse(stdout.trim());}catch{}
    console.log(JSON.stringify({event:'request',kind:match[1],nonce:match[2],family:request.socket.remoteFamily,owner,ownerQuerySucceeded:!error&&Boolean(owner?.pid)}));
    response.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store','Connection':'close'});
    response.end('<html><head><title>Edge canary</title></head><body>EDGE-CANARY '+match[2]+'</body></html>');
  });
}
const v4=http.createServer(handle),v6=http.createServer(handle);
await Promise.all([
  new Promise((resolve,reject)=>{v4.once('error',reject);v4.listen(0,'127.0.0.1',resolve);}),
  new Promise((resolve,reject)=>{v6.once('error',reject);v6.listen({port:0,host:'::1',ipv6Only:true},resolve);})
]);
console.log(JSON.stringify({event:'listening',ipv4:`http://127.0.0.1:${v4.address().port}`,ipv6:`http://[::1]:${v6.address().port}`}));
