import http from 'node:http';
if(process.cwd().toLowerCase()!=='c:\\p0lab'||process.env.PROXY_HARBOR_P0_GUEST!=='offline-lab')throw Error('Disposable guest only');
const server=http.createServer((request,response)=>{
  if(request.url!=='/p0-callback-test'){response.writeHead(404);response.end();return;}
  console.log(JSON.stringify({event:'loopback_callback_observed'}));
  response.writeHead(200,{'Content-Type':'text/plain','Connection':'close'});response.end('P0 loopback callback OK');
});
server.listen(0,'127.0.0.1',()=>console.log(JSON.stringify({event:'listening',port:server.address().port})));
setTimeout(()=>server.close(),60000);
