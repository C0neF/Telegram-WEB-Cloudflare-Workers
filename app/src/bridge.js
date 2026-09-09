export function bridgePage(host, bootstrap, nonce) {
  const origin = `https://${host}`;
  const csp = [
    "default-src 'none'",
    'base-uri \'none\'',
    'connect-src \'self\' wss://' + host,
    'frame-ancestors http://127.0.0.1:*',
    "script-src 'nonce-" + nonce + "'",
    "style-src 'none'",
    'object-src \'none\'',
    'worker-src \'none\'',
    'sandbox allow-same-origin allow-scripts',
  ].join('; ');
  const body = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connection</title></head>
<body>
<script nonce="${nonce}">
(()=>{
'use strict';
const relayOrigin=${JSON.stringify(origin)},bootstrap=${JSON.stringify(bootstrap)};
const fragment=location.hash,androidNonce=/^#android=([A-Za-z0-9_-]{43})$/.exec(fragment)?.[1]||'';
history.replaceState(null,'',location.pathname);
let initialized=false,closed=false,port=null,sessionToken='',socket=null,creating=false;
let sessionAbort=null;
const MAX_PENDING_BYTES=32*1024*1024,MAX_PENDING_ITEMS=4096,pending=[];
const SESSION_CREATE_BUDGET_MS=90000,SESSION_RETRY_MAX_MS=4000;
let pendingBytes=0;
const status=state=>{if(port&&!closed)port.postMessage({t:'status',state})};
const requestOptions=(method,token,body,keepalive=false)=>({
 method,body,keepalive,mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
 headers:Object.assign(token?{Authorization:'Bearer '+token}:{},body?{'Content-Type':'application/octet-stream'}:{})
});
const sleep=ms=>new Promise((resolve,reject)=>{
 const signal=sessionAbort.signal;
 if(signal.aborted){reject(new Error('session cancelled'));return}
 const cancel=()=>{clearTimeout(timer);reject(new Error('session cancelled'))};
 const timer=setTimeout(()=>{signal.removeEventListener('abort',cancel);resolve()},ms);
 signal.addEventListener('abort',cancel,{once:true});
});
function sessionRetryDelay(response,attempt){
 const header=response?.headers.get('Retry-After');
 const seconds=header===null||header===undefined||header===''?NaN:Number(header);
 if(Number.isFinite(seconds)&&seconds>=0)return Math.min(SESSION_RETRY_MAX_MS,seconds*1000);
 return Math.min(SESSION_RETRY_MAX_MS,250*(2**attempt));
}
async function requestSession(first){
 const started=Date.now();let attempt=0;
 for(;;){
  if(closed||sessionAbort.signal.aborted)throw new Error('session cancelled');
  let response;
  try{response=await fetch(relayOrigin+'/api/v1/session',Object.assign(requestOptions('POST',bootstrap,first),{signal:sessionAbort.signal}))}
  catch(error){
   if(closed||sessionAbort.signal.aborted)throw error;
   const delay=sessionRetryDelay(null,attempt++);
   if(Date.now()-started+delay>SESSION_CREATE_BUDGET_MS)throw error;
   await sleep(delay);continue
  }
  if(response.status!==503)return response;
  const delay=sessionRetryDelay(response,attempt++);
  try{await response.body?.cancel()}catch(error){}
  if(Date.now()-started+delay>SESSION_CREATE_BUDGET_MS)return response;
  await sleep(delay);
 }
}
function fail(){
 if(closed)return;
 status('failed');
 if(port)port.postMessage({t:'close'});
 close(true);
}
function close(notifyServer){
 if(closed)return;
 closed=true;
 sessionAbort?.abort();
 if(socket)try{socket.close()}catch(error){}
 if(notifyServer&&sessionToken)fetch(relayOrigin+'/api/v1/session',requestOptions('DELETE',sessionToken,null,true)).catch(()=>{});
 pending.length=0;pendingBytes=0;
 if(port)port.close();
}
function queueCarrier(data){
 if(!(data instanceof ArrayBuffer)||!data.byteLength){fail();return}
 if(!socket||socket.readyState!==WebSocket.OPEN){
  if(pendingBytes+data.byteLength>MAX_PENDING_BYTES||pending.length>=MAX_PENDING_ITEMS){fail();return}
  pending.push(data);pendingBytes+=data.byteLength;return
 }
 if(socket.bufferedAmount+data.byteLength>MAX_PENDING_BYTES){fail();return}
 try{socket.send(data)}catch(error){fail()}
}
function openWebSocket(){
 return new Promise((resolve,reject)=>{
  const target=relayOrigin.replace(/^https:/,'wss:')+'/api/v1/ws';
  socket=new WebSocket(target,'tproxy-v1.'+sessionToken);
  socket.binaryType='arraybuffer';
  socket.onopen=()=>resolve();
  socket.onmessage=event=>{
   if(!(event.data instanceof ArrayBuffer)||!event.data.byteLength){fail();return}
   port.postMessage({t:'traffic',up:0,down:event.data.byteLength});
   port.postMessage(event.data,[event.data]);
   status('connected');
  };
  socket.onerror=()=>{reject(new Error('websocket failed'));fail()};
  socket.onclose=()=>{reject(new Error('websocket closed'));if(!closed)fail()};
 });
}
async function createSession(first){
 sessionAbort=new AbortController();
 const deadline=setTimeout(()=>{sessionAbort.abort();fail()},SESSION_CREATE_BUDGET_MS);
 try{
  status('connecting');
  const response=await requestSession(first);
  if(response.status!==200||response.headers.get('X-Carrier-Mode')!=='websocket')throw new Error('session rejected');
  sessionToken=response.headers.get('X-Session-Token')||'';
  if(!/^[A-Za-z0-9_-]{43}$/.test(sessionToken))throw new Error('missing session token');
  const welcome=await response.arrayBuffer();
  if(closed)return;
  port.postMessage(welcome,[welcome]);
  await openWebSocket();
  if(closed)return;
  status('connected');
  for(const data of pending.splice(0)){pendingBytes-=data.byteLength;queueCarrier(data);if(closed)break}
 }catch(error){fail()}finally{clearTimeout(deadline)}
}
function activatePort(nextPort){
 initialized=true;port=nextPort;
 port.onmessage=message=>{
  const data=message.data;
  if(data instanceof ArrayBuffer){
   if(!creating){creating=true;createSession(data)}else queueCarrier(data);
  }else if(data&&data.t==='close')close(true);
 };
 port.start();status('connecting');
}
addEventListener('message',event=>{
 if(initialized||event.source!==parent||event.data===null||typeof event.data!=='object')return;
 const keys=Object.keys(event.data).sort();
 if(keys.length!==2||keys[0]!=='t'||keys[1]!=='v'||event.data.t!=='tproxy-init'||event.data.v!==1||event.ports.length!==1)return;
 let source;try{source=new URL(event.origin)}catch(error){return}
 if(source.protocol!=='http:'||source.hostname!=='127.0.0.1'||!source.port||source.origin!==event.origin)return;
 activatePort(event.ports[0]);
});
const androidBridge=globalThis.TelegramWebProxy;
if(!initialized&&androidNonce&&androidBridge&&typeof androidBridge.postMessage==='function'){
 const androidPort={onmessage:null,start(){},close(){androidBridge.onmessage=null},postMessage(value){
  androidBridge.postMessage(value instanceof ArrayBuffer?value:JSON.stringify(value));
 }};
 androidBridge.onmessage=event=>{
  let data=event.data;if(typeof data==='string'){try{data=JSON.parse(data)}catch(error){return}}
  if(androidPort.onmessage)androidPort.onmessage({data});
 };
 activatePort(androidPort);
 androidBridge.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce:androidNonce}));
}
addEventListener('pagehide',()=>close(true),{once:true});
})();
</script>
</body>
</html>`;
  return { body, csp };
}
