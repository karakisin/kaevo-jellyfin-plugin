const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const html=fs.readFileSync(path.join(__dirname,'../src/Kaevo.Plugin.KaevoForJellyfin/Configuration/configPage.html'),'utf8');
const script=html.match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];
function fixture(){
 const nodes=new Map(), timers=new Map(),requests=[];let tick=0,now=0;
 function node(id){if(!nodes.has(id))nodes.set(id,{hidden:false,disabled:false,textContent:'',dataset:{},events:{},setAttribute(){},removeAttribute(k){this.removed=k},querySelector(){return node(id+' span')},addEventListener(k,f){this.events[k]=f}});return nodes.get(id)}
 const c={document:{querySelector:node},window:{},navigator:{},console,Date:class extends Date{static now(){return now}},setInterval:()=>++tick,clearInterval(){},setTimeout:f=>{timers.set(++tick,f);return tick},clearTimeout:id=>timers.delete(id),ApiClient:{getUrl:(p,q)=>({p,q}),getJSON:url=>new Promise((resolve,reject)=>requests.push({url,resolve,reject}))}};
 vm.createContext(c);vm.runInContext(script,c);c.KaevoConfig.pairingV3Enabled=true;c.KaevoConfig.pairingV3Connected=true;
 return {c,node,requests,timers,advance:()=>{now+=300001},async settle(){await new Promise(r=>setImmediate(r))},next(){const [id,f]=timers.entries().next().value;timers.delete(id);f()}};
}
test('existing pairing cannot complete a fresh repair; exact completion clears QR',async()=>{
 const f=fixture(),id='a'.repeat(64);f.c.monitorPairingTicket(id);
 f.requests.shift().resolve({MonitorId:id,TicketState:'waiting',State:'paired'});await f.settle();assert.equal(f.node('#KaevoPairingTicket').hidden,false);
 f.next();f.requests.shift().resolve({MonitorId:id,TicketState:'pending',State:'paired'});await f.settle();assert.match(f.node('#KaevoPairingExpiry').textContent,/Confirming/);
 f.next();f.requests.shift().resolve({MonitorId:id,TicketState:'completed',State:'paired'});await f.settle();assert.equal(f.node('#KaevoPairingTicket').hidden,true);assert.equal(f.node('#KaevoPairingQr').removed,'src');assert.equal(f.timers.size,0);assert.match(f.node('#CloudSetupMessage').textContent,/completed successfully/);
});
test('late response from replaced QR cannot claim success',async()=>{const f=fixture();f.c.monitorPairingTicket('a'.repeat(64));const old=f.requests.shift();f.c.monitorPairingTicket('b'.repeat(64));old.resolve({MonitorId:'a'.repeat(64),TicketState:'completed',State:'paired'});await f.settle();assert.equal(f.node('#KaevoPairingTicket').hidden,false);assert.equal(f.c.KaevoConfig.pairingMonitorId,'b'.repeat(64));});
test('failed status reads stop at deadline without claiming success',async()=>{const f=fixture();f.c.monitorPairingTicket('a'.repeat(64));f.advance();f.requests.shift().reject(Error('offline'));await f.settle();assert.match(f.node('#KaevoPairingExpiry').textContent,/could not be read/);assert.equal(f.timers.size,0);assert.equal(f.c.KaevoConfig.pairingV3Connected,true);});
test('leaving page invalidates pending completion response',async()=>{const f=fixture();const id='a'.repeat(64);f.c.monitorPairingTicket(id);f.node('#KaevoConfigPage').events.pagehide();f.requests.shift().resolve({MonitorId:id,TicketState:'completed',State:'paired'});await f.settle();assert.equal(f.node('#KaevoPairingTicket').hidden,false);assert.equal(f.timers.size,0);});
