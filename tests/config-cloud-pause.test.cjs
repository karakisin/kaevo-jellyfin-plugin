const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const script=fs.readFileSync(path.join(__dirname,'../src/Kaevo.Plugin.KaevoForJellyfin/Configuration/configPage.html'),'utf8').match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];
function fixture(){
 const nodes=new Map(),requests=[],posts=[],timers=new Map();let counter=0,now=0;
 function node(id){if(!nodes.has(id))nodes.set(id,{events:{},disabled:false,hidden:false,textContent:'',dataset:{},querySelector(){return node(id+" span")},removeAttribute(){},addEventListener(k,f){this.events[k]=f}});return nodes.get(id);}
 const c={document:{querySelector:node},window:{},navigator:{},console,Date:class extends Date{static now(){return now}},clearInterval(){},clearTimeout:i=>timers.delete(i),setTimeout:f=>{timers.set(++counter,f);return counter},ApiClient:{getUrl:p=>p,getJSON:p=>new Promise((resolve,reject)=>requests.push({p,resolve,reject})),ajax:p=>new Promise((resolve,reject)=>posts.push({p,resolve,reject}))}};
 vm.createContext(c);vm.runInContext(script,c);
 return {c,node,requests,posts,timers,async settle(){await new Promise(r=>setImmediate(r))},next(){const [i,f]=timers.entries().next().value;timers.delete(i);f()},expire(){now=90001}};
}
test('saved pause setting does not claim requests stopped; waits for owner and zero sockets',async()=>{
 const f=fixture();f.c.changeCloudControl(false);assert.equal(f.posts.length,1);f.posts[0].resolve();await f.settle();
 f.requests.shift().resolve({Enabled:false,Paused:false,RelayChannels:0});await f.settle();assert.doesNotMatch(f.node('#KaevoCloudControlStatus').textContent,/have stopped/);
 f.next();f.requests.shift().resolve({Enabled:false,Paused:true,RelayChannels:1});await f.settle();assert.doesNotMatch(f.node('#KaevoCloudControlStatus').textContent,/have stopped/);
 f.next();f.requests.shift().resolve({Enabled:false,Paused:true,RelayChannels:0});await f.settle();assert.match(f.node('#KaevoCloudControlStatus').textContent,/have stopped/);assert.equal(f.timers.size,0);assert.equal(f.posts.length,1);
});
test('lost pause response is reconciled with reads, never resubmitted',async()=>{
 const f=fixture();f.c.changeCloudControl(false);f.posts[0].reject(Error('lost'));await f.settle();f.requests.shift().resolve({Enabled:false,Paused:true,RelayChannels:0});await f.settle();assert.equal(f.posts.length,1);assert.match(f.node('#KaevoCloudControlStatus').textContent,/pairing is saved/);
});
test('timeout never claims stopped or enables a blind resume',async()=>{
 const f=fixture();f.c.changeCloudControl(false);f.posts[0].resolve();await f.settle();f.expire();f.requests.shift().reject(Error('offline'));await f.settle();assert.match(f.node('#KaevoCloudControlStatus').textContent,/could not be confirmed/);assert.equal(f.node('#KaevoResumeCloud').disabled,true);assert.equal(f.timers.size,0);
});
test('leaving the page invalidates late confirmation',async()=>{
 const f=fixture();f.c.changeCloudControl(false);f.posts[0].resolve();await f.settle();f.node('#KaevoConfigPage').events.pagehide();f.requests.shift().resolve({Enabled:false,Paused:true,RelayChannels:0});await f.settle();assert.doesNotMatch(f.node('#KaevoCloudControlStatus').textContent,/have stopped/);assert.equal(f.timers.size,0);
});
test('pause status read failure does not erase successful pairing status',async()=>{
 const f=fixture();f.node('#CloudConnectorStatus').textContent='Kaevo App Connected';const p=f.c.loadCloudControl();f.requests.shift().reject(Error('offline'));await p;assert.equal(f.node('#CloudConnectorStatus').textContent,'Kaevo App Connected');assert.match(f.node('#KaevoCloudControlStatus').textContent,/could not be read/);
});
test('migration is offered only after confirmed pause and before Firebase selection',()=>{
 const f=fixture();f.c.renderCloudControl({Enabled:true,Paused:false,RelayChannels:0});assert.equal(f.node('#KaevoMigrateFirebase').hidden,true);
 f.c.renderCloudControl({Enabled:false,Paused:true,RelayChannels:0,FirebaseSelected:false});assert.equal(f.node('#KaevoMigrateFirebase').disabled,false);
 f.c.renderCloudControl({Enabled:false,Paused:true,RelayChannels:0,FirebaseSelected:true});assert.equal(f.node('#KaevoMigrateFirebase').hidden,true);
});
test('lost migration response reads status without retry or claiming playback',async()=>{
 const f=fixture();f.c.renderCloudControl({Enabled:false,Paused:true,RelayChannels:0});f.c.migrateFirebase();
 assert.equal(f.posts.length,1);assert.equal(f.posts[0].p.headers['X-Kaevo-Admin-Action'],'lifecycle');assert.equal(f.node('#KaevoResumeCloud').disabled,true);
 f.posts[0].reject(Error('lost'));await f.settle();f.requests.shift().resolve({Enabled:false,Paused:true,RelayChannels:0,FirebaseSelected:true});await f.settle();
 assert.equal(f.posts.length,1);assert.match(f.node('#KaevoMigrationStatus').textContent,/playback has not been verified/);
});
