const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const script=fs.readFileSync(path.join(__dirname,'../src/Kaevo.Plugin.KaevoForJellyfin/Configuration/configPage.html'),'utf8').match(/<script type="text\/javascript">([\s\S]*?)<\/script>/)[1];
function fixture(){
 const nodes=new Map(),reads=[],writes=[];
 function node(id){if(!nodes.has(id))nodes.set(id,{events:{},disabled:false,textContent:'',addEventListener(k,f){this.events[k]=f}});return nodes.get(id);}
 const context={document:{querySelector:node},window:{},console,Date:class extends Date{static now(){return 1800000000000}},ApiClient:{getPluginConfiguration:id=>new Promise((resolve,reject)=>reads.push({id,resolve,reject})),updatePluginConfiguration:(id,config)=>new Promise((resolve,reject)=>writes.push({id,config,resolve,reject}))}};
 vm.createContext(context);vm.runInContext(script,context);
 return {context,node,reads,writes,settle:()=>new Promise(r=>setImmediate(r))};
}
test('capture reads fresh settings, changes only expiry, and confirms one write',async()=>{
 const f=fixture(),run=f.context.captureNextPlayback(); await f.context.captureNextPlayback();assert.equal(f.reads.length,1);
 f.reads[0].resolve({Enabled:true,PrivateSetting:'keep',PlaybackDiagnosticExpiresAtUnixSeconds:0});await f.settle();
 assert.deepEqual(JSON.parse(JSON.stringify(f.writes[0].config)),{Enabled:true,PrivateSetting:'keep',PlaybackDiagnosticExpiresAtUnixSeconds:1800000300});
 f.writes[0].resolve();await f.settle();assert.doesNotMatch(f.node('#KaevoPlaybackDiagnosticStatus').textContent,/Capture armed/);
 f.reads[1].resolve({PlaybackDiagnosticExpiresAtUnixSeconds:1800000300});await run;
 assert.match(f.node('#KaevoPlaybackDiagnosticStatus').textContent,/Capture armed/);assert.equal(f.writes.length,1);assert.equal(f.node('#KaevoCapturePlayback').disabled,false);
});
test('lost write response uses readback and never repeats the write',async()=>{
 const f=fixture(),run=f.context.captureNextPlayback();f.reads[0].resolve({Enabled:false});await f.settle();f.writes[0].reject(Error('lost reply'));await f.settle();f.reads[1].resolve({PlaybackDiagnosticExpiresAtUnixSeconds:1800000300});await run;assert.equal(f.writes.length,1);assert.match(f.node('#KaevoPlaybackDiagnosticStatus').textContent,/Capture armed/);
});
test('failed read never writes stale settings or claims a capture',async()=>{
 const f=fixture(),run=f.context.captureNextPlayback();f.reads[0].reject(Error('offline'));await f.settle();f.reads[1].reject(Error('offline'));await run;assert.equal(f.writes.length,0);assert.match(f.node('#KaevoPlaybackDiagnosticStatus').textContent,/could not be confirmed/);
});
test('mismatched readback does not report armed',async()=>{
 const f=fixture(),run=f.context.captureNextPlayback();f.reads[0].resolve({});await f.settle();f.writes[0].resolve();await f.settle();f.reads[1].resolve({PlaybackDiagnosticExpiresAtUnixSeconds:0});await run;assert.doesNotMatch(f.node('#KaevoPlaybackDiagnosticStatus').textContent,/Capture armed/);
});
