import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID,randomBytes} from 'node:crypto';
import fs from 'node:fs';
import {handlePrivateStoreRequest} from '../src/cloudflare-private-gateway.mjs';
import {RESERVE_SQL,FIND_RESERVATION_SQL,STORE_SQL,FIND_REPORT_SQL,validRequestId,validateSealedEnvelope}
 from '../src/cloudflare-private-ledger.mjs';
import worker from '../src/cloudflare-pilot.mjs';

const AUTH='a'.repeat(48)+'b'.repeat(4);
const HASH=createHash('sha256').update(AUTH).digest('hex');
const KEYID='f'.repeat(64);
const TIME='2026-10-08T12:00:00.000Z';
const ACCESS_AUD='cf-access-audience-id-for-test-0123456789';
const ACCESS_EMAIL='owner@example.com';
const ACCESS_CONTEXT={access:{aud:ACCESS_AUD,getIdentity:async()=>({email:ACCESS_EMAIL})}};
function envelope(cipher='private ciphertext'){
 return {
  version:1,format:'RSA-3072-OAEP-SHA256+AES-256-GCM',keyId:KEYID,
  encryptedKey:btoa('k'.repeat(384)),
  iv:btoa('i'.repeat(12)),tag:btoa('t'.repeat(16)),
  ciphertext:btoa(cipher)
 };
}
class FakeD1 {
 constructor(){this.slots=new Map();this.reports=new Map();this.calls=0;this.fail=false;}
 prepare(sql){
  const db=this;
  return {bind(...args){return {async first(){
   db.calls++;
   if(db.fail)throw new Error('CONFIDENTIAL_SQL_ERROR: secret content');
   if(sql===RESERVE_SQL){
    const [id,day,created,checkDay,limit,dup]=args;
    assert.equal(day,checkDay);assert.equal(id,dup);assert.equal(typeof created,'string');
    if(db.slots.has(id)||[...db.slots.values()].filter(x=>x.day_utc===day).length>=limit)return null;
    const row={request_id:id,day_utc:day};
    db.slots.set(id,row);return {request_id:id};
   }
   if(sql===FIND_RESERVATION_SQL)return db.slots.get(args[0])||null;
   if(sql===STORE_SQL){
    const [id,payload,digest,created,lookup]=args;
    assert.equal(id,lookup);
    assert.equal(typeof created,'string');
    const res=db.slots.get(id);
    if(!res||db.reports.has(id))return null;
    db.reports.set(id,{request_id:id,day_utc:res.day_utc,payload_json:payload,payload_sha256:digest});
    return {request_id:id};
   }
   if(sql===FIND_REPORT_SQL)return db.reports.get(args[0])||null;
   throw new Error('Unknown SQL '+sql);
  }}}};
 }
}
function environment(db=new FakeD1(),limit='2'){
 return {DB:db,STORAGE_ONLY_ENABLED:'I_UNDERSTAND_PRIVATE_STORAGE_ONLY',
  AUTH_TOKEN_SHA256:HASH,PUBLIC_KEY_FINGERPRINT:KEYID,MAX_REQUESTS_PER_DAY:limit,
  ACCESS_AUD,ACCESS_ALLOWED_EMAIL:ACCESS_EMAIL};
}
function req(method,path,data,token=AUTH){
 const headers=token?{Authorization:'Bearer '+token}:{};
 let body;
 if(data!==undefined){headers['Content-Type']='application/json';body=typeof data==='string'?data:JSON.stringify(data);}
 return new Request('https://pilot.example'+path,{method,headers,body});
}
const now=()=>new Date(TIME);
async function invoke(env,method,path,data,token=AUTH,context=ACCESS_CONTEXT){
 const response=await handlePrivateStoreRequest(req(method,path,data,token),env,{now,context});
 return {response,result:await response.json()};
}
test('public Cloudflare pilot is still limited to static health and never imports private gateway',async()=>{
 const src=fs.readFileSync(new URL('../src/cloudflare-pilot.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(src,/cloudflare-private-(?:gateway|ledger)/);
 for(const route of ['/internal/v1/reservations','/internal/v1/envelopes/'+randomUUID()]){
  const res=await worker.fetch(req('GET',route));
  assert.equal(res.status,404);
 }
});
test('private gateway fails closed with missing, malformed, or unintended configuration',async()=>{
 const bad=[
  {...environment(),DB:null},
  {...environment(),AUTH_TOKEN_SHA256:'x'},
  {...environment(),PUBLIC_KEY_FINGERPRINT:null},
  {...environment(),MAX_REQUESTS_PER_DAY:'100'},
  {...environment(),MAX_REQUESTS_PER_DAY:'0'},
  {...environment(),STORAGE_ONLY_ENABLED:'true'}
 ];
 for(const env of bad){
  const {response,result}=await invoke(env,'POST','/internal/v1/reservations',{requestId:randomUUID()});
  assert.equal(response.status,503);assert.equal(result.code,'PRIVATE_STORAGE_NOT_CONFIGURED');
 }
});
test('auth token is required for all private routes and none reflect confidential input',async()=>{
 const env=environment(),id=randomUUID();
 for(const token of [null,'wrong','f'.repeat(48)]){
  const {response,result}=await invoke(env,'POST','/internal/v1/reservations',{requestId:id},token);
  assert.equal(response.status,401);assert.equal(result.code,'UNAUTHORIZED');
  assert.equal(JSON.stringify(result).includes(AUTH),false);
 }
 assert.equal(env.DB.calls,0);
});
test('a reservation consumes one atomic quota slot and repeated requests are idempotent',async()=>{
 const env=environment(),ids=[randomUUID(),randomUUID(),randomUUID()];
 const first=await invoke(env,'POST','/internal/v1/reservations',{requestId:ids[0]});
 assert.equal(first.response.status,201);assert.equal(first.result.code,'RESERVED');
 assert.equal(first.result.sendAuthorized,false);
 const repeat=await invoke(env,'POST','/internal/v1/reservations',{requestId:ids[0]});
 assert.equal(repeat.response.status,200);assert.equal(repeat.result.code,'ALREADY_RESERVED');
 assert.equal((await invoke(env,'POST','/internal/v1/reservations',{requestId:ids[1]})).response.status,201);
 const exhausted=await invoke(env,'POST','/internal/v1/reservations',{requestId:ids[2]});
 assert.equal(exhausted.response.status,429);assert.equal(exhausted.result.code,'DAILY_LIMIT');
 assert.equal(env.DB.slots.size,2);
});
test('idempotent UUID cannot be reused on another day',async()=>{
 const env=environment(),id=randomUUID();
 assert.equal((await invoke(env,'POST','/internal/v1/reservations',{requestId:id})).response.status,201);
 const next=await handlePrivateStoreRequest(req('POST','/internal/v1/reservations',{requestId:id}),env,{
  now:()=>new Date('2026-10-09T00:01:00.000Z'),context:ACCESS_CONTEXT
 });
 assert.equal(next.status,409);assert.equal((await next.json()).code,'ID_REUSED_ANOTHER_DAY');
});
test('encrypted report requires reserved ID and correct configured public key fingerprint',async()=>{
 const env=environment(),id=randomUUID();
 assert.equal((await invoke(env,'POST','/internal/v1/envelopes',{requestId:id,envelope:envelope()})).response.status,409);
 await invoke(env,'POST','/internal/v1/reservations',{requestId:id});
 const wrong=envelope();wrong.keyId='a'.repeat(64);
 assert.equal((await invoke(env,'POST','/internal/v1/envelopes',{requestId:id,envelope:wrong})).response.status,400);
 assert.equal(env.DB.reports.size,0);
 const ok=await invoke(env,'POST','/internal/v1/envelopes',{requestId:id,envelope:envelope()});
 assert.equal(ok.response.status,201);assert.equal(ok.result.code,'STORED_ENCRYPTED');
 assert.equal(env.DB.reports.size,1);
 assert.equal([...env.DB.reports.values()][0].payload_json.includes('"ciphertext"'),true);
});
test('identical encrypted report retry is safe but altered content cannot overwrite an earlier result',async()=>{
 const env=environment(),id=randomUUID();
 await invoke(env,'POST','/internal/v1/reservations',{requestId:id});
 await invoke(env,'POST','/internal/v1/envelopes',{requestId:id,envelope:envelope('A')});
 const again=await invoke(env,'POST','/internal/v1/envelopes',{requestId:id,envelope:envelope('A')});
 assert.equal(again.response.status,200);assert.equal(again.result.code,'ALREADY_STORED_ENCRYPTED');
 const alter=await invoke(env,'POST','/internal/v1/envelopes',{requestId:id,envelope:envelope('B')});
 assert.equal(alter.response.status,409);assert.equal(alter.result.code,'CONFLICTING_ENVELOPE');
 assert.equal(env.DB.reports.size,1);
});
test('reports are returned as encrypted envelopes only and never publicly disclosed',async()=>{
 const env=environment(),id=randomUUID();
 await invoke(env,'POST','/internal/v1/reservations',{requestId:id});
 await invoke(env,'POST','/internal/v1/envelopes',{requestId:id,envelope:envelope()});
 const noAuth=await invoke(env,'GET','/internal/v1/envelopes/'+id,undefined,null);
 assert.equal(noAuth.response.status,401);
 const done=await invoke(env,'GET','/internal/v1/envelopes/'+id);
 assert.equal(done.response.status,200);
 assert.deepEqual(done.result.envelope,envelope());
 assert.equal(done.result.sendAuthorized,false);
 assert.equal(done.response.headers.get('cache-control'),'no-store');
 assert.equal(done.response.headers.has('access-control-allow-origin'),false);
 assert.equal(done.response.headers.get('x-content-type-options'),'nosniff');
});
test('strict body parsing rejects excess, malformed JSON, unexpected fields and plaintext',async()=>{
 const env=environment(),id=randomUUID();
 for(const bad of [
  {requestId:id,site:'https://private.example'},
  {requestId:'invalid'},
  {requestId:id,plaintext:'name@example.com'},
  '{"requestId":',
  JSON.stringify({requestId:id,padding:'x'.repeat(18000)})
 ]){
  const r=await invoke(env,'POST','/internal/v1/reservations',bad);
  assert.equal(r.response.status,400);
 }
 const noType=new Request('https://pilot.example/internal/v1/reservations',{
  method:'POST',headers:{authorization:'Bearer '+AUTH},body:'{"requestId":"'+id+'"}'
 });
 const result=await handlePrivateStoreRequest(noType,env,{now,context:ACCESS_CONTEXT});
 assert.equal(result.status,400);
 assert.equal(env.DB.slots.size,0);
});
test('malformed ciphertext, unknown keys, wrong crypto lengths cannot be stored',async()=>{
 const env=environment(),id=randomUUID();
 await invoke(env,'POST','/internal/v1/reservations',{requestId:id});
 for(const bad of [
  {...envelope(),plaintext:'confidential'},
  {...envelope(),encryptedKey:btoa('k'.repeat(128))},
  {...envelope(),iv:btoa('i'.repeat(11))},
  {...envelope(),tag:btoa('t'.repeat(15))},
  {...envelope(),ciphertext:btoa('z'.repeat(8193))},
  {...envelope(),ciphertext:'!!!'}
 ]){
  assert.equal(validateSealedEnvelope(bad,KEYID),false);
  assert.equal((await invoke(env,'POST','/internal/v1/envelopes',{requestId:id,envelope:bad})).response.status,400);
 }
 assert.equal(env.DB.reports.size,0);
});
test('GET, scan parameters, unknown routes and method mismatches never trigger a storage write',async()=>{
 const env=environment(),id=randomUUID();
 for(const [method,path] of [
  ['GET','/scan?url=https://bad.example'],
  ['POST','/internal/v1/envelopes?url=https://bad.example'],
  ['POST','/internal/v1/reservations?url=https://bad.example'],
  ['GET','/internal/v1/envelopes/'+encodeURIComponent('../secrets')],
 ]){
  const r=await invoke(env,method,path);
  assert.equal(r.response.status,404);
 }
 const m=await invoke(env,'GET','/internal/v1/reservations');
 assert.equal(m.response.status,405);
 assert.equal(env.DB.slots.size,0);assert.equal(env.DB.reports.size,0);
});
test('database errors do not leak internal SQL, payloads, or configuration to callers',async()=>{
 const env=environment();env.DB.fail=true;
 const r=await invoke(env,'POST','/internal/v1/reservations',{requestId:randomUUID()});
 assert.equal(r.response.status,503);
 assert.deepEqual(r.result,{ok:false,code:'PRIVATE_STORAGE_UNAVAILABLE',sendAuthorized:false});
});
test('source files contain no direct outbound requests, cron configuration or public D1 binding',()=>{
 const src=fs.readFileSync(new URL('../src/cloudflare-private-gateway.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(src,/await\s+fetch\s*\(|globalThis\.fetch\s*\(/);
 assert.doesNotMatch(src,/console\.(?:log|error)|fetchImpl/);
 const config=JSON.parse(fs.readFileSync(new URL('../wrangler.jsonc',import.meta.url),'utf8'));
 assert.equal(config.main,'src/cloudflare-pilot.mjs');
 assert.equal(Object.hasOwn(config,'d1_databases'),false);
 assert.equal(Object.hasOwn(config,'triggers'),false);
});

test('Access must authenticate the exact Worker audience and owner email before D1 or bearer processing',async()=>{
  const db=new FakeD1(),env=environment(db),id=randomUUID();
  const contexts=[
    null,{access:{}},
    {access:{aud:'another-app',getIdentity:async()=>({email:ACCESS_EMAIL})}},
    {access:{aud:ACCESS_AUD,getIdentity:async()=>({email:'wrong@example.com'})}},
    {access:{aud:ACCESS_AUD,getIdentity:async()=>{throw Error('access service failed');}}}
  ];
  for(const context of contexts){
    const res=await invoke(env,'POST','/internal/v1/reservations',{requestId:id},AUTH,context);
    assert.equal(res.response.status,403);
    assert.equal(res.result.code,'CLOUDFLARE_ACCESS_REQUIRED');
  }
  assert.equal(db.calls,0);
  const tampered={...env,ACCESS_ALLOWED_EMAIL:'*'};
  const res=await invoke(tampered,'POST','/internal/v1/reservations',{requestId:id});
  assert.equal(res.response.status,403);
  assert.equal(db.calls,0);
});
