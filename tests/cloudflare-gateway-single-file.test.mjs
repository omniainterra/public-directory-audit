import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash,randomUUID} from 'node:crypto';
import standalone from '../deploy/cloudflare-private-gateway-single-file.mjs';

const url='https://gateway.example';
const validId=randomUUID();
const bearer='Z'.repeat(50);
const AUTH_SHA=createHash('sha256').update(bearer).digest('hex');
const env={DB:{prepare(){throw Error('Database must not be touched without permission');}},
  AUTH_TOKEN_SHA256:AUTH_SHA, PUBLIC_KEY_FINGERPRINT:'b'.repeat(64),
  MAX_REQUESTS_PER_DAY:'1', STORAGE_ONLY_ENABLED:'I_UNDERSTAND_PRIVATE_STORAGE_ONLY'};
test('Standalone Cloudflare gateway health returns only static safety fields',async()=>{
  const reply=await standalone.fetch(new Request(url+'/health'),{});
  assert.equal(reply.status,200);
  const v=await reply.json();
  assert.equal(v.mode,'private-storage-only');
  for(const field of ['thirdPartyNetworkEnabled','historicalDataLoaded','formSubmissionEnabled','emailSendingEnabled','paidApiUsed'])assert.equal(v[field],false);
  assert.equal(reply.headers.get('Cache-Control'),'no-store');
  const head=await standalone.fetch(new Request(url+'/health',{method:'HEAD'}),{});
  assert.equal(head.status,200);
  assert.equal(await head.text(),'');
});
test('Standalone cannot use D1 before secrets/explicit storage-only enablement',async()=>{
  const req=new Request(url+'/internal/v1/reservations',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({requestId:validId})});
  const result=await standalone.fetch(req,{DB:env.DB});
  assert.equal(result.status,503);
  assert.equal((await result.json()).code,'PRIVATE_STORAGE_NOT_CONFIGURED');
});
test('Standalone never accepts public or invalid credentials for private storage',async()=>{
  for(const token of [null, 'wrong',bearer+'wrong']){
    const h=token?{'authorization':'Bearer '+token}:{};
    const r=await standalone.fetch(new Request(url+'/internal/v1/reservations',{method:'POST',headers:{...h,'content-type':'application/json'},body:JSON.stringify({requestId:validId})}),env);
    assert.equal(r.status,401);
    assert.equal((await r.json()).code,'UNAUTHORIZED');
  }
});
test('Standalone has no arbitrary remote URL, emails, SQL query or scan endpoints',async()=>{
 for(const path of ['/','/scan?url=https://somewhere.example','/query','/api/send','/internal/v1/reservations?url=https://example.org']){
   const r=await standalone.fetch(new Request(url+path),env);
   assert.equal(r.status,404,path);
 }
 const source=fs.readFileSync(new URL('../deploy/cloudflare-private-gateway-single-file.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(source,/^import\s/m);
 assert.doesNotMatch(source,/globalThis\.fetch\s*\(|await\s+fetch\s*\(/);
 assert.doesNotMatch(source,/(?:cloudflare:|process\.env|PRIVATE KEY-----|console\.log|console\.error)/);
});
