import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import worker from '../src/cloudflare-pilot.mjs';

test('Cloudflare pilot responds only to health with no secrets',async()=>{
  const r=await worker.fetch(new Request('https://pilot.example/health'));
  assert.equal(r.status,200);
  assert.equal(r.headers.get('Cache-Control'),'no-store');
  const data=await r.json();
  assert.equal(data.ok,true);
  for(const key of ['thirdPartyNetworkEnabled','historicalDataLoaded',
    'formSubmissionEnabled','emailSendingEnabled','paidApiUsed'])assert.equal(data[key],false);
});

test('Pilot refuses all prospect/network-related endpoints and mutations',async()=>{
  for(const [method,url] of [
    ['GET','https://pilot.example/scan?url=https://site.example'],
    ['GET','https://pilot.example/?url=http://169.254.169.254'],
    ['POST','https://pilot.example/scan'],
    ['GET','https://pilot.example/healthcheck']
  ]){
    const r=await worker.fetch(new Request(url,{method}));
    assert.equal(r.status,404,method+' '+url);
  }
  const r=await worker.fetch(new Request('https://pilot.example/health',{method:'POST'}));
  assert.equal(r.status,405);
  assert.equal(r.headers.get('Allow'),'GET, HEAD');
  const head=await worker.fetch(new Request('https://pilot.example/health',{method:'HEAD'}));
  assert.equal(head.status,200);
  assert.equal(await head.text(),'');
});

test('Worker uses no schedule, storage, AI, paid binding, or external fetch',()=>{
  const config=JSON.parse(fs.readFileSync(new URL('../wrangler.jsonc',import.meta.url),'utf8'));
  assert.equal(config.main,'src/cloudflare-pilot.mjs');
  assert.equal(config.workers_dev,true);
  for(const k of ['triggers','routes','kv_namespaces','d1_databases','r2_buckets',
    'queues','durable_objects','ai','vars','unsafe'])assert.equal(Object.hasOwn(config,k),false,k);
  const source=fs.readFileSync(new URL('../src/cloudflare-pilot.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(source,/globalThis\.fetch\s*\(|await\s+fetch\s*\(|fetch\s*\(\s*['"]https?:/);
});
