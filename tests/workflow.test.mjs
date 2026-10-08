import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {unseal} from '../src/seal.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));

test('public workflows only run software tests; never execute live business scraping',()=>{
  const dir=path.join(root,'.github/workflows');
  const files=fs.readdirSync(dir).filter(x=>x.endsWith('.yml')||x.endsWith('.yaml'));
  assert.ok(files.length>=1);
  for(const item of files){
    const yaml=fs.readFileSync(path.join(dir,item),'utf8');
    assert.match(yaml,/runs-on: ubuntu-24\.04/);
    assert.match(yaml,/github\.event\.repository\.private == false/);
    assert.doesNotMatch(yaml,/self-hosted|\bschedule:|\bcron:|OPENAI_API_KEY|DATABASE_URL|SENDGRID_API_KEY|pull_request:\s*/i);
    assert.match(yaml,/permissions:\n  contents: read/);
    assert.doesNotMatch(yaml,/--mode live|discover_overture\.py|upload-artifact|ENABLE_NETWORK_AUDIT/);
  }
});

test('offline smoke outputs encrypted fixture, no network and no plaintext artifact',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'public-directory-offline-'));
  fs.mkdirSync(path.join(dir,'examples'));
  const keys=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
  fs.writeFileSync(path.join(dir,'public-key.pem'),keys.publicKey);
  fs.copyFileSync(path.join(root,'examples/synthetic-candidates.jsonl'),path.join(dir,'examples/synthetic-candidates.jsonl'));
  const result=spawnSync(process.execPath,[path.join(root,'bin/pipeline.mjs'),
    '--mode','smoke','--input','examples/synthetic-candidates.jsonl','--output','sealed-report.json','--limit','10'],
    {cwd:dir,encoding:'utf8',timeout:5000});
  assert.equal(result.status,0,result.stderr);
  const raw=fs.readFileSync(path.join(dir,'sealed-report.json'),'utf8');
  assert.ok(!raw.includes('Synthetic Example'));
  const report=unseal(JSON.parse(raw),keys.privateKey);
  assert.equal(report.items.length,2);
  assert.equal(report.sendAuthorized,false);
  assert.equal(report.verifiedSendable,0);
  assert.equal(report.items[0].status,'SYNTHETIC_OFFLINE_NO_SITE_CHECK');
  assert.match(result.stdout,/ENCRYPTED_PUBLIC_DIRECTORY_REPORT/);
  fs.rmSync(dir,{recursive:true,force:true});
});

test('live scanning cannot run without explicit isolated public-repository opt-in',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'public-directory-deny-'));
  fs.mkdirSync(path.join(dir,'examples'));
  const keys=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
  fs.writeFileSync(path.join(dir,'public-key.pem'),keys.publicKey);
  fs.copyFileSync(path.join(root,'examples/synthetic-candidates.jsonl'),path.join(dir,'examples/synthetic-candidates.jsonl'));
  const result=spawnSync(process.execPath,[path.join(root,'bin/pipeline.mjs'),
    '--mode','live','--input','examples/synthetic-candidates.jsonl','--output','sealed-report.json','--limit','10'],
    {cwd:dir,encoding:'utf8',timeout:5000,env:{...process.env,ENABLE_NETWORK_AUDIT:'false'}});
  assert.notEqual(result.status,0);
  assert.match(result.stderr,/LIVE_AUDIT_NOT_APPROVED/);
  fs.rmSync(dir,{recursive:true,force:true});
});

test('approved live research still refuses to visit any website without an external encryption key',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'public-directory-live-key-'));
  fs.writeFileSync(path.join(dir,'candidates.jsonl'),JSON.stringify({
    id:'1',name:'Synthetic-only record',url:'https://example.com',source:'OVERTURE_PUBLIC'
  })+'\n');
  const result=spawnSync(process.execPath,[path.join(root,'bin/pipeline.mjs'),
    '--mode','live','--input','candidates.jsonl','--output','sealed-report.json','--limit','10'],{
      cwd:dir,encoding:'utf8',timeout:5000,env:{
        ...process.env,ENABLE_NETWORK_AUDIT:'false',GITHUB_ACTIONS:'false',
        ISOLATED_RESEARCH_APPROVED:'true',
        AUDIT_APPROVAL_PHRASE:'I_APPROVE_PERMITTED_LINUX_RESEARCH',
        RESEARCH_PUBLIC_KEY_PATH:''
      }
    });
  assert.notEqual(result.status,0);
  assert.match(result.stderr,/LIVE_PUBLIC_KEY_NOT_CONFIGURED/);
  assert.equal(fs.existsSync(path.join(dir,'sealed-report.json')),false);
  fs.rmSync(dir,{recursive:true,force:true});
});
