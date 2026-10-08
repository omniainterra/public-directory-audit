import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,generateKeyPairSync} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {seal,unseal} from '../src/seal.mjs';
import {fingerprintForLivePublicKey,addLiveKeyFingerprint} from '../src/cloudflare-envelope-bridge.mjs';
import {validateSealedEnvelope} from '../src/cloudflare-private-ledger.mjs';

const ROOT=fileURLToPath(new URL('../',import.meta.url));
const pair=generateKeyPairSync('rsa',{
 modulusLength:3072,
 publicKeyEncoding:{type:'spki',format:'pem'},
 privateKeyEncoding:{type:'pkcs8',format:'pem'}
});
const synthetic={record:'SYNTHETIC_ONLY_SECRET',sendAuthorized:false};

test('RSA-3072 SPKI fingerprint matches independent hash and preserves decryptability',()=>{
 const data=seal(synthetic,pair.publicKey);
 const wrapped=addLiveKeyFingerprint(data,pair.publicKey);
 const der=createPublicKey(pair.publicKey).export({type:'spki',format:'der'});
 assert.equal(wrapped.keyId,createHash('sha256').update(der).digest('hex'));
 assert.equal(validateSealedEnvelope(wrapped,wrapped.keyId),true);
 assert.deepEqual(unseal(wrapped,pair.privateKey),synthetic);
 assert.equal(JSON.stringify(wrapped).includes('SYNTHETIC_ONLY_SECRET'),false);
});

test('sample public key, unsupported key size and invalid envelope fail closed',()=>{
 const sample=fs.readFileSync(path.join(ROOT,'public-key.pem'),'utf8');
 assert.throws(()=>fingerprintForLivePublicKey(sample),/TEST_KEY|RSA_3072/);
 const small=generateKeyPairSync('rsa',{
  modulusLength:2048,
  publicKeyEncoding:{type:'spki',format:'pem'},
  privateKeyEncoding:{type:'pkcs8',format:'pem'}
 });
 assert.throws(()=>fingerprintForLivePublicKey(small.publicKey),/RSA_3072_REQUIRED/);
 assert.throws(()=>fingerprintForLivePublicKey('untrusted data'),/PUBLIC_KEY_INVALID/);
 assert.throws(()=>addLiveKeyFingerprint({...seal(synthetic,pair.publicKey),plaintext:'test'},pair.publicKey),/SEALED_INPUT_INVALID/);
});

test('private envelope command fails closed inside GitHub Actions',()=>{
 const script=path.join(ROOT,'scripts/prepare-private-envelope.mjs');
 const r=spawnSync(process.execPath,[script,'ignored','ignored','ignored'],{
  encoding:'utf8',timeout:5000,env:{...process.env,GITHUB_ACTIONS:'true'}
 });
 assert.notEqual(r.status,0);
 assert.match(r.stderr,/GITHUB_ACTIONS_PRIVATE_DATA_BLOCKED/);
});

test('private envelope bridge writes encrypted-only output outside repository and never overwrites',()=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'public-audit-envelope-'));
 try{
  const input=path.join(temp,'sealed.json');
  const pem=path.join(temp,'independent.pem');
  const output=path.join(temp,'complete.json');
  fs.writeFileSync(input,JSON.stringify(seal(synthetic,pair.publicKey)));
  fs.writeFileSync(pem,pair.publicKey);
  const script=path.join(ROOT,'scripts/prepare-private-envelope.mjs');
  const args=[script,input,pem,output];
  const options={encoding:'utf8',timeout:5000,env:{...process.env,GITHUB_ACTIONS:'false'}};
  const r=spawnSync(process.execPath,args,options);
  assert.equal(r.status,0,r.stderr);
  const payload=fs.readFileSync(output,'utf8');
  assert.equal(payload.includes('SYNTHETIC_ONLY_SECRET'),false);
  const envelope=JSON.parse(payload);
  assert.equal(validateSealedEnvelope(envelope,envelope.keyId),true);
  assert.deepEqual(unseal(envelope,pair.privateKey),synthetic);
  assert.equal(fs.statSync(output).mode&0o777,0o600);
  const repeat=spawnSync(process.execPath,args,options);
  assert.notEqual(repeat.status,0);
  assert.match(repeat.stderr,/EEXIST/);
  const repoOutput=path.join(ROOT,'FORBIDDEN_PRIVATE_ENVELOPE.json');
  const bad=spawnSync(process.execPath,[script,input,pem,repoOutput],options);
  assert.notEqual(bad.status,0);
  assert.match(bad.stderr,/PUBLIC_REPOSITORY_DATA_PATH_DENIED/);
  assert.equal(fs.existsSync(repoOutput),false);
 }finally{
  fs.rmSync(temp,{recursive:true,force:true});
 }
});
