import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {seal,unseal} from '../src/seal.mjs';

test('envelope uses hybrid authenticated encryption and never includes raw candidate names',()=>{
  const keys=crypto.generateKeyPairSync('rsa',{modulusLength:2048,
    publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
  const report={items:[{name:'Private Example',email:'private@example.org',url:'https://studio.org'}],sendAuthorized:false};
  const env=seal(report,keys.publicKey);
  assert.ok(!JSON.stringify(env).includes('Private Example'));
  assert.ok(!JSON.stringify(env).includes('private@example.org'));
  assert.deepEqual(unseal(env,keys.privateKey),report);
  const altered={...env,tag:'AAAA'+env.tag.slice(4)};
  assert.throws(()=>unseal(altered,keys.privateKey));
  assert.throws(()=>unseal(env,crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}}).privateKey));
});
