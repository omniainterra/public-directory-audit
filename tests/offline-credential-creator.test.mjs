import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {webcrypto,createHash,publicEncrypt,privateDecrypt,constants,createPublicKey} from 'node:crypto';
import {fingerprintForLivePublicKey} from '../src/cloudflare-envelope-bridge.mjs';
const html=fs.readFileSync(new URL('../tools/offline-credential-creator.html',import.meta.url),'utf8');
function evaluate(){
  const js=/<script id="offline-key-script">([\s\S]*?)<\/script>/.exec(html)?.[1];
  assert.ok(js,'no inline script');
  const sandbox={TextEncoder,Uint8Array,btoa,crypto:webcrypto};
  vm.runInNewContext(js,sandbox,{timeout:2000});
  assert.equal(typeof sandbox.generateCredentials,'function');
  return sandbox;
}
test('credential creator is a single offline file with no remote imports, network or storage',()=>{
  assert.match(html,/connect-src 'none'/);
  assert.match(html,/form-action 'none'/);
  assert.match(html,/object-src 'none'/);
  assert.match(html,/window\.location\.protocol!=='file:'/);
  assert.match(html,/type="checkbox"/);
  assert.doesNotMatch(html,/<script[^>]*\bsrc=/i);
  assert.doesNotMatch(html,/<(?:iframe|img)\b/i);
  const js=/<script id="offline-key-script">([\s\S]*?)<\/script>/.exec(html)[1];
  assert.doesNotMatch(js,/\b(?:fetch|XMLHttpRequest|WebSocket|sendBeacon|localStorage|sessionStorage|indexedDB|EventSource)\b/);
  assert.doesNotMatch(html,/ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/);
});
test('trusted local credential generation does not demand Wi-Fi disconnection',()=>{
  assert.doesNotMatch(html,/id="offline"/);
  assert.doesNotMatch(html,/select\('offline'\)/);
  assert.doesNotMatch(html,/インターネット接続を切断済み/);
  assert.match(html,/id="trusted"/);
  assert.match(html,/connect-src 'none'/);
  assert.match(html,/window\.location\.protocol!=='file:'/);
});
test('WebCrypto RSA-3072 public/private key and strong bearer token are interoperable',async()=>{
  const app=evaluate();
  const bundle=await app.generateCredentials(webcrypto);
  assert.match(bundle.token,/^[A-Za-z0-9_-]{64}$/);
  assert.match(bundle.tokenSha256,/^[a-f0-9]{64}$/);
  assert.equal(bundle.tokenSha256,createHash('sha256').update(bundle.token).digest('hex'));
  assert.match(bundle.publicFingerprint,/^[a-f0-9]{64}$/);
  assert.equal(bundle.publicFingerprint,fingerprintForLivePublicKey(bundle.publicPem));
  assert.match(bundle.publicPem,/-----BEGIN PUBLIC KEY-----/);
  assert.match(bundle.privatePem,/-----BEGIN PRIVATE KEY-----/);
  assert.equal(createPublicKey(bundle.publicPem).asymmetricKeyDetails.modulusLength,3072);
  const message=Buffer.from('synthetic-only-no-private-customer-data');
  const ciphertext=publicEncrypt({key:bundle.publicPem,oaepHash:'sha256',padding:constants.RSA_PKCS1_OAEP_PADDING},message);
  const plaintext=privateDecrypt({key:bundle.privatePem,oaepHash:'sha256',padding:constants.RSA_PKCS1_OAEP_PADDING},ciphertext);
  assert.deepEqual(plaintext,message);
});
test('credential creator refuses insecure or unavailable random APIs',async()=>{
  const app=evaluate();
  await assert.rejects(()=>app.generateCredentials(null),/安全な暗号生成機能/);
  await assert.rejects(()=>app.generateCredentials({getRandomValues() {}}),/安全な暗号生成機能/);
});
