// Local Node.js-only bridge for previously encrypted reports.
// NOT imported by the Cloudflare Worker. No private key is loaded here.
import {createHash,createPublicKey} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {validateSealedEnvelope} from './cloudflare-private-ledger.mjs';

const SAMPLE_PUBLIC_KEY=readFileSync(new URL('../public-key.pem',import.meta.url),'utf8').trim();

export function fingerprintForLivePublicKey(pem){
  if(typeof pem!=='string'||!pem.includes('-----BEGIN PUBLIC KEY-----'))throw new Error('PUBLIC_KEY_INVALID');
  if(pem.trim()===SAMPLE_PUBLIC_KEY)throw new Error('PUBLIC_REPOSITORY_TEST_KEY_DENIED');
  let key;
  try{key=createPublicKey(pem);}catch{throw new Error('PUBLIC_KEY_INVALID');}
  if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails?.modulusLength!==3072){
    throw new Error('RSA_3072_REQUIRED');
  }
  const spki=key.export({type:'spki',format:'der'});
  return createHash('sha256').update(spki).digest('hex');
}

export function addLiveKeyFingerprint(sealed,pem){
  if(!sealed||typeof sealed!=='object'||Array.isArray(sealed)||
    Object.keys(sealed).sort().join(',')!=='ciphertext,encryptedKey,format,iv,tag,version'){
    throw new Error('SEALED_INPUT_INVALID');
  }
  const keyId=fingerprintForLivePublicKey(pem);
  const tagged={...sealed,keyId};
  if(!validateSealedEnvelope(tagged,keyId))throw new Error('SEALED_CRYPTO_FORMAT_INVALID');
  return tagged;
}
