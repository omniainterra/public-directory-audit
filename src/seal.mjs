import crypto from 'node:crypto';

export function seal(report,publicPem){
  const key=crypto.randomBytes(32),iv=crypto.randomBytes(12);
  const plaintext=Buffer.from(JSON.stringify(report),'utf8');
  if(plaintext.byteLength>240000)throw new Error('REPORT_EXCEEDS_STORAGE_CAP');
  const cipher=crypto.createCipheriv('aes-256-gcm',key,iv);
  const ciphertext=Buffer.concat([cipher.update(plaintext),cipher.final()]);
  const encryptedKey=crypto.publicEncrypt({key:publicPem,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},key);
  return {
    version:1,format:'RSA-3072-OAEP-SHA256+AES-256-GCM',
    encryptedKey:encryptedKey.toString('base64'),
    iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),
    ciphertext:ciphertext.toString('base64')
  };
}
export function unseal(envelope,privatePem){
  if(envelope?.version!==1||envelope?.format!=='RSA-3072-OAEP-SHA256+AES-256-GCM')throw new Error('ENVELOPE_INVALID');
  const key=crypto.privateDecrypt({key:privatePem,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},Buffer.from(envelope.encryptedKey,'base64'));
  const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(envelope.iv,'base64'));
  decipher.setAuthTag(Buffer.from(envelope.tag,'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext,'base64')),decipher.final()]).toString('utf8'));
}
