import {createCipheriv,createDecipheriv,createHash,randomBytes} from 'node:crypto';
export async function encryption(config,db){
 if(!/^[a-f0-9]{64}$/i.test(config.encryptionKey))throw new Error('Set a persistent OFFICE_ENCRYPTION_KEY');
 const key=Buffer.from(config.encryptionKey,'hex'),fingerprint=createHash('sha256').update(key).digest('hex');
 await db.transaction(async()=>{
  const row=await db.prepare("SELECT value FROM drive_store WHERE key='encryption-fingerprint'").get();
  if(row&&JSON.parse(row.value)!==fingerprint)throw new Error('Encryption key differs from existing records. Restore the original key.');
  if(!row)await db.prepare('INSERT INTO drive_store VALUES(?,?)').run('encryption-fingerprint',JSON.stringify(fingerprint));
 });
 return {key,
  encrypt(bytes){const iv=randomBytes(12),c=createCipheriv('aes-256-gcm',key,iv),cipher=Buffer.concat([c.update(bytes),c.final()]);return Buffer.concat([iv,c.getAuthTag(),cipher]);},
  decrypt(bytes){bytes=Buffer.from(bytes);const d=createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));d.setAuthTag(bytes.subarray(12,28));return Buffer.concat([d.update(bytes.subarray(28)),d.final()]);}
 };
}
