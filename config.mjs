import {readFileSync,existsSync,writeFileSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
export function loadConfig(){
 const path=fileURLToPath(new URL('../.office-secrets/supabase.json',import.meta.url));
 const local=existsSync(path)?JSON.parse(readFileSync(path,'utf8').replace(/^\uFEFF/,'')):{};
 const keyPath=fileURLToPath(new URL('../.office-secrets/encryption-key.txt',import.meta.url));
 const certPath=fileURLToPath(new URL('./supabase-ca.crt',import.meta.url));
 if(Object.keys(local).length&&!existsSync(keyPath))writeFileSync(keyPath,randomBytes(32).toString('hex'),{flag:'wx',mode:0o600});
 return {host:process.env.PGHOST||local.databaseHost,port:Number(process.env.PGPORT||local.databasePort||5432),database:process.env.PGDATABASE||local.databaseName||'postgres',user:process.env.PGUSER||local.databaseUser,password:process.env.PGPASSWORD||local.databasePassword,
 sslCa:process.env.SUPABASE_CA_CERT||(existsSync(certPath)?readFileSync(certPath,'utf8'):undefined),schema:process.env.OFFICE_DB_SCHEMA||'office_app',projectUrl:process.env.SUPABASE_URL||local.projectUrl,storageKey:process.env.SUPABASE_SECRET_KEY||local.storageKey,bucket:process.env.PHOTO_BUCKET||local.photoBucket||'office-photos',encryptionKey:process.env.OFFICE_ENCRYPTION_KEY||(existsSync(keyPath)?readFileSync(keyPath,'utf8').trim():'')};
}
