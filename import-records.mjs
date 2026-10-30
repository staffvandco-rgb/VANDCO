import {readFileSync,writeFileSync,existsSync} from 'node:fs';
import {resolve,join,sep} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash,randomBytes,scryptSync,createCipheriv,createDecipheriv} from 'node:crypto';
import {loadConfig} from './config.mjs';
import {connectDatabase,initializeSchema} from './database.mjs';
import {createPhotoStore} from './photos.mjs';
import {encryption} from './encryption.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
const parse=p=>JSON.parse(readFileSync(p,'utf8').replace(/^\uFEFF/,''));
export async function importRecords(folder,config=loadConfig()){
 folder=resolve(folder);const manifest=parse(join(folder,'manifest.json'));
 if(manifest.failedPhotos?.length||manifest.photosExpected!==manifest.photosDownloaded)throw new Error('Export has incomplete photos');
 for(const item of manifest.files){const p=resolve(folder,item.name);if(!p.startsWith(folder+sep)||hash(readFileSync(p))!==item.sha256.toLowerCase())throw new Error('Export checksum mismatch');}
 const raw=readFileSync(join(folder,'records.json'));const data=JSON.parse(raw.toString().replace(/^\uFEFF/,''));const digest=hash(raw);
 if(!data.employees?.length||!data.employees.some(u=>u.role==='Admin'))throw new Error('Export must contain an administrator');
 if(!/^[a-f0-9]{64}$/i.test(config.encryptionKey))throw new Error('Persistent encryption key required');
 const recoveryPath=config.recoveryFile||fileURLToPath(new URL('../.office-secrets/imported-account-passwords.json',import.meta.url));
 const credentials=existsSync(recoveryPath)?parse(recoveryPath):{};
 const records=[];for(const kind of ['attendance','leave','tasks','announcements','notifications'])for(const source of data[kind]||[]){const r={...source};delete r.carriedForward;delete r.assignedMonth;if(!r.id||!r.owner)throw new Error('Record identity missing');records.push({kind,r});}
 const photos=new Map();function scan(value,owner){if(!value||typeof value!=='object')return;for(const [name,v]of Object.entries(value)){if(/photo/i.test(name)&&typeof v==='string'&&/^[a-f0-9-]{36}$/i.test(v)){if(photos.has(v)&&photos.get(v)!==owner)throw new Error('Photo owner conflict');photos.set(v,owner);}else scan(v,owner);}}
 for(const {r}of records)scan(r,r.owner);
 if(photos.size!==manifest.photosExpected)throw new Error('Photo reference count mismatch');
 const accountPassword=u=>{if(!credentials[u.id])credentials[u.id]={email:u.email,password:randomBytes(24).toString('base64url')};const salt=randomBytes(16).toString('hex');return salt+':'+scryptSync(credentials[u.id].password,salt,64).toString('hex');};
 for(const u of [...data.employees,...(data.registrations||[]).filter(r=>r.status==='Pending')])accountPassword(u);
 // Persist recovery passwords before writing any accounts to the database.
 writeFileSync(recoveryPath,JSON.stringify(credentials,null,2),{mode:0o600});
 const db=await connectDatabase(config);const store=createPhotoStore(config,db);
 try{
  await initializeSchema(db,config.schema);await store.verify();
  const {encrypt,decrypt}=await encryption(config,db);
  const result=await db.transaction(async()=>{
   if(await db.prepare('SELECT digest FROM migration_imports WHERE digest=?').get(digest))return {alreadyImported:true};
   if(await db.prepare('SELECT hash FROM sessions LIMIT 1').get())throw new Error('Target has login sessions. Refusing to import into an active application.');
   const existing=await db.prepare('SELECT id FROM users LIMIT 1').get();const imported=await db.prepare('SELECT digest FROM migration_imports LIMIT 1').get();if(existing&&!imported)throw new Error('Target database is not an empty migration destination');
   for(const u of data.employees){if(!['Admin','Employee'].includes(u.role))throw new Error('Invalid user role');await db.prepare('INSERT INTO users VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,email=excluded.email,department=excluded.department,title=excluded.title,role=excluded.role').run(u.id,u.name,u.email,u.department,u.title,u.role,accountPassword(u));}
   for(const r of data.registrations||[])await db.prepare('INSERT INTO registrations VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,reviewed_by=excluded.reviewed_by,reviewed_at=excluded.reviewed_at').run(r.id,r.name,r.email,r.department,r.title,r.role,r.status==='Pending'?accountPassword(r):'',r.status,r.created_at,r.reviewed_by||null,r.reviewed_at||null);
   for(const {kind,r}of records){await db.prepare('INSERT INTO records(id,kind,owner,payload) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload').run(r.id,kind,r.owner,JSON.stringify(r));if(kind==='attendance')await db.prepare('INSERT INTO punches VALUES(?,?,?) ON CONFLICT(owner,workday) DO UPDATE SET record_id=excluded.record_id').run(r.owner,r.date,r.id);}
   for(const [id,owner] of photos){const p=await db.prepare('SELECT object_key FROM photos WHERE id=?').get(id);const bytes=readFileSync(join(folder,'photos',id+'.jpg'));if(p){if(hash(decrypt(await store.read(p.object_key)))!==hash(bytes))throw new Error('Existing photo differs from export');}else{await store.save(id,owner,encrypt(bytes));const saved=await db.prepare('SELECT object_key FROM photos WHERE id=?').get(id);if(hash(decrypt(await store.read(saved.object_key)))!==hash(bytes))throw new Error('Uploaded photo verification failed');}}
   await db.prepare('INSERT INTO migration_imports(digest) VALUES(?)').run(digest);
   return {employees:data.employees.length,registrations:(data.registrations||[]).length,attendance:(data.attendance||[]).length,tasks:(data.tasks||[]).length,photos:photos.size};
  });return result;
 }finally{await db.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){try{if(!process.argv[2])throw new Error('Provide the preserved-records directory');console.log(JSON.stringify(await importRecords(process.argv[2])));}catch(e){console.error('Import failed:',e.code||e.message);process.exitCode=1;}}
