import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {loadConfig} from './config.mjs';
import {connectDatabase} from './database.mjs';
import {createPhotoStore} from './photos.mjs';
import {importRecords} from './import-records.mjs';
import {createOfficeServer} from './server.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
test('rescue import, photo round-trip, concurrent recurrence and restart persistence',async t=>{
 const folder=mkdtempSync(join(tmpdir(),'vco-migrate-'));mkdirSync(join(folder,'photos'));
 const config={...loadConfig(),schema:'office_test_'+randomBytes(8).toString('hex'),recoveryFile:join(folder,'private-passwords.json')};
 const admin=randomUUID(),staff=randomUUID(),photo=randomUUID(),task=randomUUID(),attendance=randomUUID(),registration=randomUUID();
 const jpeg=Buffer.concat([Buffer.from([255,216]),Buffer.alloc(100,1),Buffer.from([255,217])]);
 const data={employees:[{id:admin,name:'Test Admin',email:'migrationadmin@example.test',department:'Admin',title:'Admin',role:'Admin'},{id:staff,name:'Test Staff',email:'migrationstaff@example.test',department:'Office',title:'Staff',role:'Employee'}],registrations:[{id:registration,name:'Pending Staff',email:'pending@example.test',department:'Office',title:'Staff',role:'Employee',status:'Pending',created_at:'2026-01-01T00:00:00Z'}],attendance:[{id:attendance,owner:staff,date:'2026-01-01',in:'1767243600000',out:'1767247200000',inProof:{photo},source:'server'}],tasks:[{id:task,owner:staff,title:'Monthly work',due:'2026-01-31',assignedOn:'2026-01-01',status:'To do',assignmentPhoto:photo}],leave:[],announcements:[],notifications:[]};
 const raw=Buffer.from(JSON.stringify(data));writeFileSync(join(folder,'records.json'),raw);writeFileSync(join(folder,'photos',photo+'.jpg'),jpeg);
 writeFileSync(join(folder,'manifest.json'),JSON.stringify({photosExpected:1,photosDownloaded:1,failedPhotos:[],files:[{name:'records.json',sha256:hash(raw)},{name:'photos/'+photo+'.jpg',sha256:hash(jpeg)}]}));
 let server;
 async function stop(){if(server){await new Promise(r=>server.close(r));server=null;}}
 t.after(async()=>{await stop();const db=await connectDatabase(config);try{const store=createPhotoStore(config,db);for(const p of await db.prepare('SELECT object_key FROM photos').all())await store.remove(p.object_key);assert.match(config.schema,/^office_test_[a-f0-9]{16}$/);await db.exec(`DROP SCHEMA ${config.schema} CASCADE`);}finally{await db.close();rmSync(folder,{recursive:true,force:true});}});
 const imported=await importRecords(folder,config);assert.equal(imported.employees,2);assert.equal(imported.photos,1);
 assert.equal((await importRecords(folder,config)).alreadyImported,true);
 const creds=JSON.parse(readFileSync(config.recoveryFile,'utf8'));
 async function start(){server=await createOfficeServer({config});await new Promise(r=>server.listen(0,'127.0.0.1',r));return 'http://127.0.0.1:'+server.address().port;}
 let base=await start();
 async function req(path,token,body){const r=await fetch(base+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});return {status:r.status,value:r.headers.get('content-type').includes('json')?await r.json():Buffer.from(await r.arrayBuffer())};}
 const login=await req('/api/login',null,{email:creds[staff].email,password:creds[staff].password});assert.equal(login.status,200);const token=login.value.token;
 assert.equal((await req('/api/photos/'+photo,token)).value.toString('hex'),jpeg.toString('hex'));
 const concurrent=await Promise.all([1,2].map(()=>req('/api/action',token,{op:'task_status',args:{id:task,status:'Done'}})));assert.deepEqual(concurrent.map(r=>r.status),[200,200]);
 let state=(await req('/api/state',token)).value;assert.equal(state.tasks.filter(r=>r.previousTaskId===task).length,1);
 await stop();base=await start();state=(await req('/api/state',token)).value;assert.equal(state.attendance.length,1);assert.equal(state.tasks.length,2);assert.equal((await req('/api/photos/'+photo,token)).value.toString('hex'),jpeg.toString('hex'));
 const bad=await req('/api/photos/'+photo);assert.equal(bad.status,401);
 await stop();
 const db=await connectDatabase(config);try{await db.exec('DELETE FROM sessions');}finally{await db.close();}
 // An export with corrupted media must be rejected before any database writes.
 writeFileSync(join(folder,'photos',photo+'.jpg'),'corrupt');await assert.rejects(importRecords(folder,config),/checksum/);
});
