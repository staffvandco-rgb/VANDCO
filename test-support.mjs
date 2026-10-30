import {randomBytes} from 'node:crypto';
import {createOfficeServer} from './server.mjs';
import {loadConfig} from './config.mjs';
import {connectDatabase} from './database.mjs';
import {createPhotoStore} from './photos.mjs';
export async function testServer(t,options={}){
 const config={...loadConfig(),schema:'office_test_'+randomBytes(8).toString('hex')};
 const server=await createOfficeServer({...options,config});
 t.after(async()=>{await new Promise(r=>server.close(r));const db=await connectDatabase(config);try{const store=createPhotoStore(config,db);for(const p of await db.prepare('SELECT object_key FROM photos').all())await store.remove(p.object_key);if(!/^office_test_[a-f0-9]{16}$/.test(config.schema))throw new Error('Unsafe test cleanup');await db.exec(`DROP SCHEMA ${config.schema} CASCADE`);}finally{await db.close();}});
 return server;
}
