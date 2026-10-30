export function createPhotoStore(config,db){
 const base=new URL(config.projectUrl);if(base.protocol!=='https:')throw new Error('Storage requires HTTPS');
 const headers={apikey:config.storageKey,...(config.storageKey.startsWith('sb_secret_')?{}:{Authorization:'Bearer '+config.storageKey})};
 const root=base.origin+'/storage/v1';
 async function request(path,options={}){const r=await fetch(root+path,{...options,headers:{...headers,...options.headers},redirect:'error',signal:AbortSignal.timeout(45000)});if(!r.ok){const e=new Error('Private photo storage request failed');e.status=502;throw e;}return r;}
 const objectPath=key=>'/object/'+encodeURIComponent(config.bucket)+'/'+key.split('/').map(encodeURIComponent).join('/');
 return {
  async verify(){const b=await(await request('/bucket/'+encodeURIComponent(config.bucket))).json();if(b.public!==false)throw new Error('Photo bucket must be private');},
  async save(id,owner,bytes){const key=config.schema+'/'+id+'.bin';await request(objectPath(key),{method:'POST',headers:{'Content-Type':'application/octet-stream','x-upsert':'false'},body:bytes});const cleanup=()=>request('/object/'+encodeURIComponent(config.bucket),{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({prefixes:[key]})});db.onRollback(cleanup);try{await db.prepare('INSERT INTO photos VALUES(?,?,?)').run(id,owner,key);}catch(e){await cleanup().catch(()=>{});throw e;}},
  async read(key){return Buffer.from(await(await request(objectPath(key))).arrayBuffer());},
  async remove(key){await request('/object/'+encodeURIComponent(config.bucket),{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({prefixes:[key]})});}
 };
}
