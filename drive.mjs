import {randomBytes,randomUUID,createHash,scryptSync,createCipheriv,createDecipheriv} from 'node:crypto';
import {gzipSync,gunzipSync} from 'node:zlib';

const API='https://www.googleapis.com/drive/v3';
const UPLOAD='https://www.googleapis.com/upload/drive/v3/files';
const EXPECTED='staffvandco@gmail.com';
const hash=s=>createHash('sha256').update(s).digest('hex');
const fail=(message,status=400)=>{const e=new Error(message);e.status=status;throw e;};
const quote=s=>String(s).replaceAll('\\','\\\\').replaceAll("'","\\'");
const MAGIC=Buffer.from('OFFICEHUB1\n');

export function sealBackup(snapshot,password){
    if(typeof password!=='string'||password.length<20)fail('A recovery password of at least 20 characters is required before Drive backup.');
    const salt=randomBytes(16),iv=randomBytes(12),key=scryptSync(password,salt,32),c=createCipheriv('aes-256-gcm',key,iv);
    const bytes=Buffer.concat([c.update(gzipSync(Buffer.from(JSON.stringify(snapshot)))),c.final()]);
    return Buffer.concat([MAGIC,salt,iv,c.getAuthTag(),bytes]);
}
export function openBackup(bytes,password){
    bytes=Buffer.from(bytes);if(bytes.length<70||!bytes.subarray(0,MAGIC.length).equals(MAGIC))fail('Not an OfficeHub backup.');
    let offset=MAGIC.length;const salt=bytes.subarray(offset,offset+=16),iv=bytes.subarray(offset,offset+=12),tag=bytes.subarray(offset,offset+=16);
    const d=createDecipheriv('aes-256-gcm',scryptSync(password,salt,32),iv);d.setAuthTag(tag);
    return JSON.parse(gunzipSync(Buffer.concat([d.update(bytes.subarray(offset)),d.final()])).toString('utf8'));
}

export async function createDriveService({db,encrypt,decrypt,snapshot,config={},fetcher=fetch}){
    const read=async (key,fallback=null)=>{const r=(await db.prepare('SELECT value FROM drive_store WHERE key=?').get(key));return r?JSON.parse(r.value):fallback;};
    const write=async (key,value)=>(await db.prepare('INSERT INTO drive_store VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,JSON.stringify(value)));
    const secret=async ()=>{const r=(await read('connection'));return r?JSON.parse(decrypt(Buffer.from(r,'base64')).toString()):null;};
    const saveSecret=async s=>(await write('connection',encrypt(Buffer.from(JSON.stringify(s))).toString('base64')));
    const env={clientId:config.clientId??process.env.GOOGLE_CLIENT_ID,clientSecret:config.clientSecret??process.env.GOOGLE_CLIENT_SECRET,redirectUri:config.redirectUri??process.env.GOOGLE_REDIRECT_URI,recovery:config.recovery??process.env.DRIVE_BACKUP_PASSWORD};
    let workspace=(await read('workspace'));if(!workspace){workspace=randomUUID();(await write('workspace',workspace));}
    let closed=false,running=false,queued=null;
    const controller=new AbortController();
    const configured=()=>!!(env.clientId&&env.clientSecret&&env.redirectUri);
    const status=async ()=>{const values=Object.fromEntries((await db.prepare('SELECT key,value FROM drive_store').all()).map(r=>[r.key,JSON.parse(r.value)]));let connected=false;try{connected=!!(values.connection&&JSON.parse(decrypt(Buffer.from(values.connection,'base64')).toString()).refreshToken);}catch{}return {configured:configured(),connected,account:connected?EXPECTED:'',expectedAccount:EXPECTED,backupReady:typeof env.recovery==='string'&&env.recovery.length>=20,pending:(values.revision??0)!==(values.syncedRevision??-1),syncing:running,lastSync:values.lastSync||'',lastError:values.error||'',folderId:values.folderId||''};};
    async function http(url,options={}){
        const timeout=AbortSignal.timeout(45000);const r=await fetcher(url,{...options,redirect:'error',signal:AbortSignal.any([controller.signal,timeout])});
        if(!r.ok){let detail='';try{detail=(await r.json()).error?.status||'';}catch{}const e=new Error(r.status===401?'Google authorization expired. Connect Drive again.':r.status===403?'Google Drive denied access or has insufficient storage.':r.status===404?'A Drive item is missing. Retry synchronization.':'Google Drive request failed. Please retry.');e.status=r.status;e.googleStatus=detail;throw e;}return r;
    }
    async function token(){const s=(await secret());if(!s?.refreshToken)fail('Connect Google Drive first.');if(s.accessToken&&s.expires>Date.now()+60000)return s.accessToken;
        const r=await http('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:env.clientId,client_secret:env.clientSecret,refresh_token:s.refreshToken,grant_type:'refresh_token'}).toString()});const t=await r.json();s.accessToken=t.access_token;s.expires=Date.now()+(t.expires_in||3600)*1000;(await saveSecret(s));return s.accessToken;
    }
    async function api(path,options={}){return http(API+path,{...options,headers:{Authorization:'Bearer '+await token(),...(options.headers||{})}});}
    async function begin(actor){
        if(!configured())fail('Your administrator must configure Google OAuth for OfficeHub first.',503);
        if(!(await status()).backupReady)fail('Configure the private Drive backup recovery password first.',503);
        const redirect=new URL(env.redirectUri);if(redirect.protocol!=='https:'&&!(redirect.protocol==='http:'&&['localhost','127.0.0.1'].includes(redirect.hostname)))fail('The Google redirect address must use HTTPS.',503);
        const state=randomBytes(32).toString('base64url'),verifier=randomBytes(32).toString('base64url');
        (await db.prepare('DELETE FROM drive_auth WHERE expires<?').run(Date.now()));
        (await db.prepare('INSERT INTO drive_auth VALUES(?,?,?)').run(hash(state),encrypt(Buffer.from(JSON.stringify({actor,verifier}))),Date.now()+600000));
        const u=new URL('https://accounts.google.com/o/oauth2/v2/auth');u.search=new URLSearchParams({client_id:env.clientId,redirect_uri:env.redirectUri,response_type:'code',scope:'https://www.googleapis.com/auth/drive.file',access_type:'offline',prompt:'consent select_account',login_hint:EXPECTED,state,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'}).toString();return {url:u.toString()};
    }
    async function callback(params){
        const state=params.get('state')||'';const row=(await db.prepare('SELECT secret,expires FROM drive_auth WHERE hash=?').get(hash(state)));if(!row||row.expires<Date.now())fail('This Google connection request expired. Start again.');
        (await db.prepare('DELETE FROM drive_auth WHERE hash=?').run(hash(state)));
        if(params.get('error'))fail('Google connection was not approved.');
        const code=params.get('code');if(!code)fail('Google did not return an authorization code.');
        const pending=JSON.parse(decrypt(row.secret).toString());
        const actor=(await db.prepare('SELECT role FROM users WHERE id=?').get(pending.actor));if(actor?.role!=='Admin')fail('Administrator access is no longer available.',403);
        const r=await http('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:env.clientId,client_secret:env.clientSecret,code,grant_type:'authorization_code',redirect_uri:env.redirectUri,code_verifier:pending.verifier}).toString()});const t=await r.json();
        if(!t.access_token||!t.refresh_token)fail('Google did not grant persistent access. Connect again and approve the requested access.');
        const about=await (await http(API+'/about?fields=user(emailAddress)',{headers:{Authorization:'Bearer '+t.access_token}})).json();
        if(about.user?.emailAddress?.toLowerCase()!==EXPECTED)fail('Connect only '+EXPECTED+'. No files were uploaded to the selected account.',403);
        (await saveSecret({refreshToken:t.refresh_token,accessToken:t.access_token,expires:Date.now()+(t.expires_in||3600)*1000}));(await write('error',''));(await markDirty());return {connected:true,account:EXPECTED};
    }
    async function find(q){const r=await api('/files?'+new URLSearchParams({q,fields:'files(id)',pageSize:'10'}));return (await r.json()).files?.[0]?.id;}
    async function folder(){
        let id=(await read('folderId',''));if(id){try{const r=await api('/files/'+encodeURIComponent(id)+'?fields=id,trashed');if(!(await r.json()).trashed)return id;}catch(e){if(e.status!==404)throw e;}}
        id=await find(`trashed=false and mimeType='application/vnd.google-apps.folder' and appProperties has { key='officehubWorkspace' and value='${quote(workspace)}' }`);
        if(!id){const r=await api('/files?fields=id',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'OfficeHub',mimeType:'application/vnd.google-apps.folder',appProperties:{officehubWorkspace:workspace}})});id=(await r.json()).id;}
        (await write('folderId',id));(await db.prepare('DELETE FROM drive_files').run());return id;
    }
    async function upload(parent,key,name,mime,bytes){
        let id=(await db.prepare('SELECT id FROM drive_files WHERE key=?').get(key))?.id;
        if(!id)id=await find(`'${quote(parent)}' in parents and trashed=false and appProperties has { key='officehubKey' and value='${quote(key)}' }`);
        const access=await token();const meta={name,appProperties:{officehubKey:key,officehubWorkspace:workspace},...(id?{}:{parents:[parent]})};
        let response;
        try{response=await http(UPLOAD+(id?'/'+encodeURIComponent(id):'')+'?uploadType=resumable&fields=id',{method:id?'PATCH':'POST',headers:{Authorization:'Bearer '+access,'Content-Type':'application/json','X-Upload-Content-Type':mime,'X-Upload-Content-Length':String(bytes.length)},body:JSON.stringify(meta)});}catch(e){if(id&&e.status===404){(await db.prepare('DELETE FROM drive_files WHERE key=?').run(key));return upload(parent,key,name,mime,bytes);}throw e;}
        const location=response.headers.get('location');if(!location)fail('Google did not return an upload session.',502);const session=new URL(location);if(session.protocol!=='https:'||!(session.hostname==='www.googleapis.com'||session.hostname==='content.googleapis.com'))fail('Unexpected Google upload endpoint.',502);
        const done=await http(location,{method:'PUT',headers:{Authorization:'Bearer '+access,'Content-Type':mime,'Content-Length':String(bytes.length)},body:bytes});const value=await done.json();
        if(!value.id)fail('Google did not confirm the uploaded file.',502);(await db.prepare('INSERT INTO drive_files VALUES(?,?) ON CONFLICT(key) DO UPDATE SET id=excluded.id').run(key,value.id));return value.id;
    }
    async function sync(){
        if(closed||running)return;running=true;let revision;
        try{
            const s=await status();if(!s.connected)return;if(!s.backupReady){await write('error','Backup recovery password is missing.');return;}revision=await read('revision',0);
            const data=await snapshot();const parent=await folder();const media=[];
            for(const p of data.photos){const key='photo:'+p.id;let id=(await db.prepare('SELECT id FROM drive_files WHERE key=?').get(key))?.id;
                if(id){try{const existing=await (await api('/files/'+encodeURIComponent(id)+'?fields=id,trashed')).json();if(existing.trashed){(await db.prepare('DELETE FROM drive_files WHERE key=?').run(key));id=null;}}catch(e){if(e.status!==404)throw e;(await db.prepare('DELETE FROM drive_files WHERE key=?').run(key));id=null;}}
                if(!id)id=await upload(parent,key,`selfie-${p.id}.jpg`,'image/jpeg',p.bytes);
                media.push({photo:p.id,owner:p.owner,driveFileId:id});
            }
            await upload(parent,'records','officehub-records.json','application/json',Buffer.from(JSON.stringify({...data.publicRecords,media},null,2)));
            const day=new Date().toISOString().slice(0,10);await upload(parent,'backup:'+day,`officehub-backup-${day}.ohb`,'application/octet-stream',sealBackup(data.backup,env.recovery));
            if(!closed){(await write('syncedRevision',revision));(await write('lastSync',new Date().toISOString()));(await write('error',''));}
        }catch(e){if(!closed)(await write('error',e.message||'Google Drive synchronization failed.'));}finally{running=false;}
    }
    const logFailure=e=>console.error('Drive background job:',e.code||e.name);
    async function requestSync(){if(closed)return;await write('error','');if(!queued)queued=setTimeout(()=>{queued=null;void sync().catch(logFailure);},1000);queued?.unref();return await status();}
    async function markDirty(){await db.exec("INSERT INTO drive_store VALUES('revision','1') ON CONFLICT(key) DO UPDATE SET value=((drive_store.value::bigint)+1)::text");if((await status()).connected)await requestSync();}
    const timer=setInterval(()=>{void (async()=>{const s=await status();if(s.connected&&(s.pending||Date.now()-Date.parse(s.lastSync||'1970-01-01')>86400000))await sync();})().catch(logFailure);},60000);timer.unref();
    return {status,begin,callback,markDirty,requestSync,sync,close(){closed=true;clearInterval(timer);if(queued)clearTimeout(queued);controller.abort();}};
}
