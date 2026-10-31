
import http from 'node:http';
import {createAttendanceReminders,lateArrival,taskForMonth,nextMonthlyDue} from './office-rules.mjs';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID, scryptSync, timingSafeEqual, createHash, createCipheriv, createDecipheriv } from 'node:crypto';
import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createDriveService } from './drive.mjs';

class ApiError extends Error { constructor(status, message) { super(message); this.status=status; } }
function requireValue(ok, message, status=400) { if(!ok) throw new ApiError(status,message); }
function str(value, name, max=500) { requireValue(typeof value==='string'&&value.trim().length>0&&value.length<=max,`Enter a valid ${name}.`); return value.trim(); }
function passwordHash(password) { const salt=randomBytes(16).toString('hex'); return salt+':'+scryptSync(password,salt,64).toString('hex'); }
function passwordOk(password, encoded) { const [salt,hash]=encoded.split(':'); return typeof password==='string'&&password.length<=256&&timingSafeEqual(scryptSync(password,salt,64),Buffer.from(hash,'hex')); }
function password(value) { requireValue(typeof value==='string'&&value.length>=12&&value.length<=128,'Use a password with 12–128 characters.'); return value; }
function email(value) { const v=str(value,'email address',254).toLowerCase(); requireValue(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),'Enter a valid email address.'); return v; }
function date(value) { requireValue(typeof value==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(value)&&!Number.isNaN(Date.parse(value))&&new Date(value).toISOString().slice(0,10)===value,'Enter a valid date.'); return value; }
const tokenHash=token=>createHash('sha256').update(token).digest('hex');

export function createOfficeServer(options={}) {
    const dataDir=resolve(options.dataDir||process.env.DATA_DIR||'data'); mkdirSync(dataDir,{recursive:true,mode:0o700});
    const timezone=options.timezone||process.env.OFFICE_TIMEZONE||'Asia/Kolkata';
    const dayFormat=new Intl.DateTimeFormat('en-CA',{timeZone:timezone,year:'numeric',month:'2-digit',day:'2-digit'});
    const today=()=>{const p=Object.fromEntries(dayFormat.formatToParts(new Date()).map(x=>[x.type,x.value]));return `${p.year}-${p.month}-${p.day}`;};
    const db=new DatabaseSync(join(dataDir,'officehub.sqlite'));
    db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,department TEXT NOT NULL,title TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('Admin','Employee')),password TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES users(id),expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY,kind TEXT NOT NULL,owner TEXT NOT NULL,payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS record_lookup ON records(kind,owner);
        CREATE TABLE IF NOT EXISTS photos(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES users(id),bytes BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,record_id TEXT NOT NULL,at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS punches(owner TEXT NOT NULL,workday TEXT NOT NULL,record_id TEXT NOT NULL UNIQUE REFERENCES records(id),PRIMARY KEY(owner,workday));
        CREATE TABLE IF NOT EXISTS registrations(id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,department TEXT NOT NULL,title TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('Admin','Employee')),password TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,reviewed_by TEXT,reviewed_at TEXT);`);
    db.exec(`CREATE TABLE IF NOT EXISTS password_reset_requests(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),email TEXT NOT NULL,requested_at TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Pending',reviewed_by TEXT,reviewed_at TEXT)`);
    const keyFile=join(dataDir,'photo-encryption.key');
    if(!existsSync(keyFile)) writeFileSync(keyFile,randomBytes(32),{mode:0o600,flag:'wx'});
    const key=readFileSync(keyFile); requireValue(key.length===32,'Invalid photo encryption key.',500);
    const encrypt=bytes=>{const iv=randomBytes(12),c=createCipheriv('aes-256-gcm',key,iv);const cipher=Buffer.concat([c.update(bytes),c.final()]);return Buffer.concat([iv,c.getAuthTag(),cipher]);};
    const decrypt=bytes=>{bytes=Buffer.from(bytes);const d=createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));d.setAuthTag(bytes.subarray(12,28));return Buffer.concat([d.update(bytes.subarray(28)),d.final()]);};
    if(!db.prepare('SELECT id FROM users LIMIT 1').get()) {
        const adminEmail=email(options.adminEmail||process.env.ADMIN_EMAIL);
        const secret=password(options.adminPassword||process.env.ADMIN_PASSWORD);
        db.prepare('INSERT INTO users VALUES(?,?,?,?,?,?,?)').run(randomUUID(),options.officeName||process.env.OFFICE_NAME||'Office Admin',adminEmail,'Administration','Office Administrator','Admin',passwordHash(secret));
    }
    const publicUser=u=>({id:u.id,name:u.name,email:u.email,department:u.department,title:u.title,role:u.role});
    const list=(kind)=>db.prepare('SELECT payload FROM records WHERE kind=? ORDER BY rowid').all(kind).map(r=>JSON.parse(r.payload));
    const add=(kind,owner,value)=>{const id=randomUUID();const record={...value,id,owner};db.prepare('INSERT INTO records VALUES(?,?,?,?)').run(id,kind,owner,JSON.stringify(record));return record;};
    const update=(kind,r)=>db.prepare('UPDATE records SET payload=? WHERE id=? AND kind=?').run(JSON.stringify(r),r.id,kind);
    const getRecord=(kind,id)=>{const r=db.prepare('SELECT payload FROM records WHERE kind=? AND id=?').get(kind,id);requireValue(r,'Record not found.',404);return JSON.parse(r.payload);};
    const notice=(owner,body)=>add('notifications',owner,{body,date:new Date().toISOString(),read:'false'});
    const isAdmin=u=>u.role==='Admin';
    const admin=u=>requireValue(isAdmin(u),'Administrator access required.',403);
    const own=(u,r)=>requireValue(isAdmin(u)||r.owner===u.id,'You cannot access another employee’s record.',403);
    const registrationList=()=>db.prepare('SELECT id,name,email,department,title,role,status,created_at,reviewed_by,reviewed_at FROM registrations ORDER BY created_at DESC').all();
    const state=u=>({user:publicUser(u),today:today(),timezone,employees:db.prepare('SELECT * FROM users ORDER BY name').all().map(publicUser),registrations:isAdmin(u)?registrationList():[],passwordResetRequests:isAdmin(u)?db.prepare("SELECT id,email,requested_at,status,reviewed_at FROM password_reset_requests WHERE status='Pending' ORDER BY requested_at DESC").all():[],drive:isAdmin(u)?drive.status():undefined,
        ...Object.fromEntries(['attendance','leave','tasks','announcements','notifications'].map(kind=>[kind,list(kind).map(r=>kind==='tasks'?taskForMonth(r,today()):r).filter(r=>kind==='announcements'||(kind==='notifications'?r.owner===u.id:isAdmin(u)||r.owner===u.id))]))});
    const drive=createDriveService({db,encrypt,decrypt,config:options.driveConfig||{},fetcher:options.driveFetch||fetch,snapshot:()=>{
        const users=db.prepare('SELECT * FROM users').all(),records=db.prepare('SELECT * FROM records').all(),photos=db.prepare('SELECT * FROM photos').all();
        return {publicRecords:{version:1,exportedAt:new Date().toISOString(),timezone,employees:users.map(publicUser),registrations:registrationList(),...Object.fromEntries(['attendance','leave','tasks','announcements','notifications'].map(kind=>[kind,records.filter(r=>r.kind===kind).map(r=>JSON.parse(r.payload))]))},
            photos:photos.map(p=>({id:p.id,owner:p.owner,bytes:decrypt(p.bytes)})),
            backup:{version:1,exportedAt:new Date().toISOString(),timezone,users,registrations:db.prepare('SELECT * FROM registrations').all(),records,punches:db.prepare('SELECT * FROM punches').all(),audit:db.prepare('SELECT * FROM audit').all(),photos:photos.map(p=>({...p,bytes:Buffer.from(p.bytes).toString('base64')})),photoEncryptionKey:key.toString('base64')}};
    }});
    const reminders=createAttendanceReminders({db,list,add,onChange:()=>drive.markDirty(),timezone});
    const reminderTick=()=>{try{reminders.run();}catch(e){console.error('Attendance reminder check failed:',e.name);}};
    const reminderTimer=setInterval(reminderTick,30000);reminderTimer.unref();
    const limits=new Map();
    function limit(key,max,period) {const now=Date.now();let l=limits.get(key);if(!l||l.until<now)l={n:0,until:now+period};l.n++;limits.set(key,l);requireValue(l.n<=max,'Too many requests. Please try again later.',429);}
    const cleanup=setInterval(()=>{const now=Date.now();for(const [k,v] of limits)if(v.until<now)limits.delete(k);db.prepare('DELETE FROM sessions WHERE expires<?').run(now);},60000);cleanup.unref();
    const authenticate=req=>{const token=(req.headers.authorization||'').replace(/^Bearer /,'');requireValue(/^[a-f0-9]{64}$/.test(token),'Sign in to continue.',401);const u=db.prepare('SELECT users.* FROM users JOIN sessions ON users.id=sessions.owner WHERE sessions.hash=? AND sessions.expires>?').get(tokenHash(token),Date.now());requireValue(u,'Your session expired. Please sign in again.',401);return u;};
    const audit=(u,action,id='')=>db.prepare('INSERT INTO audit(actor,action,record_id,at) VALUES(?,?,?,?)').run(u.id,action,id,Date.now());
    function evidence(input,u) {
        const loc=input.location;
        requireValue(loc&&typeof loc.latitude==='number'&&Number.isFinite(loc.latitude)&&Math.abs(loc.latitude)<=90&&typeof loc.longitude==='number'&&Number.isFinite(loc.longitude)&&Math.abs(loc.longitude)<=180,'A valid GPS location is required.');
        requireValue(typeof loc.accuracy==='number'&&loc.accuracy>0&&loc.accuracy<=100,'Wait for GPS accuracy within 100 metres.');
        requireValue(loc.mock!==true,'Simulated locations cannot be used for office attendance.');
        const now=Date.now();requireValue(Number.isFinite(loc.time)&&Math.abs(now-loc.time)<=120000,'GPS location has expired. Capture again.');
        requireValue(Number.isFinite(input.capturedAt)&&Math.abs(now-input.capturedAt)<=120000,'The selfie has expired. Take a fresh selfie.');
        requireValue(typeof input.photo==='string'&&input.photo.length<2100000&&/^[A-Za-z0-9+/]+={0,2}$/.test(input.photo),'A camera selfie is required.');
        const bytes=Buffer.from(input.photo,'base64');requireValue(bytes.length>=100&&bytes.length<=1500000&&bytes[0]===255&&bytes[1]===216&&bytes[bytes.length-2]===255&&bytes[bytes.length-1]===217,'Submit a valid JPEG selfie under 1.5 MB.');
        const photo=randomUUID();db.prepare('INSERT INTO photos VALUES(?,?,?)').run(photo,u.id,encrypt(bytes));
        return {photo,location:{latitude:loc.latitude,longitude:loc.longitude,accuracy:loc.accuracy,time:loc.time,provider:String(loc.provider||'device').slice(0,30),mock:false},capturedAt:input.capturedAt};
    }
    function action(u,input) {
        const op=str(input.op,'action',40),a=input.args||{};let id='';
        switch(op) {
            case 'review_registration': {
                admin(u);requireValue(['Approved','Rejected'].includes(a.status),'Choose approve or reject.');
                const r=db.prepare('SELECT * FROM registrations WHERE id=?').get(str(a.id,'registration ID',100));
                requireValue(r,'Registration not found.',404);requireValue(r.status==='Pending','This registration has already been reviewed.',409);
                if(a.status==='Approved'){
                    requireValue(!db.prepare('SELECT id FROM users WHERE email=?').get(r.email),'An account with this email already exists.',409);
                    const userId=randomUUID();db.prepare('INSERT INTO users VALUES(?,?,?,?,?,?,?)').run(userId,r.name,r.email,r.department,r.title,r.role,r.password);
                    notice(userId,'Your registration was approved. Welcome to OfficeHub.');
                }
                db.prepare('UPDATE registrations SET status=?,password=?,reviewed_by=?,reviewed_at=? WHERE id=?').run(a.status,'',u.id,new Date().toISOString(),r.id);id=r.id;break;
            }
            case 'create_employee': {
                admin(u);const id=randomUUID();db.prepare('INSERT INTO users VALUES(?,?,?,?,?,?,?)').run(id,str(a.name,'name',100),email(a.email),str(a.department,'department',100),str(a.title,'job title',100),'Employee',passwordHash(password(a.password)));break;
            }
            case 'edit_employee': {
                requireValue(isAdmin(u)||a.id===u.id,'You can only edit your own profile.',403);
                requireValue(db.prepare('SELECT id FROM users WHERE id=?').get(a.id),'Employee not found.',404);
                db.prepare('UPDATE users SET name=?,email=?,department=?,title=? WHERE id=?').run(str(a.name,'name',100),email(a.email),str(a.department,'department',100),str(a.title,'job title',100),a.id);break;
            }
            case 'change_password': {
                requireValue(passwordOk(a.current,u.password),'Current password is incorrect.',403);
                db.prepare('UPDATE users SET password=? WHERE id=?').run(passwordHash(password(a.password)),u.id);
                db.prepare('DELETE FROM sessions WHERE owner=?').run(u.id);break;
            }
            case 'admin_reset_password': {
                admin(u);const target=db.prepare('SELECT * FROM users WHERE id=?').get(str(a.userId,'employee ID',100));requireValue(target,'Employee not found.',404);db.prepare('UPDATE users SET password=? WHERE id=?').run(passwordHash(password(a.password)),target.id);db.prepare("UPDATE password_reset_requests SET status='Approved',reviewed_by=?,reviewed_at=? WHERE user_id=? AND status='Pending'").run(u.id,new Date().toISOString(),target.id);db.prepare('DELETE FROM sessions WHERE owner=?').run(target.id);notice(target.id,'Your administrator reset your password. Sign in with the new password.');break;
            }
            case 'request_leave': {
                const start=date(a.start),end=date(a.end);requireValue(start>=today()&&end>=start,'Choose a valid leave range from today onward.');
                requireValue(!list('leave').some(r=>r.owner===u.id&&r.status!=='Rejected'&&start<=r.end&&end>=r.start),'These dates overlap an existing leave request.',409);
                const r=add('leave',u.id,{start,end,reason:str(a.reason,'leave reason',1000),status:'Pending'});id=r.id;
                for(const x of db.prepare("SELECT id FROM users WHERE role='Admin'").all())notice(x.id,`${u.name} requested leave.`);break;
            }
            case 'decide_leave': {
                admin(u);const r=getRecord('leave',a.id);requireValue(r.owner!==u.id,'You cannot approve your own leave.',403);requireValue(r.status==='Pending','This request has already been decided.',409);requireValue(['Approved','Rejected'].includes(a.status),'Invalid decision.');r.status=a.status;update('leave',r);notice(r.owner,`Your leave for ${r.start} was ${a.status.toLowerCase()}.`);id=r.id;break;
            }
            case 'assign_task': {
                admin(u);requireValue(db.prepare('SELECT id FROM users WHERE id=?').get(a.owner),'Employee not found.',404);const due=date(a.due);requireValue(due>=today(),'Deadline must be today or later.');requireValue(a.instructions===undefined||typeof a.instructions==='string','Enter written instructions.');const instructions=(a.instructions||'').trim();requireValue(instructions.length<=4000,'Instructions must be within 4,000 characters.');let assignmentPhoto='';
                requireValue(a.photo===undefined||typeof a.photo==='string','Choose a valid photo.');
                if(a.photo){requireValue(a.photo.length<2100000&&/^[A-Za-z0-9+/]+={0,2}$/.test(a.photo),'Choose a valid JPEG photo.');const bytes=Buffer.from(a.photo,'base64');requireValue(bytes.length>=100&&bytes.length<=1500000&&bytes[0]===255&&bytes[1]===216&&bytes[bytes.length-2]===255&&bytes[bytes.length-1]===217,'Choose a JPEG photo under 1.5 MB.');assignmentPhoto=randomUUID();db.prepare('INSERT INTO photos VALUES(?,?,?)').run(assignmentPhoto,a.owner,encrypt(bytes));}
                const r=add('tasks',a.owner,{title:str(a.title,'task title',200),instructions,assignmentPhoto,due,assignedOn:today(),repeat:'Monthly',anchorDay:Number(due.slice(8,10)),status:'To do'});notice(a.owner,`New assignment: ${r.title}`);id=r.id;break;
            }
            case 'submit_task': {
                const task=getRecord('tasks',a.id);requireValue(task.owner===u.id,'Only the assigned employee can submit work.',403);
                requireValue(task.status!=='Done','This task is completed. Submit to the next assignment.',409);
                requireValue(a.text===undefined||typeof a.text==='string','Write a valid update.');const text=(a.text||'').trim();requireValue(text.length<=4000,'Use at most 4,000 characters.');
                requireValue(a.photo===undefined||typeof a.photo==='string','Choose a valid photo.');requireValue(text||a.photo,'Write an update or upload a photo.');
                const submissions=task.submissions||[];requireValue(submissions.length<50,'This task has reached its 50-submission limit.',409);let photo='';
                if(a.photo){requireValue(a.photo.length<2100000&&/^[A-Za-z0-9+/]+={0,2}$/.test(a.photo),'Choose a valid JPEG photo.');const bytes=Buffer.from(a.photo,'base64');requireValue(bytes.length>=100&&bytes.length<=1500000&&bytes[0]===255&&bytes[1]===216&&bytes[bytes.length-2]===255&&bytes[bytes.length-1]===217,'Choose a JPEG photo under 1.5 MB.');photo=randomUUID();db.prepare('INSERT INTO photos VALUES(?,?,?)').run(photo,u.id,encrypt(bytes));}
                submissions.push({id:randomUUID(),text,photo,at:new Date().toISOString(),submittedBy:u.id});task.submissions=submissions;update('tasks',task);id=task.id;
                for(const adminUser of db.prepare("SELECT id FROM users WHERE role='Admin'").all())notice(adminUser.id,`Work submitted by ${u.name}: ${task.title}`);break;
            }
            case 'task_status': {const r=getRecord('tasks',a.id);own(u,r);requireValue(['To do','In progress','Done'].includes(a.status),'Invalid task status.');requireValue(!r.nextTaskId||a.status==='Done','This completed task has a next-month assignment. Update that assignment instead.',409);
                r.status=a.status;
                if(a.status==='Done'&&!r.nextTaskId){
                    r.completedOn=today();r.repeat='Monthly';r.anchorDay=r.anchorDay||Number(r.due.slice(8,10));
                    const due=nextMonthlyDue(r.due,r.completedOn,r.anchorDay);
                    const next=add('tasks',r.owner,{title:r.title,instructions:r.instructions||'',assignmentPhoto:r.assignmentPhoto||'',due,assignedOn:today(),repeat:'Monthly',anchorDay:r.anchorDay,previousTaskId:r.id,status:'To do'});
                    r.nextTaskId=next.id;notice(r.owner,`Monthly assignment: ${r.title}. Next deadline: ${due}.`);
                }
                update('tasks',r);id=r.id;break;}
            case 'announce': {admin(u);const title=str(a.title,'title',200);const r=add('announcements',u.id,{title,body:str(a.body,'announcement',4000),date:today()});for(const e of db.prepare('SELECT id FROM users').all())notice(e.id,`Announcement: ${title}`);id=r.id;break;}
            case 'read_notification': {const r=getRecord('notifications',a.id);requireValue(r.owner===u.id,'This notification is private.',403);r.read='true';update('notifications',r);id=r.id;break;}
            case 'punch': {
                requireValue(['in','out'].includes(a.direction),'Choose IN or OUT.');
                const existing=list('attendance').filter(r=>r.owner===u.id),open=existing.find(r=>!r.out);
                if(a.direction==='in') {
                    requireValue(!open,'Check OUT before starting another attendance record.',409);
                    requireValue(!db.prepare('SELECT record_id FROM punches WHERE owner=? AND workday=?').get(u.id,today()),'Attendance has already been recorded for today.',409);
                    const proof=evidence(a,u);const r=add('attendance',u.id,{date:today(),in:String(Date.now()),out:'',inProof:proof,source:'server'});id=r.id;
                    db.prepare('INSERT INTO punches VALUES(?,?,?)').run(u.id,today(),r.id);
                    r.late=lateArrival(Number(r.in),timezone);update('attendance',r);
                    if(r.late)notice(u.id,'Late attendance: your IN was recorded after 10:15 AM. Your selfie and location have been saved.');
                } else {
                    requireValue(open,'Record IN before recording OUT.',409);const proof=evidence(a,u);open.out=String(Date.now());open.outProof=proof;update('attendance',open);id=open.id;
                }
                break;
            }
            default: throw new ApiError(400,'Unknown action.');
        }
        audit(u,op,id);
        return op==='change_password'?{signedOut:true}:state(db.prepare('SELECT * FROM users WHERE id=?').get(u.id));
    }
    async function body(req) {requireValue((req.headers['content-type']||'').startsWith('application/json'),'Send JSON.',415);let length=0,chunks=[];for await(const c of req){length+=c.length;requireValue(length<=3*1024*1024,'Request too large.',413);chunks.push(c);}let result;try{result=JSON.parse(Buffer.concat(chunks).toString());}catch{throw new ApiError(400,'Invalid JSON.');}requireValue(result&&typeof result==='object'&&!Array.isArray(result),'Send a JSON object.');return result;}
    const server=http.createServer(async(req,res)=>{
        res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
        const send=(status,value)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(value));};
        try {
            const path=new URL(req.url,'http://localhost').pathname;
            if(path==='/health'&&req.method==='GET'){send(200,{status:'ok',version:'0.6.1'});return;}
            if(path==='/api/drive/callback'&&req.method==='GET'){
                await drive.callback(new URL(req.url,'http://localhost').searchParams);
                res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'"});
                res.end('<!doctype html><html><meta name="viewport" content="width=device-width"><title>OfficeHub Drive connected</title><body style="font:18px system-ui;max-width:620px;margin:60px auto;padding:24px"><h1>Google Drive connected</h1><p>OfficeHub is connected to vijapur.sachin@gmail.com. Return to OfficeHub and refresh the Google Drive screen to see synchronization progress.</p></body></html>');return;
            }
            if(path==='/api/register'&&req.method==='POST'){
                limit('register-ip:'+req.socket.remoteAddress,20,3600000);const a=await body(req);const address=email(a.email);limit('register-email:'+address,5,3600000);
                requireValue(['Admin','Employee'].includes(a.role),'Choose Admin or Employee.');
                const entry={id:randomUUID(),name:str(a.name,'full name',100),email:address,department:str(a.department,'department',100),title:str(a.title,'job title',100),role:a.role,password:passwordHash(password(a.password))};
                db.exec('BEGIN IMMEDIATE');try{
                    requireValue(!db.prepare('SELECT id FROM users WHERE email=?').get(address),'An account with this email already exists. Sign in instead.',409);
                    requireValue(!db.prepare('SELECT id FROM registrations WHERE email=?').get(address),'A registration with this email is already on file. Contact your administrator.',409);
                    db.prepare('INSERT INTO registrations(id,name,email,department,title,role,password,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)').run(entry.id,entry.name,entry.email,entry.department,entry.title,entry.role,entry.password,'Pending',new Date().toISOString());
                    for(const u of db.prepare("SELECT id FROM users WHERE role='Admin'").all())notice(u.id,`${entry.name} requested ${entry.role.toLowerCase()} registration.`);
                    db.prepare('INSERT INTO audit(actor,action,record_id,at) VALUES(?,?,?,?)').run('registration','register',entry.id,Date.now());db.exec('COMMIT');
                }catch(e){db.exec('ROLLBACK');throw e;}
                drive.markDirty();send(202,{status:'Pending',message:'Registration submitted. An existing administrator must approve your account before you can sign in.'});return;
            }
            if(path==='/api/login'&&req.method==='POST') {
                limit('ip:'+req.socket.remoteAddress,40,15*60000);const a=await body(req);const address=email(a.email);limit('login:'+address,10,15*60000);
                const u=db.prepare('SELECT * FROM users WHERE email=?').get(address);
                // A fixed-cost dummy hash avoids a quick response for unknown email addresses.
                const hash=u?.password||dummyHash;requireValue(passwordOk(a.password,hash)&&u,'Email or password is incorrect.',401);
                const token=randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(tokenHash(token),u.id,Date.now()+8*3600000);send(200,{token,...state(u)});return;
            }
            if(path==='/api/password-reset/request'&&req.method==='POST') {const a=await body(req);const address=email(a.email);const target=db.prepare('SELECT id FROM users WHERE email=?').get(address);if(target){db.prepare("INSERT INTO password_reset_requests VALUES(?,?,?,?,?,?,?)").run(randomUUID(),target.id,address,new Date().toISOString(),'Pending','',null);for(const x of db.prepare("SELECT id FROM users WHERE role='Admin'").all())notice(x.id,`Password reset requested for ${address}.`);}send(202,{message:'If the account exists, an administrator has been notified.'});return;}
            const u=authenticate(req);limit('user:'+u.id,180,60000);
            if(path==='/api/drive/connect'&&req.method==='POST'){admin(u);send(200,drive.begin(u.id));return;}
            if(path==='/api/drive/status'&&req.method==='GET'){admin(u);send(200,drive.status());return;}
            if(path==='/api/drive/sync'&&req.method==='POST'){admin(u);requireValue(drive.status().connected,'Connect Google Drive first.');drive.markDirty();send(202,state(u));return;}
            if(path==='/api/logout'&&req.method==='POST'){db.prepare('DELETE FROM sessions WHERE hash=?').run(tokenHash(req.headers.authorization.slice(7)));send(200,{ok:true});return;}
            if(path==='/api/state'&&req.method==='GET'){reminderTick();send(200,state(u));return;}
            if(path==='/api/action'&&req.method==='POST') {
                const input=await body(req);db.exec('BEGIN IMMEDIATE');
                let result;try {result=action(u,input);db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');throw e;}drive.markDirty();if(result.drive)result.drive=drive.status();send(200,result);return;
            }
            if(path.startsWith('/api/photos/')&&req.method==='GET') {
                const r=db.prepare('SELECT owner,bytes FROM photos WHERE id=?').get(path.slice('/api/photos/'.length));requireValue(r,'Photo not found.',404);own(u,r);const bytes=decrypt(r.bytes);res.writeHead(200,{'Content-Type':'image/jpeg','Content-Length':bytes.length});res.end(bytes);return;
            }
            throw new ApiError(404,'Endpoint not found.');
        } catch(e) {
            const status=e.status||(e.message?.includes('UNIQUE constraint')?409:500);
            send(status,{error:status===500?'Server error. Please try again.':status===409&&!e.status?'That record already exists.':e.message});
            if(status===500)console.error('Request failed:',e.code||e.name); // Never log credentials or attendance bodies.
        }
    });
    const dummyHash=passwordHash(randomBytes(24).toString('hex'));
    server.requestTimeout=30000;server.headersTimeout=10000;
    server.on('close',()=>{clearInterval(cleanup);clearInterval(reminderTimer);drive.close();db.close();});
    return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
    const server=createOfficeServer();server.listen(Number(process.env.PORT||8080),process.env.HOST||'127.0.0.1',()=>console.log('OfficeHub API is ready.'));
    process.on('SIGTERM',()=>server.close());process.on('SIGINT',()=>server.close());
}
