import pg from 'pg';
import {AsyncLocalStorage} from 'node:async_hooks';
export async function connectDatabase(config){
 if(!/^[a-z][a-z0-9_]{0,62}$/.test(config.schema))throw new Error('Invalid database schema');
 const pool=new pg.Pool({host:config.host,port:config.port,database:config.database,user:config.user,password:config.password,ssl:{rejectUnauthorized:true,ca:config.sslCa},max:4,connectionTimeoutMillis:15000,idleTimeoutMillis:30000,options:`-c search_path=${config.schema},pg_catalog -c statement_timeout=30000`});
 let closed=false;
 pool.on('error',e=>console.error('Database connection:',e.code||e.name));
 const context=new AsyncLocalStorage();
 const query=(sql,args=[]) => (context.getStore()?.client||pool).query(sql,args);
 try{await query('SELECT 1');}catch(e){await pool.end();throw e;}
 return {
  query,
  prepare(sql){let n=0;const text=sql.replace(/\?/g,()=>'$'+(++n));return {get:async(...args)=>(await query(text,args)).rows[0],all:async(...args)=>(await query(text,args)).rows,run:async(...args)=>{const r=await query(text,args);return {changes:r.rowCount};}};},
  exec:sql=>query(sql),
  onRollback(fn){context.getStore()?.rollback.push(fn);},
  async transaction(fn){if(context.getStore())return fn();const client=await pool.connect();const scope={client,rollback:[]};try{await client.query('BEGIN');await client.query('SELECT pg_advisory_xact_lock(hashtext($1))',[config.schema]);const value=await context.run(scope,fn);await client.query('COMMIT');return value;}catch(e){await client.query('ROLLBACK').catch(()=>{});for(const cleanup of scope.rollback)await cleanup().catch(()=>{});throw e;}finally{client.release();}},
  close:()=>{if(closed)return Promise.resolve();closed=true;return pool.end()}
 };
}
export async function initializeSchema(db,schema){
 await db.exec(`CREATE SCHEMA IF NOT EXISTS ${schema}; REVOKE ALL ON SCHEMA ${schema} FROM PUBLIC,anon,authenticated;
 CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,department TEXT NOT NULL,title TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('Admin','Employee')),password TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES users(id),expires BIGINT NOT NULL);
 CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY,kind TEXT NOT NULL,owner TEXT NOT NULL,payload TEXT NOT NULL,sequence BIGSERIAL UNIQUE);
 CREATE INDEX IF NOT EXISTS record_lookup ON records(kind,owner);
 CREATE TABLE IF NOT EXISTS photos(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES users(id),object_key TEXT NOT NULL UNIQUE);
 CREATE TABLE IF NOT EXISTS audit(id BIGSERIAL PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,record_id TEXT NOT NULL,at BIGINT NOT NULL);
 CREATE TABLE IF NOT EXISTS punches(owner TEXT NOT NULL,workday TEXT NOT NULL,record_id TEXT NOT NULL UNIQUE REFERENCES records(id),PRIMARY KEY(owner,workday));
 CREATE TABLE IF NOT EXISTS registrations(id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,department TEXT NOT NULL,title TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('Admin','Employee')),password TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,reviewed_by TEXT,reviewed_at TEXT);
 CREATE TABLE IF NOT EXISTS drive_store(key TEXT PRIMARY KEY,value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS drive_auth(hash TEXT PRIMARY KEY,secret BYTEA NOT NULL,expires BIGINT NOT NULL);
 CREATE TABLE IF NOT EXISTS drive_files(key TEXT PRIMARY KEY,id TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS migration_imports(digest TEXT PRIMARY KEY,imported_at TIMESTAMPTZ NOT NULL DEFAULT now());
 REVOKE ALL ON ALL TABLES IN SCHEMA ${schema} FROM PUBLIC,anon,authenticated;
 ALTER DEFAULT PRIVILEGES IN SCHEMA ${schema} REVOKE ALL ON TABLES FROM PUBLIC,anon,authenticated;`);
}
