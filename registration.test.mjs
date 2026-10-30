import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {testServer} from './test-support.mjs';

test('admin and employee registration require trusted review',async t=>{
    const dir=mkdtempSync(join(tmpdir(),'officehub-registration-'));const server=await testServer(t,{dataDir:dir,adminEmail:'owner@example.test',adminPassword:'OwnerPassword123!'});
    await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(async()=>{await new Promise(r=>server.close(r));assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
    const base=`http://127.0.0.1:${server.address().port}`;
    async function request(path,body,token){const r=await fetch(base+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{})},...(body?{body:JSON.stringify(body)}:{})});return {status:r.status,body:await r.json()};}
    const login=(email,password)=>request('/api/login',{email,password});
    const owner=(await login('owner@example.test','OwnerPassword123!')).body;
    const applicant=role=>({name:role+' Applicant',email:role.toLowerCase()+'@example.test',department:'Operations',title:'Office member',role,password:'ApplicantPassword123!'});
    for(const role of ['Employee','Admin']){
        const a=applicant(role);const registered=await request('/api/register',a);assert.equal(registered.status,202);assert.equal(registered.body.status,'Pending');
        assert.equal((await login(a.email,a.password)).status,401,'pending users cannot log in');
        assert.equal((await request('/api/register',a)).status,409,'duplicate registrations rejected');
    }
    let state=(await request('/api/state',null,owner.token)).body;assert.equal(state.registrations.length,2);assert.ok(!JSON.stringify(state.registrations).includes('password'));
    const employee=state.registrations.find(r=>r.role==='Employee'),admin=state.registrations.find(r=>r.role==='Admin');
    const action=(token,id,status)=>request('/api/action',{op:'review_registration',args:{id,status}},token);
    assert.equal((await action(owner.token,employee.id,'Approved')).status,200);
    const staff=(await login('employee@example.test','ApplicantPassword123!')).body;assert.equal(staff.user.role,'Employee');assert.deepEqual(staff.registrations,[]);assert.equal(staff.drive,undefined);
    assert.equal((await action(staff.token,admin.id,'Approved')).status,403,'employees cannot approve admin applications');
    assert.equal((await request('/api/drive/connect',{},staff.token)).status,403,'employees cannot connect Drive');
    assert.equal((await request('/api/drive/connect',{},owner.token)).status,503,'unconfigured Drive does not pretend to connect');
    assert.equal((await action(owner.token,admin.id,'Approved')).status,200);
    assert.equal((await login('admin@example.test','ApplicantPassword123!')).body.user.role,'Admin');
    assert.equal((await action(owner.token,admin.id,'Rejected')).status,409,'cannot decide a request twice');
    const rejected={...applicant('Employee'),email:'rejected@example.test'};assert.equal((await request('/api/register',rejected)).status,202);
    state=(await request('/api/state',null,owner.token)).body;const r=state.registrations.find(x=>x.email===rejected.email);
    assert.equal((await action(owner.token,r.id,'Rejected')).status,200);assert.equal((await login(rejected.email,rejected.password)).status,401);
});
