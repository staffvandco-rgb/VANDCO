export function officeTime(now,timezone='Asia/Kolkata') {
 const p=Object.fromEntries(new Intl.DateTimeFormat('en-CA',{timeZone:timezone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'}).formatToParts(new Date(now)).map(p=>[p.type,p.value]));
 return {date:`${p.year}-${p.month}-${p.day}`,seconds:Number(p.hour)*3600+Number(p.minute)*60+Number(p.second)};
}
export function taskForMonth(task,today) {
 const origin=(task.assignedOn||task.due||'').slice(0,7);
 return {...task,carriedForward:task.status!=='Done'&&!!origin&&origin<today.slice(0,7),assignedMonth:origin};
}
export function lateArrival(now,timezone='Asia/Kolkata') {return officeTime(now,timezone).seconds>10*3600+15*60;}
export function createAttendanceReminders({db,list,add,onChange,now=Date.now,timezone='Asia/Kolkata'}) {
 async function run(){
  const time=officeTime(now(),timezone);if(time.seconds<10*3600+15*60)return 0;
  return db.transaction(async()=>{
   const attendance=(await list('attendance')),leave=(await list('leave')),notes=(await list('notifications'));let count=0;
   for(const employee of (await db.prepare("SELECT id FROM users WHERE role='Employee'").all())) {
    if(attendance.some(a=>a.owner===employee.id&&a.date===time.date&&a.in))continue;
    if(leave.some(l=>l.owner===employee.id&&l.status==='Approved'&&l.start<=time.date&&l.end>=time.date))continue;
    if(notes.some(n=>n.owner===employee.id&&n.type==='attendance-reminder'&&n.workday===time.date))continue;
    (await add('notifications',employee.id,{type:'attendance-reminder',workday:time.date,body:'Attendance reminder: it is past the 10:15 AM check-IN time. Please record your IN with a fresh selfie and GPS location.',date:new Date(now()).toISOString(),read:'false'}));count++;
   }
   
  if(count)await onChange();return count;
  });
 }
 return {run};
}

export function nextMonthlyDue(due,completedOn,anchorDay=Number(due.slice(8,10))) {
 const base=due.slice(0,7)>completedOn.slice(0,7)?due:completedOn;
 const [y,m]=base.split('-').map(Number);const last=new Date(Date.UTC(y,m+1,0));
 return last.getUTCFullYear()+'-'+String(last.getUTCMonth()+1).padStart(2,'0')+'-'+String(Math.min(anchorDay,last.getUTCDate())).padStart(2,'0');
}
