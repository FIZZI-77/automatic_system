import fs from 'fs';
import path from 'path';
const seed = Number(process.argv[2] || 77); const count = Number(process.argv[3] || 100);
const output = process.argv[4] || path.join('load-tests', 'data', 'fixtures', `seed-${seed}.json`);
function uuid(n) { return `00000000-0000-4000-8000-${Math.abs(seed * 1000000 + n).toString(16).padStart(12, '0').slice(-12)}`; }
const fixtures = { seed, generated_at: 'deterministic', users: [], profiles: [], departments: [], brigades: [], tickets: [], location_history: [], sla: [], notifications: [], assets: [], analytics_events: [] };
for (let i = 0; i < count; i++) { fixtures.users.push({id:uuid(i),email:`load-${seed}-${i}@example.invalid`}); fixtures.profiles.push({id:uuid(100000+i),user_id:uuid(i)}); fixtures.departments.push({id:uuid(200000+i),name:`Load department ${i}`}); fixtures.brigades.push({id:uuid(300000+i),department_id:uuid(200000+i)}); fixtures.tickets.push({id:uuid(400000+i),department_id:uuid(200000+i)}); fixtures.location_history.push({event_id:uuid(500000+i),brigade_id:uuid(300000+i),sequence:i+1,latitude:55.75,longitude:37.61}); fixtures.sla.push({id:uuid(600000+i),ticket_id:uuid(400000+i)}); fixtures.notifications.push({id:uuid(700000+i),user_id:uuid(i)}); fixtures.assets.push({id:uuid(800000+i),serial_number:`LOAD-${seed}-${i}`}); fixtures.analytics_events.push({event_id:uuid(900000+i),ticket_id:uuid(400000+i),type:'load.test'}); }
fs.mkdirSync(path.dirname(output), {recursive:true}); fs.writeFileSync(output, `${JSON.stringify(fixtures,null,2)}\n`); console.log(output);
