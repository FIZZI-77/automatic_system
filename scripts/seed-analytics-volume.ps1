param(
    [ValidateRange(100, 100000)]
    [int]$Scale = 1000,
    [string]$Namespace = "automatic-system",
    [switch]$SkipDemoSeed
)

$ErrorActionPreference = "Stop"
$script:OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PGCLIENTENCODING = "UTF8"

function Get-PrimaryPod([string]$Selector) {
    $pod = kubectl -n $Namespace get pods -l $Selector -o json | ConvertFrom-Json |
        Select-Object -ExpandProperty items |
        Where-Object { $_.status.phase -eq "Running" } |
        Select-Object -First 1
    if (-not $pod) { throw "Primary pod not found for $Selector" }
    $pod.metadata.name
}

$platformPod = Get-PrimaryPod "cluster-name=postgres-platform,role=primary"
$ticketPod = Get-PrimaryPod "cluster-name=postgres-ticket-citus,citus-group=0,role=primary"

function Invoke-Postgres([string]$Database, [string]$Sql, [switch]$Ticket) {
    $pod = if ($Ticket) { $ticketPod } else { $platformPod }
    $Sql | kubectl -n $Namespace exec -i $pod -c postgres -- psql -X -v ON_ERROR_STOP=1 -U postgres -d $Database
    if ($LASTEXITCODE -ne 0) { throw "Bulk seed failed for $Database" }
}

function Get-PrefixSql {
    @"
CREATE OR REPLACE FUNCTION pg_temp.seed_uuid(value text) RETURNS uuid
LANGUAGE sql IMMUTABLE STRICT AS `$`$
SELECT (substr(md5(value),1,8)||'-'||substr(md5(value),9,4)||'-4'||substr(md5(value),14,3)||'-8'||substr(md5(value),18,3)||'-'||substr(md5(value),21,12))::uuid
`$`$;
"@
}

if (-not $SkipDemoSeed) {
    & "$PSScriptRoot\seed-demo-data.ps1" -Target Kubernetes -Namespace $Namespace -SkipRegister
    if ($LASTEXITCODE -ne 0) { throw "Base demo seed failed" }
}

$prefix = Get-PrefixSql

Invoke-Postgres department_db @"
$prefix
INSERT INTO departments(id,name,description,status,created_at,updated_at)
SELECT pg_temp.seed_uuid('dep-'||g), 'Городская служба №'||g,
       'Синтетическое подразделение для аналитики и проверки восстановления',
       CASE WHEN g % 11 = 0 THEN 'INACTIVE' ELSE 'ACTIVE' END,
       now()-(g||' days')::interval, now()
FROM generate_series(1,12) g ON CONFLICT (id) DO NOTHING;
INSERT INTO idempotency_keys(actor_key,operation,idempotency_key,request_hash,status,response,created_at,updated_at,expires_at)
SELECT 'seed-actor-'||(g%20),'department.seed','department-seed-'||g,md5(g::text),'COMPLETED',jsonb_build_object('seed',true),now()-interval '2 days',now()-interval '2 days',now()+interval '30 days'
FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload,status,attempts,next_attempt_at,created_at,sent_at)
SELECT pg_temp.seed_uuid('dep-outbox-'||g),'department',pg_temp.seed_uuid('dep-'||(1+g%12)),'department.updated',jsonb_build_object('seed',true,'sequence',g),'SENT',1,now(),now()-(g||' hours')::interval,now()-(g||' hours')::interval
FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
"@

Invoke-Postgres auth_db @"
$prefix
INSERT INTO users(id,email,username,password_hash,email_verified,is_active,created_at,updated_at)
SELECT pg_temp.seed_uuid('user-'||g),'analytics.user'||g||'@city.local','analytics_user_'||g,
       COALESCE((SELECT password_hash FROM users LIMIT 1),'synthetic-disabled-password'),true,true,
       now()-(g%365||' days')::interval,now()
FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO user_roles(user_id,role_id,assigned_at)
SELECT pg_temp.seed_uuid('user-'||g),r.id,now()-(g%365||' days')::interval
FROM generate_series(1,GREATEST(100,$Scale/5)) g
CROSS JOIN LATERAL (SELECT id FROM roles ORDER BY name OFFSET (g % GREATEST(1,(SELECT count(*) FROM roles))) LIMIT 1) r
ON CONFLICT DO NOTHING;
INSERT INTO sessions(id,user_id,client_id,ip,user_agent,is_revoked,expires_at,last_seen_at,created_at)
SELECT pg_temp.seed_uuid('session-'||g),pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),'analytics-seed',('10.10.'||(g%250)||'.'||(1+g%249))::inet,'bulk-seed',g%10=0,now()+interval '30 days',now()-(g%1440||' minutes')::interval,now()-(g%365||' days')::interval
FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO refresh_tokens(id,user_id,session_id,token_hash,is_revoked,expires_at,created_at)
SELECT pg_temp.seed_uuid('refresh-'||g),pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),pg_temp.seed_uuid('session-'||g),md5('refresh-'||g),g%10=0,now()+interval '30 days',now()-(g%365||' days')::interval
FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO one_time_tokens(id,user_id,token_hash,type,expires_at,used_at,created_at)
SELECT pg_temp.seed_uuid('ott-'||g),pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),md5('ott-'||g),CASE WHEN g%2=0 THEN 'EMAIL_VERIFICATION' ELSE 'PASSWORD_RESET' END,now()+interval '1 day',CASE WHEN g%3=0 THEN now() ELSE NULL END,now()-interval '1 hour'
FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO signing_keys(id,kid,algorithm,public_key_pem,private_key_pem,is_active,created_at,expires_at)
SELECT pg_temp.seed_uuid('signing-'||g),'analytics-seed-'||g,'RS256','INACTIVE SYNTHETIC PUBLIC KEY','INACTIVE SYNTHETIC PRIVATE KEY',false,now(),now()+interval '1 year'
FROM generate_series(1,5) g ON CONFLICT DO NOTHING;
INSERT INTO idempotency_keys(actor_key,operation,idempotency_key,request_hash,status,response,created_at,updated_at,expires_at)
SELECT 'seed-'||(g%100),'auth.seed','auth-seed-'||g,md5(g::text),'COMPLETED','{}',now(),now(),now()+interval '30 days'
FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload,status,attempts,next_attempt_at,created_at,sent_at)
SELECT pg_temp.seed_uuid('auth-outbox-'||g),'user',pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),'user.updated',jsonb_build_object('seed',true),'SENT',1,now(),now(),now()
FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
"@

Invoke-Postgres ticket_db @"
$prefix
INSERT INTO ticket_categories(id,code,name,description,is_active,created_at,updated_at)
SELECT pg_temp.seed_uuid('cat-'||g),'ANALYTICS_'||g,'Категория аналитики №'||g,'Синтетическая категория',true,now(),now()
FROM generate_series(1,16) g ON CONFLICT DO NOTHING;
INSERT INTO tickets(id,department_id,user_id,brigade_id,asset_id,title,description,category_id,priority,status,address,latitude,longitude,created_at,updated_at,assigned_at,completed_at,canceled_at,archived_at)
SELECT pg_temp.seed_uuid('ticket-'||g),pg_temp.seed_uuid('dep-'||(1+g%12)),pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),
       CASE WHEN g%6=0 THEN NULL ELSE pg_temp.seed_uuid('brigade-'||(1+g%40)) END,
       CASE WHEN g%4=0 THEN pg_temp.seed_uuid('asset-'||(1+g%GREATEST(100,$Scale/5))) ELSE NULL END,
       'Заявка для аналитики №'||g,'Синтетическое обращение с реалистичным жизненным циклом',pg_temp.seed_uuid('cat-'||(1+g%16)),
       (ARRAY['LOW','MEDIUM','HIGH','EMERGENCY'])[1+g%4],(ARRAY['NEW','ASSIGNED','IN_PROGRESS','DONE','CANCELED','ARCHIVED'])[1+g%6],
       'Москва, тестовый адрес '||g,55.55+(g%300)/1000.0,37.35+(g%500)/1000.0,
       now()-(g%365||' days')::interval,now()-(g%1440||' minutes')::interval,
       CASE WHEN g%6 IN (1,2,3,5) THEN now()-(g%365||' days')::interval+interval '45 minutes' END,
       CASE WHEN g%6 IN (3,5) THEN now()-(g%365||' days')::interval+interval '8 hours' END,
       CASE WHEN g%6=4 THEN now()-(g%365||' days')::interval+interval '2 hours' END,
       CASE WHEN g%6=5 THEN now()-(g%365||' days')::interval+interval '30 days' END
FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO ticket_status_history(id,department_id,ticket_id,old_status,new_status,changed_by,comment,created_at)
SELECT md5('ticket-history-'||t.id||'-'||step)::uuid,t.department_id,t.id,
       (ARRAY[NULL,'NEW','ASSIGNED'])[step],(ARRAY['NEW','ASSIGNED','IN_PROGRESS'])[step],NULL,'Синтетический переход',t.created_at+(step||' hours')::interval
FROM tickets t CROSS JOIN generate_series(1,3) step
WHERE t.title LIKE 'Заявка для аналитики %' ON CONFLICT DO NOTHING;
INSERT INTO ticket_reports(id,department_id,ticket_id,author_user_id,description,idempotency_key,completion_status,completion_attempts,completion_compensation_attempts,created_at,updated_at)
SELECT md5('ticket-report-'||t.id)::uuid,t.department_id,t.id,t.user_id,
       'Выполнены работы по синтетической заявке','seed-report-'||t.id,(ARRAY['NONE','PENDING','COMPLETED','FAILED'])[1+(row_number() OVER ())%4],(row_number() OVER ())%3,(row_number() OVER ())%2,t.created_at,now()
FROM (SELECT * FROM tickets WHERE title LIKE 'Заявка для аналитики %' ORDER BY id LIMIT GREATEST(100,$Scale/2)) t ON CONFLICT DO NOTHING;
INSERT INTO ticket_report_files(department_id,report_id,file_id,created_at)
SELECT department_id,id,md5('file-'||row_number() OVER (ORDER BY id))::uuid,now()
FROM ticket_reports WHERE id=md5('ticket-report-'||ticket_id)::uuid ON CONFLICT DO NOTHING;
INSERT INTO routing_inbox_events(event_id,event_type,topic,partition_id,message_offset,payload,processed_at)
SELECT pg_temp.seed_uuid('ticket-routing-inbox-'||g),'route.updated','routing.events.v1',g%6,g,jsonb_build_object('seed',true),now()
FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO completion_report_inbox(event_id,received_at)
SELECT pg_temp.seed_uuid('completion-inbox-'||g),now()-(g%365||' days')::interval FROM generate_series(1,GREATEST(100,$Scale/2)) g ON CONFLICT DO NOTHING;
INSERT INTO idempotency_keys(actor_key,operation,idempotency_key,request_hash,status,response,created_at,updated_at,expires_at)
SELECT 'seed-'||(g%100),'ticket.seed','ticket-seed-'||g,md5(g::text),'COMPLETED','{}',now(),now(),now()+interval '30 days' FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload,status,attempts,next_attempt_at,created_at,sent_at)
SELECT pg_temp.seed_uuid('ticket-outbox-'||g),'ticket',pg_temp.seed_uuid('ticket-'||g),'ticket.analytics_seeded',jsonb_build_object('seed',true),'SENT',1,now(),now(),now() FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
"@ -Ticket

Invoke-Postgres brigade_db @"
$prefix
INSERT INTO skills(id,code,name,description,active) SELECT pg_temp.seed_uuid('skill-'||g),'SKILL_'||g,'Навык №'||g,'Синтетический навык',true FROM generate_series(1,20) g ON CONFLICT DO NOTHING;
INSERT INTO brigades(id,department_id,name,description,status,specialization,created_at,updated_at)
SELECT pg_temp.seed_uuid('brigade-'||g),pg_temp.seed_uuid('dep-'||(1+g%12)),'Бригада №'||g,'Синтетическая бригада',(ARRAY['AVAILABLE','BUSY','ON_ROUTE','OFFLINE'])[1+g%4],'Городские работы',now()-(g||' days')::interval,now()
FROM generate_series(1,40) g ON CONFLICT DO NOTHING;
INSERT INTO brigade_members(id,brigade_id,user_id,profile_id,role,active,availability_status,joined_at,created_at,updated_at)
SELECT pg_temp.seed_uuid('member-'||g),pg_temp.seed_uuid('brigade-'||(1+g%40)),pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),pg_temp.seed_uuid('work-profile-'||(1+g%GREATEST(100,$Scale/5))),
       CASE WHEN g%5=0 THEN 'LEAD' ELSE 'TECHNICIAN' END,true,(ARRAY['AVAILABLE','UNAVAILABLE'])[1+g%2],now()-(g%365||' days')::interval,now(),now()
FROM generate_series(1,GREATEST(120,$Scale/3)) g ON CONFLICT DO NOTHING;
INSERT INTO brigade_skills(id,brigade_id,skill_id,active) SELECT pg_temp.seed_uuid('brigade-skill-'||g),pg_temp.seed_uuid('brigade-'||(1+g%40)),pg_temp.seed_uuid('skill-'||(1+g%20)),true FROM generate_series(1,160) g ON CONFLICT DO NOTHING;
INSERT INTO brigade_schedule(id,brigade_id,day_of_week,starts_at,ends_at,timezone,active) SELECT pg_temp.seed_uuid('schedule-'||g),pg_temp.seed_uuid('brigade-'||(1+(g-1)/7)),1+(g-1)%7,'08:00','20:00','Europe/Moscow',true FROM generate_series(1,280) g ON CONFLICT DO NOTHING;
INSERT INTO brigade_status_history(id,brigade_id,from_status,to_status,reason,created_at) SELECT pg_temp.seed_uuid('brigade-status-'||g),pg_temp.seed_uuid('brigade-'||(1+g%40)),'AVAILABLE','BUSY','Синтетическая смена',now()-(g%365||' days')::interval FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO brigade_member_history(id,brigade_id,member_id,user_id,profile_id,action,new_role,created_at) SELECT md5('member-history-'||m.id)::uuid,m.brigade_id,m.id,m.user_id,m.profile_id,'ADDED',m.role,now() FROM brigade_members m WHERE m.id::text IS NOT NULL ON CONFLICT DO NOTHING;
INSERT INTO brigade_member_status_history(id,brigade_id,member_id,user_id,from_status,to_status,reason,created_at) SELECT md5('member-state-'||m.id)::uuid,m.brigade_id,m.id,m.user_id,'AVAILABLE','UNAVAILABLE','Синтетический перерыв',now() FROM brigade_members m WHERE m.id::text IS NOT NULL ON CONFLICT DO NOTHING;
INSERT INTO brigade_zones(id,brigade_id,department_id,name,zone,priority,active) SELECT pg_temp.seed_uuid('brigade-zone-'||g),pg_temp.seed_uuid('brigade-'||g),pg_temp.seed_uuid('dep-'||(1+g%12)),'Зона №'||g,ST_GeomFromText('POLYGON(('||(37.3+g/1000.0)||' 55.5,'||(37.31+g/1000.0)||' 55.5,'||(37.31+g/1000.0)||' 55.51,'||(37.3+g/1000.0)||' 55.51,'||(37.3+g/1000.0)||' 55.5))',4326),g,true FROM generate_series(1,40) g ON CONFLICT DO NOTHING;
INSERT INTO brigade_member_skills(id,brigade_id,member_id,work_profile_id,skill_id,source_grant_id,proficiency_level,active,work_profile_active,source_occurred_at,created_at,updated_at) SELECT md5('member-skill-'||m.id)::uuid,m.brigade_id,m.id,COALESCE(m.profile_id,md5('work-profile-'||m.id)::uuid),pg_temp.seed_uuid('skill-'||(1+(row_number() OVER ())%20)),md5('grant-'||m.id)::uuid,'STANDARD',true,true,now(),now(),now() FROM brigade_members m ON CONFLICT DO NOTHING;
INSERT INTO brigade_route_projection(brigade_id,route_id,ticket_id,route_status,revision,source_updated_at,updated_at) SELECT pg_temp.seed_uuid('brigade-'||g),pg_temp.seed_uuid('route-'||g),pg_temp.seed_uuid('ticket-'||g),'COMPLETED',1,now(),now() FROM generate_series(1,40) g ON CONFLICT DO NOTHING;
INSERT INTO inbox_events(event_id,source_service,topic,partition_id,message_offset,event_type,event_version,occurred_at,payload,processed_at) SELECT pg_temp.seed_uuid('brigade-inbox-'||g),'profile','profiles.events.v1',g%6,g,'profile.updated',1,now(),jsonb_build_object('seed',true),now() FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO routing_inbox_events(event_id,event_type,topic,partition_id,message_offset,payload,processed_at) SELECT pg_temp.seed_uuid('brigade-routing-'||g),'route.updated','routing.events.v1',g%6,g,'{}',now() FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO ticket_inbox_events(event_id,event_type,topic,partition_id,message_offset,payload,processed_at) SELECT pg_temp.seed_uuid('brigade-ticket-'||g),'ticket.updated','tickets.events.v1',g%6,g,'{}',now() FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO idempotency_keys(actor_key,operation,idempotency_key,request_hash,status,response,created_at,updated_at,expires_at) SELECT 'seed','brigade.seed','brigade-seed-'||g,md5(g::text),'COMPLETED','{}',now(),now(),now()+interval '30 days' FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload,status,attempts,next_attempt_at,created_at,sent_at) SELECT pg_temp.seed_uuid('brigade-outbox-'||g),'brigade',pg_temp.seed_uuid('brigade-'||(1+g%40)),'brigade.updated','{}','SENT',1,now(),now(),now() FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
"@

Invoke-Postgres profile_db @"
$prefix
INSERT INTO user_profiles(id,user_id,full_name,phone,preferred_contact_method,created_at,updated_at) SELECT pg_temp.seed_uuid('profile-'||g),pg_temp.seed_uuid('user-'||g),'Сотрудник аналитики №'||g,'+7999'||lpad(g::text,7,'0'),'EMAIL',now(),now() FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO work_profiles(id,user_profile_id,department_id,employee_number,position,status,created_at,updated_at) SELECT pg_temp.seed_uuid('work-profile-'||g),pg_temp.seed_uuid('profile-'||g),pg_temp.seed_uuid('dep-'||(1+g%12)),'EMP-'||g,(ARRAY['Инженер','Мастер','Диспетчер'])[1+g%3],(ARRAY['ACTIVE','ON_SHIFT','OFF_SHIFT'])[1+g%3],now(),now() FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO certification_types(id,code,name,description,default_validity_days,requires_file,active) SELECT pg_temp.seed_uuid('cert-type-'||g),'CERT_'||g,'Сертификат №'||g,'Синтетический сертификат',365,g%2=0,true FROM generate_series(1,20) g ON CONFLICT DO NOTHING;
INSERT INTO certification_type_skills(id,certification_type_id,skill_id,proficiency_level,active) SELECT pg_temp.seed_uuid('cert-skill-'||g),pg_temp.seed_uuid('cert-type-'||(1+g%20)),pg_temp.seed_uuid('skill-'||(1+g%20)),'STANDARD',true FROM generate_series(1,60) g ON CONFLICT DO NOTHING;
INSERT INTO work_profile_certifications(id,work_profile_id,certification_type_id,certificate_number,issuer,issued_at,expires_at,status,verified_by_user_id,verified_at,created_at,updated_at) SELECT pg_temp.seed_uuid('cert-'||g),pg_temp.seed_uuid('work-profile-'||(1+g%GREATEST(100,$Scale/5))),pg_temp.seed_uuid('cert-type-'||(1+g%20)),'CERT-N-'||g,'Учебный центр',(current_date-(g%365))::date,(current_date+365-(g%365))::date,'VERIFIED',pg_temp.seed_uuid('user-1'),now(),now(),now() FROM generate_series(1,GREATEST(100,$Scale/3)) g ON CONFLICT DO NOTHING;
INSERT INTO work_profile_skill_grants(id,work_profile_id,skill_id,source_type,source_id,proficiency_level,active,created_at) SELECT pg_temp.seed_uuid('grant-'||g),pg_temp.seed_uuid('work-profile-'||(1+g%GREATEST(100,$Scale/5))),pg_temp.seed_uuid('skill-'||(1+g%20)),'CERTIFICATION',pg_temp.seed_uuid('cert-'||(1+g%GREATEST(100,$Scale/3))),'STANDARD',true,now() FROM generate_series(1,GREATEST(100,$Scale/3)) g ON CONFLICT DO NOTHING;
INSERT INTO work_profile_status_history(id,work_profile_id,from_status,to_status,reason,changed_by_user_id,created_at) SELECT pg_temp.seed_uuid('profile-status-'||g),pg_temp.seed_uuid('work-profile-'||(1+g%GREATEST(100,$Scale/5))),'OFF_SHIFT','ON_SHIFT','Начало смены',pg_temp.seed_uuid('user-1'),now()-(g%365||' days')::interval FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO processed_events(event_id,event_type,source_service,processed_at) SELECT pg_temp.seed_uuid('profile-event-'||g),'user.updated','auth',now() FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO idempotency_keys(actor_key,operation,idempotency_key,request_hash,status,response,created_at,updated_at,expires_at) SELECT 'seed','profile.seed','profile-seed-'||g,md5(g::text),'COMPLETED','{}',now(),now(),now()+interval '30 days' FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload,status,attempts,next_attempt_at,created_at,sent_at) SELECT pg_temp.seed_uuid('profile-outbox-'||g),'profile',pg_temp.seed_uuid('profile-'||(1+g%GREATEST(100,$Scale/5))),'profile.updated','{}','SENT',1,now(),now(),now() FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
"@

Invoke-Postgres dispatch @"
$prefix
INSERT INTO dispatch_operations(id,ticket_id,brigade_id,route_id,mode,status,version,requested_by,failure_reason,expires_at,created_at,updated_at,department_id,failure_code,category_id,priority,failure_stage,trigger_event_id)
SELECT pg_temp.seed_uuid('dispatch-'||g),pg_temp.seed_uuid('ticket-'||g),CASE WHEN g%5=0 THEN NULL ELSE pg_temp.seed_uuid('brigade-'||(1+g%40)) END,CASE WHEN g%5=0 THEN NULL ELSE pg_temp.seed_uuid('route-'||g) END,(ARRAY['AUTO','MANUAL'])[1+g%2],(ARRAY['PENDING','RESERVED','CONFIRMING','ASSIGNED','FAILED','CANCELLED','EXPIRED'])[1+g%7],1+g%4,pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),CASE WHEN g%7=4 THEN 'Нет подходящей бригады' END,now()+interval '2 hours',now()-(g%365||' days')::interval,now(),pg_temp.seed_uuid('dep-'||(1+g%12)),CASE WHEN g%7=4 THEN 'NO_BRIGADE' END,pg_temp.seed_uuid('cat-'||(1+g%16)),(ARRAY['LOW','MEDIUM','HIGH','EMERGENCY'])[1+g%4],CASE WHEN g%7=4 THEN 'RESERVATION' END,pg_temp.seed_uuid('dispatch-trigger-'||g)
FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO dispatch_outbox_events(id,aggregate_id,event_type,payload,status,attempts,next_attempt_at,created_at,sent_at) SELECT pg_temp.seed_uuid('dispatch-outbox-'||g),pg_temp.seed_uuid('dispatch-'||g),'dispatch.completed','{}','SENT',1,now(),now(),now() FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
"@

Invoke-Postgres routing @"
$prefix
INSERT INTO routes(id,ticket_id,brigade_id,status,origin,destination,waypoints,options,calculation,revision,created_at,updated_at)
SELECT pg_temp.seed_uuid('route-'||g),pg_temp.seed_uuid('ticket-'||g),pg_temp.seed_uuid('brigade-'||(1+g%40)),(ARRAY['PLANNED','ACTIVE','COMPLETED','CANCELLED'])[1+g%4],jsonb_build_object('latitude',55.6+(g%200)/1000.0,'longitude',37.4+(g%300)/1000.0),jsonb_build_object('latitude',55.61+(g%200)/1000.0,'longitude',37.41+(g%300)/1000.0),'[]','{"travel_mode":"auto"}',jsonb_build_object('distance_meters',1000+g%20000,'duration_seconds',300+g%3600),1+g%3,now()-(g%365||' days')::interval,now()
FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO ticket_inbox_events(event_id,event_type,topic,partition_id,message_offset,payload,processed_at) SELECT pg_temp.seed_uuid('routing-inbox-'||g),'ticket.updated','tickets.events.v1',g%6,g,'{}',now() FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload,status,attempts,next_attempt_at,created_at,sent_at) SELECT pg_temp.seed_uuid('routing-outbox-'||g),'route',pg_temp.seed_uuid('route-'||g),'route.updated','{}','SENT',1,now(),now(),now() FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
"@

Invoke-Postgres sla @"
$prefix
INSERT INTO sla_rules(id,name,department_id,category_id,priority,response_seconds,resolution_seconds,warning_percent,active) SELECT pg_temp.seed_uuid('sla-rule-'||g),'Правило SLA №'||g,pg_temp.seed_uuid('dep-'||(1+g%12)),pg_temp.seed_uuid('cat-'||(1+g%16)),(ARRAY['LOW','MEDIUM','HIGH','EMERGENCY'])[1+g%4],900*(1+g%4),7200*(1+g%4),80,true FROM generate_series(1,48) g ON CONFLICT DO NOTHING;
INSERT INTO ticket_slas(id,ticket_id,rule_id,department_id,category_id,priority,status,response_deadline,resolution_deadline,responded_at,completed_at,response_breached,resolution_breached,response_warning_sent,resolution_warning_sent,version,created_at,updated_at)
SELECT pg_temp.seed_uuid('ticket-sla-'||g),pg_temp.seed_uuid('ticket-'||g),pg_temp.seed_uuid('sla-rule-'||(1+g%48)),pg_temp.seed_uuid('dep-'||(1+g%12)),pg_temp.seed_uuid('cat-'||(1+g%16)),(ARRAY['LOW','MEDIUM','HIGH','EMERGENCY'])[1+g%4],(ARRAY['ACTIVE','COMPLETED','CANCELLED'])[1+g%3],now()-(g%365||' days')::interval+interval '1 hour',now()-(g%365||' days')::interval+interval '12 hours',now()-(g%365||' days')::interval+interval '30 minutes',CASE WHEN g%3=1 THEN now()-(g%365||' days')::interval+interval '8 hours' END,g%7=0,g%9=0,g%4=0,g%5=0,1,now()-(g%365||' days')::interval,now()
FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO sla_history(id,ticket_sla_id,ticket_id,event_type,details,occurred_at) SELECT pg_temp.seed_uuid('sla-history-'||g),pg_temp.seed_uuid('ticket-sla-'||(1+g%$Scale)),pg_temp.seed_uuid('ticket-'||(1+g%$Scale)),(ARRAY['CREATED','WARNING','BREACHED','COMPLETED'])[1+g%4],'Синтетическое событие SLA',now()-(g%365||' days')::interval FROM generate_series(1,$Scale*2) g ON CONFLICT DO NOTHING;
INSERT INTO ticket_event_inbox(event_id,event_type,ticket_id,payload,processed_at) SELECT 'sla-seed-'||g,'ticket.updated',pg_temp.seed_uuid('ticket-'||g),'{}',now() FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO outbox_events(id,aggregate_type,aggregate_id,event_type,payload,status,attempts,next_attempt_at,created_at,sent_at) SELECT pg_temp.seed_uuid('sla-outbox-'||g),'sla',pg_temp.seed_uuid('ticket-sla-'||g),'sla.updated','{}','SENT',1,now(),now(),now() FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
"@

Invoke-Postgres location @"
$prefix
INSERT INTO geo_zones(id,department_id,name,zone,active) SELECT pg_temp.seed_uuid('geo-zone-'||g),pg_temp.seed_uuid('dep-'||(1+g%12)),'Геозона №'||g,ST_GeomFromText('POLYGON(('||(37.2+g/1000.0)||' 55.4,'||(37.21+g/1000.0)||' 55.4,'||(37.21+g/1000.0)||' 55.41,'||(37.2+g/1000.0)||' 55.41,'||(37.2+g/1000.0)||' 55.4))',4326),true FROM generate_series(1,80) g ON CONFLICT DO NOTHING;
INSERT INTO position_history(id,event_id,device_id,vehicle_id,brigade_id,sequence,latitude,longitude,speed_kmh,heading,accuracy_meters,altitude_meters,simulated,recorded_at,received_at)
SELECT pg_temp.seed_uuid('position-'||g),pg_temp.seed_uuid('position-event-'||g),'seed-device-'||(1+g%80),pg_temp.seed_uuid('vehicle-'||(1+g%80)),pg_temp.seed_uuid('brigade-'||(1+g%40)),g,55.5+(g%300)/1000.0,37.3+(g%500)/1000.0,g%80,g%360,3+g%10,150+g%20,true,date_trunc('day',now())-(g%525600||' minutes')::interval,date_trunc('day',now())-(g%525600||' minutes')::interval+interval '1 second'
FROM generate_series(1,$Scale*5) g ON CONFLICT DO NOTHING;
"@

Invoke-Postgres asset @"
$prefix
INSERT INTO assets(id,external_id,department_id,type,name,address,district,municipality,geometry,status,model,serial_number,installation_year,service_life_years,owner,service_organization,contractor,inspection_interval_days,response_norm_minutes,repair_norm_minutes,criticality,risk_score,risk_level,created_at,updated_at)
SELECT pg_temp.seed_uuid('asset-'||g),'ASSET-'||g,pg_temp.seed_uuid('dep-'||(1+g%12)),(ARRAY['STREET_LIGHT','ROAD_SIGN','HYDRANT','TRAFFIC_LIGHT'])[1+g%4],'Объект №'||g,'Москва, объект '||g,'Район '||(g%20),'Москва',ST_SetSRID(ST_MakePoint(37.3+(g%500)/1000.0,55.5+(g%300)/1000.0),4326),(ARRAY['ACTIVE','DEGRADED','UNDER_REPAIR'])[1+g%3],'MODEL-'||(g%20),'SN-'||g,2000+g%25,20,'Город','Эксплуатация','Подрядчик',90,60,1440,(g%100)/100.0,(g%100)/100.0,(ARRAY['LOW','MEDIUM','HIGH','CRITICAL'])[1+g%4],now()-(g%365||' days')::interval,now()
FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO asset_status_history(id,asset_id,old_status,new_status,reason,changed_by,created_at) SELECT pg_temp.seed_uuid('asset-status-'||g),pg_temp.seed_uuid('asset-'||(1+g%GREATEST(100,$Scale/5))),'ACTIVE','DEGRADED','Плановая аналитическая фиксация',pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),now()-(g%365||' days')::interval FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO asset_incidents(id,asset_id,ticket_id,failure_type,description,source,priority,repeated,occurred_at) SELECT pg_temp.seed_uuid('incident-'||g),pg_temp.seed_uuid('asset-'||(1+g%GREATEST(100,$Scale/5))),pg_temp.seed_uuid('ticket-'||g),(ARRAY['FAILURE','LEAK','POWER_LOSS'])[1+g%3],'Синтетический инцидент','SEED',(ARRAY['LOW','MEDIUM','HIGH','EMERGENCY'])[1+g%4],g%5=0,now()-(g%365||' days')::interval FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO asset_repairs(id,asset_id,incident_id,ticket_id,brigade_id,description,replaced_components,duration_minutes,completed_at) SELECT pg_temp.seed_uuid('repair-'||g),pg_temp.seed_uuid('asset-'||(1+g%GREATEST(100,$Scale/5))),pg_temp.seed_uuid('incident-'||g),pg_temp.seed_uuid('ticket-'||g),pg_temp.seed_uuid('brigade-'||(1+g%40)),'Синтетический ремонт','Расходные материалы',30+g%600,now()-(g%365||' days')::interval FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO asset_inspections(id,asset_id,inspector_user_id,kind,result,defect_found,condition_score,recommendation,inspected_at) SELECT pg_temp.seed_uuid('inspection-'||g),pg_temp.seed_uuid('asset-'||(1+g%GREATEST(100,$Scale/5))),pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),'Плановый','Осмотр выполнен',g%4=0,(g%100)/100.0,'Следовать плану',now()-(g%365||' days')::interval FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO maintenance_plans(id,asset_id,kind,interval_days,next_due_at,active,last_completed_at) SELECT pg_temp.seed_uuid('plan-'||g),pg_temp.seed_uuid('asset-'||g),'Плановый осмотр',90,now()+((g%90)||' days')::interval,true,now()-interval '30 days' FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO failure_predictions(id,asset_id,risk_score,risk_level,failure_probability_90d,factors,recommended_action,calculated_at) SELECT pg_temp.seed_uuid('prediction-'||g),pg_temp.seed_uuid('asset-'||(1+g%GREATEST(100,$Scale/5))),(g%100)/100.0,(ARRAY['LOW','MEDIUM','HIGH','CRITICAL'])[1+g%4],(g%100)/100.0,jsonb_build_object('age',g%25,'incidents',g%8),'Плановый осмотр',now()-(g%365||' days')::interval FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO outbox_events(id,aggregate_id,event_type,payload,status,attempts,next_attempt_at,created_at,sent_at) SELECT pg_temp.seed_uuid('asset-outbox-'||g),pg_temp.seed_uuid('asset-'||(1+g%GREATEST(100,$Scale/5))),'asset.updated','{}','SENT',1,now(),now(),now() FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
"@

Invoke-Postgres notification @"
$prefix
INSERT INTO notification_preferences(user_id,in_app_enabled,push_enabled,email_enabled,sms_enabled,email,phone,updated_at) SELECT pg_temp.seed_uuid('user-'||g),true,g%2=0,true,g%5=0,'analytics.user'||g||'@city.local','+7999'||lpad(g::text,7,'0'),now() FROM generate_series(1,GREATEST(100,$Scale/5)) g ON CONFLICT DO NOTHING;
INSERT INTO devices(id,user_id,token,platform,active) SELECT pg_temp.seed_uuid('device-'||g),pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),'seed-device-token-'||g,(ARRAY['android','ios','web'])[1+g%3],true FROM generate_series(1,GREATEST(100,$Scale/3)) g ON CONFLICT DO NOTHING;
INSERT INTO notification_templates(id,event_type,channel,subject,body,active) SELECT pg_temp.seed_uuid('template-'||g),'analytics.event.'||g,(ARRAY['IN_APP','PUSH','EMAIL','SMS'])[1+g%4],'Событие №'||g,'Текст синтетического уведомления',true FROM generate_series(1,40) g ON CONFLICT DO NOTHING;
INSERT INTO notifications(id,event_id,user_id,event_type,title,body,data,read,read_at,created_at) SELECT pg_temp.seed_uuid('notification-'||g),'notification-seed-'||g,pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),'ticket.updated','Заявка обновлена','Синтетическое уведомление',jsonb_build_object('ticket_id',pg_temp.seed_uuid('ticket-'||g)),g%3=0,CASE WHEN g%3=0 THEN now() END,now()-(g%365||' days')::interval FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO deliveries(id,notification_id,channel,recipient,status,provider_id,attempts,next_attempt_at,created_at,updated_at) SELECT pg_temp.seed_uuid('delivery-'||g),pg_temp.seed_uuid('notification-'||g),(ARRAY['IN_APP','PUSH','EMAIL','SMS'])[1+g%4],'recipient-'||g,(ARRAY['PENDING','SENT','FAILED'])[1+g%3],'seed-provider',g%4,now(),now(),now() FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO event_inbox(event_id,event_type,topic,payload,processed_at) SELECT 'notification-inbox-'||g,'ticket.updated','tickets.events.v1','{}',now() FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
INSERT INTO ticket_recipients(ticket_id,user_id,department_id,brigade_id,updated_at) SELECT pg_temp.seed_uuid('ticket-'||g),pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),pg_temp.seed_uuid('dep-'||(1+g%12)),pg_temp.seed_uuid('brigade-'||(1+g%40)),now() FROM generate_series(1,$Scale) g ON CONFLICT DO NOTHING;
"@

Invoke-Postgres audit @"
$prefix
INSERT INTO audit_entries(id,event_id,topic,action,actor_id,entity_type,entity_id,request_id,trace_id,data,occurred_at,recorded_at) SELECT pg_temp.seed_uuid('audit-'||g),'audit-seed-'||g,(ARRAY['tickets.events.v1','dispatch.events.v1','assets.events.v1'])[1+g%3],(ARRAY['created','updated','completed','failed'])[1+g%4],pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),(ARRAY['ticket','dispatch','asset'])[1+g%3],pg_temp.seed_uuid('entity-'||g)::text,'seed-request-'||g,'seed-trace-'||(g%100),jsonb_build_object('seed',true,'sequence',g),now()-(g%365||' days')::interval,now()-(g%365||' days')::interval FROM generate_series(1,$Scale*5) g ON CONFLICT DO NOTHING;
"@

Invoke-Postgres file @"
$prefix
INSERT INTO files(id,owner_user_id,resource_type,resource_id,name,content_type,size,checksum,object_key,status,created_at,updated_at) SELECT pg_temp.seed_uuid('file-'||g),pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),'ticket_report',pg_temp.seed_uuid('ticket-report-'||(1+g%GREATEST(100,$Scale/2))),'analytics-file-'||g||'.pdf','application/pdf',1024+g,md5('file-'||g),'analytics-seed/'||g||'.pdf',(ARRAY['UPLOADED','LINKED','DELETED','QUARANTINED'])[1+g%4],now()-(g%365||' days')::interval,now() FROM generate_series(1,GREATEST(100,$Scale/2)) g ON CONFLICT DO NOTHING;
"@

Invoke-Postgres report @"
$prefix
INSERT INTO reports(id,requested_by,actor_roles,name,type,format,status,filter,file_id,error,attempts,created_at,updated_at,completed_at) SELECT pg_temp.seed_uuid('report-'||g),pg_temp.seed_uuid('user-'||(1+g%GREATEST(100,$Scale/5))),ARRAY['admin'],'Аналитический отчёт №'||g,(ARRAY['TICKET_OVERVIEW','SLA_SUMMARY','TICKET_BREAKDOWN','DAILY_TICKETS'])[1+g%4],(ARRAY['PDF','XLSX','CSV'])[1+g%3],(ARRAY['PENDING','PROCESSING','COMPLETED','FAILED','CANCELED'])[1+g%5],jsonb_build_object('days',1+g%365),CASE WHEN g%5=2 THEN pg_temp.seed_uuid('file-'||(1+g%GREATEST(100,$Scale/2))) END,CASE WHEN g%5=3 THEN 'Синтетическая ошибка' END,g%4,now()-(g%365||' days')::interval,now(),CASE WHEN g%5=2 THEN now() END FROM generate_series(1,GREATEST(100,$Scale/3)) g ON CONFLICT DO NOTHING;
INSERT INTO outbox_events(id,aggregate_id,event_type,payload,status,attempts,next_attempt_at,created_at,sent_at) SELECT pg_temp.seed_uuid('report-outbox-'||g),pg_temp.seed_uuid('report-'||(1+g%GREATEST(100,$Scale/3))),'report.completed','{}','SENT',1,now(),now(),now() FROM generate_series(1,GREATEST(100,$Scale/3)) g ON CONFLICT DO NOTHING;
"@

$clickhouseSql = @"
INSERT INTO analytics.domain_events
(topic,event_id,event_type,entity_id,ticket_id,department_id,category_id,brigade_id,user_id,priority,status,latitude,longitude,payload,occurred_at,version)
SELECT
    ['tickets.events.v1','dispatch.events.v1','assets.events.v1'][1+number%3],
    concat('analytics-volume-',toString(number)),
    if(number%6 < 4,
       ['ticket.created','ticket.assigned','ticket.status_changed','ticket.completed'][1+number%4],
       if(intDiv(number,6)%10 = 0,'dispatch.failed','dispatch.assigned')),
    toString(generateUUIDv4()),toString(generateUUIDv4()),toString(generateUUIDv4()),toString(generateUUIDv4()),toString(generateUUIDv4()),toString(generateUUIDv4()),
    ['LOW','MEDIUM','HIGH','EMERGENCY'][1+number%4],['NEW','ASSIGNED','IN_PROGRESS','DONE','FAILED'][1+number%5],
    55.5+(number%300)/1000,37.3+(number%500)/1000,'{\"seed\":true}',
    now64(3)-toIntervalMinute(number%525600),toUInt64(toUnixTimestamp64Milli(now64(3)))+number
FROM numbers($($Scale*10));
OPTIMIZE TABLE analytics.domain_events FINAL;
"@
$clickhouseSql | kubectl -n $Namespace exec -i clickhouse-0 -c clickhouse -- clickhouse-client --multiquery
if ($LASTEXITCODE -ne 0) { throw "Bulk seed failed for ClickHouse" }

Write-Host "Analytics volume seed completed (Scale=$Scale)."
