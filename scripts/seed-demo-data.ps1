param(
    [string]$BaseUrl = "http://localhost:8081",
    [string]$Password = "CityDemo123!",
    [ValidateSet("Compose", "Kubernetes")]
    [string]$Target = "Compose",
    [string]$Namespace = "automatic-system"
)

$ErrorActionPreference = "Stop"

function Get-ReadyPrimaryPod {
    param([string]$Selector)
    $result = kubectl get pods -n $Namespace -l $Selector -o json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to list primary pods for selector $Selector"
    }
    $pod = $result.items |
        Where-Object {
            $_.status.phase -eq "Running" -and
            ($_.status.containerStatuses | Where-Object { $_.name -eq "postgres" -and $_.ready })
        } |
        Select-Object -First 1
    if (-not $pod) {
        throw "Ready primary pod not found for selector $Selector"
    }
    return $pod.metadata.name
}

function Invoke-SeedSql {
    param([string]$Service, [string]$User, [string]$Database, [string]$Sql)
    # Windows PowerShell otherwise sends native-process stdin in the active OEM
    # code page and Cyrillic values reach PostgreSQL as question marks.
    $previousOutputEncoding = $OutputEncoding
    $previousClientEncoding = $env:PGCLIENTENCODING
    $script:OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $env:PGCLIENTENCODING = "UTF8"
    try {
        if ($Target -eq "Kubernetes") {
            $databaseMap = @{
                "postgres-auth" = "auth_db"
                "postgres-ticket" = "ticket_db"
                "postgres-department" = "department_db"
                "postgres-brigade" = "brigade_db"
                "postgres-profile" = "profile_db"
                "postgres-location" = "location"
                "postgres-routing" = "routing"
                "postgres-dispatch" = "dispatch"
                "postgres-file" = "file"
                "postgres-sla" = "sla"
                "postgres-notification" = "notification"
                "postgres-audit" = "audit"
                "postgres-report" = "report"
                "postgres-asset" = "asset"
            }
            $podSelector = if ($Service -eq "postgres-ticket") {
                "cluster-name=postgres-ticket-citus,citus-group=0,role=primary"
            } else {
                "cluster-name=postgres-platform,role=primary"
            }
            $pod = Get-ReadyPrimaryPod $podSelector
            $targetDatabase = $databaseMap[$Service]
            $Sql | kubectl exec -i -n $Namespace $pod -- psql -v ON_ERROR_STOP=1 -U postgres -d $targetDatabase
        }
        else {
            $Sql | docker compose exec -T $Service psql -v ON_ERROR_STOP=1 -U $User -d $Database
        }
        if ($LASTEXITCODE -ne 0) { throw "Seed failed for $Service" }
    }
    finally {
        $script:OutputEncoding = $previousOutputEncoding
        $env:PGCLIENTENCODING = $previousClientEncoding
    }
}

$accounts = @(
    @{ Email = "demo.admin@city.local"; Username = "demo_admin"; Role = "admin" },
    @{ Email = "demo.dispatcher@city.local"; Username = "demo_dispatcher"; Role = "dispatcher" },
    @{ Email = "demo.worker1@city.local"; Username = "demo_worker1"; Role = "worker" },
    @{ Email = "demo.worker2@city.local"; Username = "demo_worker2"; Role = "worker" },
    @{ Email = "demo.dispatch-worker1@city.local"; Username = "demo_dispatch_worker1"; Role = "worker" },
    @{ Email = "demo.dispatch-worker2@city.local"; Username = "demo_dispatch_worker2"; Role = "worker" },
    @{ Email = "demo.dispatch-worker3@city.local"; Username = "demo_dispatch_worker3"; Role = "worker" },
    @{ Email = "demo.user@city.local"; Username = "demo_user"; Role = "user" }
)

foreach ($account in $accounts) {
    try {
        Invoke-RestMethod -Uri "$BaseUrl/auth/register" -Method Post -ContentType "application/json" -Body (@{
            email = $account.Email
            password = $Password
            username = $account.Username
        } | ConvertTo-Json) | Out-Null
    }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 409) { throw }
    }
}

$roleValues = ($accounts | ForEach-Object { "('$($_.Email)','$($_.Role)')" }) -join ",`n"
Invoke-SeedSql "postgres-auth" "auth_user" "auth_db" @"
UPDATE users SET is_active = TRUE, email_verified = TRUE
WHERE email LIKE 'demo.%@city.local';
WITH desired(email, role_name) AS (VALUES
$roleValues
)
INSERT INTO user_roles(user_id, role_id)
SELECT users.id, roles.id FROM desired
JOIN users ON users.email = desired.email
JOIN roles ON roles.name = desired.role_name
ON CONFLICT (user_id, role_id) DO NOTHING;
"@

function Get-DemoUserId([string]$Email) {
    if ($Target -eq "Kubernetes") {
        $pod = Get-ReadyPrimaryPod "cluster-name=postgres-platform,role=primary"
        $value = kubectl exec -n $Namespace $pod -- psql -U postgres -d auth_db -At -c "SELECT id FROM users WHERE email='$Email'"
    }
    else {
        $value = docker compose exec -T postgres-auth psql -U auth_user -d auth_db -At -c "SELECT id FROM users WHERE email='$Email'"
    }
    if ($LASTEXITCODE -ne 0 -or -not $value) { throw "User not found: $Email" }
    return $value.Trim()
}

$adminId = Get-DemoUserId "demo.admin@city.local"
$dispatcherId = Get-DemoUserId "demo.dispatcher@city.local"
$worker1Id = Get-DemoUserId "demo.worker1@city.local"
$worker2Id = Get-DemoUserId "demo.worker2@city.local"
$dispatchWorker1Id = Get-DemoUserId "demo.dispatch-worker1@city.local"
$dispatchWorker2Id = Get-DemoUserId "demo.dispatch-worker2@city.local"
$dispatchWorker3Id = Get-DemoUserId "demo.dispatch-worker3@city.local"
$residentId = Get-DemoUserId "demo.user@city.local"

$depRoads = "10000000-0000-4000-8000-000000000001"
$depUtilities = "10000000-0000-4000-8000-000000000002"
$catRoad = "20000000-0000-4000-8000-000000000001"
$catLight = "20000000-0000-4000-8000-000000000002"
$catWater = "20000000-0000-4000-8000-000000000003"
$brigadeRoad = "30000000-0000-4000-8000-000000000001"
$brigadeUtility = "30000000-0000-4000-8000-000000000002"
$brigadeDispatchPrimary = "30000000-0000-4000-8000-000000000003"
$brigadeDispatchSecondary = "30000000-0000-4000-8000-000000000004"
$brigadeDispatchCancel = "30000000-0000-4000-8000-000000000005"
$skillRoad = "40000000-0000-4000-8000-000000000001"
$skillElectric = "40000000-0000-4000-8000-000000000002"
$skillWater = "40000000-0000-4000-8000-000000000003"
$userProfileWorker1 = "50000000-0000-4000-8000-000000000001"
$userProfileWorker2 = "50000000-0000-4000-8000-000000000002"
$userProfileDispatcher = "50000000-0000-4000-8000-000000000003"
$userProfileAdmin = "50000000-0000-4000-8000-000000000004"
$userProfileResident = "50000000-0000-4000-8000-000000000005"
$userProfileDispatchWorker1 = "50000000-0000-4000-8000-000000000006"
$userProfileDispatchWorker2 = "50000000-0000-4000-8000-000000000007"
$userProfileDispatchWorker3 = "50000000-0000-4000-8000-000000000008"
$workProfileWorker1 = "51000000-0000-4000-8000-000000000001"
$workProfileWorker2 = "51000000-0000-4000-8000-000000000002"
$workProfileDispatcher = "51000000-0000-4000-8000-000000000003"
$workProfileAdmin = "51000000-0000-4000-8000-000000000004"
$workProfileDispatchWorker1 = "51000000-0000-4000-8000-000000000005"
$workProfileDispatchWorker2 = "51000000-0000-4000-8000-000000000006"
$workProfileDispatchWorker3 = "51000000-0000-4000-8000-000000000007"
$ticketNew = "60000000-0000-4000-8000-000000000001"
$ticketAssigned = "60000000-0000-4000-8000-000000000002"
$ticketProgress = "60000000-0000-4000-8000-000000000003"
$ticketDone = "60000000-0000-4000-8000-000000000004"
$ticketEmergency = "60000000-0000-4000-8000-000000000005"
$ticketCanceled = "60000000-0000-4000-8000-000000000006"
$routePlanned = "70000000-0000-4000-8000-000000000001"
$routeActive = "70000000-0000-4000-8000-000000000002"

Invoke-SeedSql "postgres-department" "postgres" "departmentdb" @"
INSERT INTO departments(id,name,description,status) VALUES
('$depRoads','Дорожное хозяйство — демо','Дороги, знаки, остановки и освещение','ACTIVE'),
('$depUtilities','Городские коммуникации — демо','Водоснабжение, теплосети и аварийные работы','ACTIVE')
ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,status=EXCLUDED.status,updated_at=now();
"@

Invoke-SeedSql "postgres-ticket" "postgres" "ticketdb" @"
INSERT INTO ticket_categories(id,code,name,description,is_active,updated_at) VALUES
('$catRoad','DEMO_ROAD','Дорожное покрытие','Ямы, выбоины и повреждения полотна',TRUE,now()),
('$catLight','DEMO_LIGHT','Уличное освещение','Фонари, опоры и электропитание',TRUE,now()),
('$catWater','DEMO_WATER','Водоснабжение','Протечки и повреждения водопровода',TRUE,now())
ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,is_active=TRUE,updated_at=EXCLUDED.updated_at;
INSERT INTO tickets(id,department_id,user_id,brigade_id,title,description,category_id,priority,status,address,latitude,longitude,created_at,updated_at,assigned_at,completed_at,canceled_at) VALUES
('$ticketNew','$depRoads','$residentId',NULL,'Повреждён дорожный знак','Знак наклонён после сильного ветра, требуется восстановление.','$catRoad','MEDIUM','NEW','Тверская улица, 12',55.7622,37.6070,now()-interval '35 minutes',now()-interval '35 minutes',NULL,NULL,NULL),
('$ticketAssigned','$depRoads','$residentId','$brigadeRoad','Не работает освещение','Не горят три фонаря вдоль пешеходной зоны.','$catLight','HIGH','ASSIGNED','Страстной бульвар, 6',55.7650,37.6076,now()-interval '2 hours',now()-interval '25 minutes',now()-interval '25 minutes',NULL,NULL),
('$ticketProgress','$depUtilities','$residentId','$brigadeUtility','Повреждение водопровода','Сильная течь у проезжей части.','$catWater','EMERGENCY','IN_PROGRESS','Большая Дмитровка, 18',55.7611,37.6136,now()-interval '3 hours',now()-interval '18 minutes',now()-interval '45 minutes',NULL,NULL),
('$ticketDone','$depRoads','$residentId','$brigadeRoad','Яма на дороге устранена','Восстановлено асфальтовое покрытие во дворе.','$catRoad','HIGH','DONE','Петровка, 22',55.7665,37.6178,now()-interval '14 hours',now()-interval '2 hours',now()-interval '12 hours',now()-interval '2 hours',NULL),
('$ticketEmergency','$depUtilities','$residentId',NULL,'Открытый люк','Крышка люка отсутствует рядом с остановкой.','$catWater','EMERGENCY','NEW','Пречистенка, 31',55.7417,37.5905,now()-interval '12 minutes',now()-interval '12 minutes',NULL,NULL,NULL),
('$ticketCanceled','$depRoads','$residentId',NULL,'Ветка на проезжей части','Объект уже убран другой службой.','$catRoad','LOW','CANCELED','Чистопрудный бульвар, 9',55.7631,37.6385,now()-interval '10 hours',now()-interval '3 hours',NULL,NULL,now()-interval '3 hours')
ON CONFLICT (department_id,id) DO UPDATE SET brigade_id=EXCLUDED.brigade_id,title=EXCLUDED.title,description=EXCLUDED.description,priority=EXCLUDED.priority,status=EXCLUDED.status,address=EXCLUDED.address,latitude=EXCLUDED.latitude,longitude=EXCLUDED.longitude,updated_at=EXCLUDED.updated_at,assigned_at=EXCLUDED.assigned_at,completed_at=EXCLUDED.completed_at,canceled_at=EXCLUDED.canceled_at;
INSERT INTO ticket_status_history(id,department_id,ticket_id,old_status,new_status,changed_by,comment,created_at) VALUES
('61000000-0000-4000-8000-000000000001','$depUtilities','$ticketProgress','NEW','ASSIGNED','$dispatcherId','Назначена аварийная бригада',now()-interval '45 minutes'),
('61000000-0000-4000-8000-000000000002','$depUtilities','$ticketProgress','ASSIGNED','IN_PROGRESS','$worker2Id','Бригада прибыла на место',now()-interval '18 minutes'),
('61000000-0000-4000-8000-000000000003','$depRoads','$ticketDone','IN_PROGRESS','DONE','$worker1Id','Покрытие восстановлено и проверено',now()-interval '1 day')
ON CONFLICT (department_id,id) DO NOTHING;
INSERT INTO ticket_reports(id,department_id,ticket_id,author_user_id,description,created_at,updated_at) VALUES
('62000000-0000-4000-8000-000000000001','$depRoads','$ticketDone','$worker1Id','Повреждённый участок очищен, основание уплотнено, уложен новый асфальт. Состав: Алексей Смирнов, Ирина Волкова.',now()-interval '1 day',now()-interval '1 day')
ON CONFLICT (department_id,id) DO UPDATE SET description=EXCLUDED.description,updated_at=EXCLUDED.updated_at;
"@

Invoke-SeedSql "postgres-brigade" "postgres" "brigadedb" @"
INSERT INTO skills(id,code,name,description,active) VALUES
('$skillRoad','DEMO_ROAD_REPAIR','Ремонт дорожного покрытия','Локальный ремонт и восстановление асфальта',TRUE),
('$skillElectric','DEMO_ELECTRIC','Электробезопасность','Работы с городскими сетями освещения',TRUE),
('$skillWater','DEMO_WATER','Аварийный ремонт водопровода','Локализация и устранение течей',TRUE)
ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,active=TRUE,updated_at=now();
INSERT INTO brigades(id,department_id,name,description,status,specialization) VALUES
('$brigadeRoad','$depRoads','Бригада №14 — дорожная','Асфальт, знаки и элементы дорожной инфраструктуры','BUSY','Дорожные работы'),
('$brigadeUtility','$depUtilities','Бригада №7 — аварийная','Водоснабжение и срочные городские коммуникации','ON_ROUTE','Аварийные коммуникации'),
('$brigadeDispatchPrimary','$depRoads','Тестовая бригада диспетчеризации №1','Выделена для позитивных dispatch-сценариев','AVAILABLE','Диспетчеризация'),
('$brigadeDispatchSecondary','$depRoads','Тестовая бригада диспетчеризации №2','Выделена для auto dispatch-сценария','AVAILABLE','Диспетчеризация'),
('$brigadeDispatchCancel','$depRoads','Тестовая бригада диспетчеризации №3','Выделена для cancel dispatch-сценария','AVAILABLE','Диспетчеризация')
ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,status=EXCLUDED.status,specialization=EXCLUDED.specialization,updated_at=now();
INSERT INTO brigade_members(id,brigade_id,user_id,profile_id,role,active,availability_status) VALUES
('31000000-0000-4000-8000-000000000001','$brigadeRoad','$worker1Id','$workProfileWorker1','LEAD',TRUE,'UNAVAILABLE'),
('31000000-0000-4000-8000-000000000002','$brigadeUtility','$worker2Id','$workProfileWorker2','LEAD',TRUE,'UNAVAILABLE'),
('31000000-0000-4000-8000-000000000003','$brigadeDispatchPrimary','$dispatchWorker1Id','$workProfileDispatchWorker1','LEAD',TRUE,'AVAILABLE'),
('31000000-0000-4000-8000-000000000004','$brigadeDispatchSecondary','$dispatchWorker2Id','$workProfileDispatchWorker2','LEAD',TRUE,'AVAILABLE'),
('31000000-0000-4000-8000-000000000005','$brigadeDispatchCancel','$dispatchWorker3Id','$workProfileDispatchWorker3','LEAD',TRUE,'AVAILABLE')
ON CONFLICT (id) DO UPDATE SET brigade_id=EXCLUDED.brigade_id,role=EXCLUDED.role,active=TRUE,availability_status=EXCLUDED.availability_status,updated_at=now();
INSERT INTO brigade_skills(id,brigade_id,skill_id,active) VALUES
('32000000-0000-4000-8000-000000000001','$brigadeRoad','$skillRoad',TRUE),
('32000000-0000-4000-8000-000000000002','$brigadeRoad','$skillElectric',TRUE),
('32000000-0000-4000-8000-000000000003','$brigadeUtility','$skillWater',TRUE)
ON CONFLICT (id) DO UPDATE SET active=TRUE,updated_at=now();
DELETE FROM brigade_schedule WHERE brigade_id IN ('$brigadeRoad','$brigadeUtility','$brigadeDispatchPrimary','$brigadeDispatchSecondary','$brigadeDispatchCancel');
INSERT INTO brigade_schedule(id,brigade_id,day_of_week,starts_at,ends_at,timezone,active) SELECT gen_random_uuid(),'$brigadeRoad',day,'08:00','20:00','Europe/Moscow',TRUE FROM generate_series(1,5) day;
INSERT INTO brigade_schedule(id,brigade_id,day_of_week,starts_at,ends_at,timezone,active) SELECT gen_random_uuid(),'$brigadeUtility',day,'00:00','23:59','Europe/Moscow',TRUE FROM generate_series(1,7) day;
INSERT INTO brigade_schedule(id,brigade_id,day_of_week,starts_at,ends_at,timezone,active) SELECT gen_random_uuid(),'$brigadeDispatchPrimary',day,'00:00','23:59','Europe/Moscow',TRUE FROM generate_series(1,7) day;
INSERT INTO brigade_schedule(id,brigade_id,day_of_week,starts_at,ends_at,timezone,active) SELECT gen_random_uuid(),'$brigadeDispatchSecondary',day,'00:00','23:59','Europe/Moscow',TRUE FROM generate_series(1,7) day;
INSERT INTO brigade_schedule(id,brigade_id,day_of_week,starts_at,ends_at,timezone,active) SELECT gen_random_uuid(),'$brigadeDispatchCancel',day,'00:00','23:59','Europe/Moscow',TRUE FROM generate_series(1,7) day;
INSERT INTO brigade_zones(id,brigade_id,department_id,name,zone,priority,active) VALUES
('33000000-0000-4000-8000-000000000001','$brigadeRoad','$depRoads','Центральный дорожный сектор',ST_GeomFromText('POLYGON((37.56 55.72,37.66 55.72,37.66 55.79,37.56 55.79,37.56 55.72))',4326),10,TRUE),
('33000000-0000-4000-8000-000000000002','$brigadeUtility','$depUtilities','Центральный аварийный сектор',ST_GeomFromText('POLYGON((37.58 55.73,37.69 55.73,37.69 55.81,37.58 55.81,37.58 55.73))',4326),20,TRUE),
('33000000-0000-4000-8000-000000000003','$brigadeDispatchPrimary','$depRoads','Тестовый сектор диспетчеризации №1',ST_GeomFromText('POLYGON((37.56 55.72,37.66 55.72,37.66 55.79,37.56 55.79,37.56 55.72))',4326),30,TRUE),
('33000000-0000-4000-8000-000000000004','$brigadeDispatchSecondary','$depRoads','Тестовый сектор диспетчеризации №2',ST_GeomFromText('POLYGON((37.56 55.72,37.66 55.72,37.66 55.79,37.56 55.79,37.56 55.72))',4326),40,TRUE),
('33000000-0000-4000-8000-000000000005','$brigadeDispatchCancel','$depRoads','Тестовый сектор диспетчеризации №3',ST_GeomFromText('POLYGON((37.56 55.72,37.66 55.72,37.66 55.79,37.56 55.79,37.56 55.72))',4326),50,TRUE)
ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,zone=EXCLUDED.zone,priority=EXCLUDED.priority,active=TRUE,updated_at=now();
"@

Invoke-SeedSql "postgres-profile" "profile_user" "profile_db" @"
INSERT INTO user_profiles(id,user_id,full_name,phone,preferred_contact_method) VALUES
('$userProfileWorker1','$worker1Id','Алексей Смирнов','+79001001001','PHONE'),
('$userProfileWorker2','$worker2Id','Ирина Волкова','+79001001002','PHONE'),
('$userProfileDispatcher','$dispatcherId','Мария Орлова','+79001001003','EMAIL'),
('$userProfileAdmin','$adminId','Администратор системы',NULL,'EMAIL'),
('$userProfileResident','$residentId','Демо-житель',NULL,'EMAIL'),
('$userProfileDispatchWorker1','$dispatchWorker1Id','Тестовый диспетчерский работник 1',NULL,'EMAIL'),
('$userProfileDispatchWorker2','$dispatchWorker2Id','Тестовый диспетчерский работник 2',NULL,'EMAIL'),
('$userProfileDispatchWorker3','$dispatchWorker3Id','Тестовый диспетчерский работник 3',NULL,'EMAIL')
ON CONFLICT (user_id) DO UPDATE SET
id=EXCLUDED.id,
full_name=EXCLUDED.full_name,
phone=EXCLUDED.phone,
preferred_contact_method=EXCLUDED.preferred_contact_method,
updated_at=now();
INSERT INTO work_profiles(id,user_profile_id,department_id,employee_number,position,status) VALUES
('$workProfileWorker1','$userProfileWorker1','$depRoads','DEMO-001','Мастер дорожных работ','ACTIVE'),
('$workProfileWorker2','$userProfileWorker2','$depUtilities','DEMO-002','Аварийный техник','ACTIVE'),
('$workProfileDispatcher','$userProfileDispatcher','$depRoads','DEMO-003','Диспетчер','ACTIVE'),
('$workProfileAdmin','$userProfileAdmin','$depRoads','DEMO-004','Администратор системы','ACTIVE'),
('$workProfileDispatchWorker1','$userProfileDispatchWorker1','$depRoads','DEMO-005','Тестовый выездной специалист 1','ACTIVE'),
('$workProfileDispatchWorker2','$userProfileDispatchWorker2','$depRoads','DEMO-006','Тестовый выездной специалист 2','ACTIVE'),
('$workProfileDispatchWorker3','$userProfileDispatchWorker3','$depRoads','DEMO-007','Тестовый выездной специалист 3','ACTIVE')
ON CONFLICT (id) DO UPDATE SET
department_id=EXCLUDED.department_id,
position=EXCLUDED.position,
status='ACTIVE',
deactivated_at=NULL,
updated_at=now();
INSERT INTO certification_types(id,code,name,description,default_validity_days,requires_file,active) VALUES
('52000000-0000-4000-8000-000000000001','DEMO_ELECTRIC_CERT','Допуск к электроустановкам','Группа электробезопасности для городского освещения',365,TRUE,TRUE),
('52000000-0000-4000-8000-000000000002','DEMO_ROAD_CERT','Безопасность дорожных работ','Организация работ в зоне движения',730,TRUE,TRUE)
ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,active=TRUE,updated_at=now();
INSERT INTO work_profile_certifications(id,work_profile_id,certification_type_id,certificate_number,issuer,issued_at,expires_at,status,verified_by_user_id,verified_at) VALUES
('53000000-0000-4000-8000-000000000001','$workProfileWorker1','52000000-0000-4000-8000-000000000002','ДР-2026-014','Учебный центр городских служб',current_date-90,current_date+640,'VERIFIED','$adminId',now()-interval '80 days'),
('53000000-0000-4000-8000-000000000002','$workProfileWorker2','52000000-0000-4000-8000-000000000001','ЭБ-2026-077','МосЭнергоОбучение',current_date-40,current_date+325,'PENDING',NULL,NULL)
ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status,expires_at=EXCLUDED.expires_at,updated_at=now();
INSERT INTO work_profile_skill_grants(id,work_profile_id,skill_id,source_type,proficiency_level,active) VALUES
('54000000-0000-4000-8000-000000000001','$workProfileWorker1','$skillRoad','MANUAL','Эксперт',TRUE),
('54000000-0000-4000-8000-000000000002','$workProfileWorker2','$skillWater','MANUAL','Старший специалист',TRUE)
ON CONFLICT (id) DO UPDATE SET proficiency_level=EXCLUDED.proficiency_level,active=TRUE,revoked_at=NULL;
"@

Invoke-SeedSql "postgres-routing" "routing" "routing" @"
INSERT INTO routes(id,ticket_id,brigade_id,status,origin,destination,waypoints,options,calculation,revision) VALUES
('$routePlanned','$ticketAssigned','$brigadeRoad','PLANNED','{"latitude":55.7505,"longitude":37.6030}','{"latitude":55.7650,"longitude":37.6076}','[]','{"travel_mode":"auto"}','{"distance_meters":2400,"duration_seconds":540,"encoded_polyline":""}',1),
('$routeActive','$ticketProgress','$brigadeUtility','ACTIVE','{"latitude":55.7550,"longitude":37.6250}','{"latitude":55.7611,"longitude":37.6136}','[]','{"travel_mode":"auto"}','{"distance_meters":1800,"duration_seconds":420,"encoded_polyline":""}',2)
ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status,origin=EXCLUDED.origin,destination=EXCLUDED.destination,calculation=EXCLUDED.calculation,updated_at=now();
"@

Invoke-SeedSql "postgres-dispatch" "dispatch" "dispatch" @"
INSERT INTO dispatch_operations(id,ticket_id,brigade_id,route_id,mode,status,version,requested_by,failure_reason,expires_at,created_at,updated_at) VALUES
('80000000-0000-4000-8000-000000000001','$ticketAssigned','$brigadeRoad','$routePlanned','MANUAL','ASSIGNED',2,'$dispatcherId',NULL,now()+interval '2 hours',now()-interval '25 minutes',now()-interval '25 minutes'),
('80000000-0000-4000-8000-000000000002','$ticketProgress','$brigadeUtility','$routeActive','AUTO','ASSIGNED',3,'$dispatcherId',NULL,now()+interval '2 hours',now()-interval '45 minutes',now()-interval '18 minutes'),
('80000000-0000-4000-8000-000000000003','$ticketCanceled',NULL,NULL,'AUTO','FAILED',1,'$dispatcherId','Нет доступной бригады нужной квалификации',now()-interval '1 day',now()-interval '2 days',now()-interval '2 days')
ON CONFLICT (id) DO UPDATE SET brigade_id=EXCLUDED.brigade_id,route_id=EXCLUDED.route_id,status=EXCLUDED.status,version=EXCLUDED.version,failure_reason=EXCLUDED.failure_reason,updated_at=EXCLUDED.updated_at;
"@

Invoke-SeedSql "postgres-sla" "sla" "sla" @"
INSERT INTO sla_rules(id,name,department_id,category_id,priority,response_seconds,resolution_seconds,warning_percent,active) VALUES
('90000000-0000-4000-8000-000000000001','Экстренное водоснабжение','$depUtilities','$catWater','EMERGENCY',600,7200,70,TRUE),
('90000000-0000-4000-8000-000000000002','Дорожные повреждения высокого приоритета','$depRoads','$catRoad','HIGH',1800,14400,80,TRUE),
('90000000-0000-4000-8000-000000000003','Освещение высокого приоритета','$depRoads','$catLight','HIGH',1200,10800,75,TRUE)
ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,response_seconds=EXCLUDED.response_seconds,resolution_seconds=EXCLUDED.resolution_seconds,warning_percent=EXCLUDED.warning_percent,active=TRUE,updated_at=now();
INSERT INTO ticket_slas(id,ticket_id,rule_id,department_id,category_id,priority,status,response_deadline,resolution_deadline,responded_at,completed_at,response_breached,resolution_breached,response_warning_sent,resolution_warning_sent) VALUES
('91000000-0000-4000-8000-000000000001','$ticketProgress','90000000-0000-4000-8000-000000000001','$depUtilities','$catWater','EMERGENCY','ACTIVE',now()-interval '2 hours 50 minutes',now()+interval '4 hours',now()-interval '2 hours 45 minutes',NULL,FALSE,FALSE,TRUE,FALSE),
('91000000-0000-4000-8000-000000000002','$ticketAssigned','90000000-0000-4000-8000-000000000003','$depRoads','$catLight','HIGH','ACTIVE',now()-interval '1 hour 40 minutes',now()+interval '1 hour',now()-interval '25 minutes',NULL,TRUE,FALSE,TRUE,TRUE),
('91000000-0000-4000-8000-000000000003','$ticketDone','90000000-0000-4000-8000-000000000002','$depRoads','$catRoad','HIGH','COMPLETED',now()-interval '47 hours',now()-interval '28 hours',now()-interval '46 hours',now()-interval '1 day',FALSE,FALSE,TRUE,TRUE)
ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status,response_deadline=EXCLUDED.response_deadline,resolution_deadline=EXCLUDED.resolution_deadline,responded_at=EXCLUDED.responded_at,completed_at=EXCLUDED.completed_at,response_breached=EXCLUDED.response_breached,resolution_breached=EXCLUDED.resolution_breached,updated_at=now();
INSERT INTO sla_history(id,ticket_sla_id,ticket_id,event_type,details,occurred_at) VALUES
('92000000-0000-4000-8000-000000000001','91000000-0000-4000-8000-000000000002','$ticketAssigned','RESPONSE_BREACHED','Бригада назначена позже нормы реакции',now()-interval '25 minutes'),
('92000000-0000-4000-8000-000000000002','91000000-0000-4000-8000-000000000003','$ticketDone','COMPLETED','Заявка выполнена в пределах срока решения',now()-interval '1 day')
ON CONFLICT (id) DO NOTHING;
"@

Invoke-SeedSql "postgres-notification" "notification" "notification" @"
INSERT INTO notification_preferences(user_id,in_app_enabled,push_enabled,email_enabled,sms_enabled,email,phone) VALUES
('$adminId',TRUE,TRUE,TRUE,FALSE,'demo.admin@city.local',NULL),
('$dispatcherId',TRUE,TRUE,TRUE,FALSE,'demo.dispatcher@city.local',NULL),
('$residentId',TRUE,FALSE,TRUE,FALSE,'demo.user@city.local',NULL)
ON CONFLICT (user_id) DO UPDATE SET in_app_enabled=TRUE,email_enabled=TRUE,updated_at=now();
INSERT INTO notification_templates(id,event_type,channel,subject,body,active) VALUES
('a1000000-0000-4000-8000-000000000001','ticket.assigned','IN_APP','Бригада назначена','По заявке {{ticket_id}} назначена бригада {{brigade_id}}.',TRUE),
('a1000000-0000-4000-8000-000000000002','ticket.completed','EMAIL','Работы завершены','Заявка {{ticket_id}} выполнена. Отчёт доступен в личном кабинете.',TRUE),
('a1000000-0000-4000-8000-000000000003','sla.warning','IN_APP','Риск нарушения SLA','По заявке {{ticket_id}} приближается контрольный срок.',TRUE)
ON CONFLICT (event_type,channel) DO UPDATE SET subject=EXCLUDED.subject,body=EXCLUDED.body,active=TRUE,updated_at=now();
INSERT INTO notifications(id,event_id,user_id,event_type,title,body,data,read,created_at) VALUES
('a0000000-0000-4000-8000-000000000001','demo-ticket-assigned','$residentId','ticket.assigned','Бригада назначена','Дорожная бригада №14 выехала по заявке об освещении','{"ticket_id":"$ticketAssigned","brigade_id":"$brigadeRoad"}',FALSE,now()-interval '25 minutes'),
('a0000000-0000-4000-8000-000000000002','demo-sla-warning','$dispatcherId','sla.warning','Риск нарушения SLA','Для заявки по освещению превышено время реакции','{"ticket_id":"$ticketAssigned"}',FALSE,now()-interval '10 minutes'),
('a0000000-0000-4000-8000-000000000003','demo-ticket-done','$residentId','ticket.completed','Работы завершены','Повреждение дорожного покрытия устранено','{"ticket_id":"$ticketDone"}',TRUE,now()-interval '1 day')
ON CONFLICT (id) DO UPDATE SET title=EXCLUDED.title,body=EXCLUDED.body,data=EXCLUDED.data,read=EXCLUDED.read,created_at=EXCLUDED.created_at;
INSERT INTO deliveries(id,notification_id,channel,recipient,status,provider_id,attempts,next_attempt_at,created_at,updated_at) VALUES
('a2000000-0000-4000-8000-000000000001','a0000000-0000-4000-8000-000000000001','IN_APP','demo.user@city.local','SENT','local-websocket',1,now(),now()-interval '25 minutes',now()-interval '25 minutes'),
('a2000000-0000-4000-8000-000000000002','a0000000-0000-4000-8000-000000000003','EMAIL','demo.user@city.local','SENT','mailhog-demo',1,now(),now()-interval '1 day',now()-interval '1 day'),
('a2000000-0000-4000-8000-000000000003','a0000000-0000-4000-8000-000000000002','PUSH','demo-dispatcher-device','FAILED',NULL,3,now()+interval '15 minutes',now()-interval '10 minutes',now())
ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status,provider_id=EXCLUDED.provider_id,attempts=EXCLUDED.attempts,updated_at=now();
"@

Invoke-SeedSql "postgres-audit" "audit" "audit" @"
INSERT INTO audit_entries(id,event_id,topic,action,actor_id,entity_type,entity_id,request_id,trace_id,data,occurred_at) VALUES
('b0000000-0000-4000-8000-000000000001','demo-audit-1','tickets.events.v1','ticket.created','$residentId','ticket','$ticketProgress','demo-request-1','demo-trace-1','{"title":"Повреждение водопровода","priority":"EMERGENCY"}',now()-interval '3 hours'),
('b0000000-0000-4000-8000-000000000002','demo-audit-2','dispatch.events.v1','dispatch.assigned','$dispatcherId','dispatch','80000000-0000-4000-8000-000000000002','demo-request-2','demo-trace-2','{"ticket_id":"$ticketProgress","brigade_id":"$brigadeUtility"}',now()-interval '45 minutes'),
('b0000000-0000-4000-8000-000000000003','demo-audit-3','tickets.events.v1','ticket.completed','$worker1Id','ticket','$ticketDone','demo-request-3','demo-trace-3','{"report_id":"62000000-0000-4000-8000-000000000001"}',now()-interval '1 day')
ON CONFLICT (id) DO NOTHING;
"@

Invoke-SeedSql "postgres-report" "report" "report" @"
INSERT INTO reports(id,requested_by,name,type,format,status,filter,file_id,error,attempts,created_at,updated_at,completed_at,actor_roles) VALUES
('c0000000-0000-4000-8000-000000000001','$adminId','Сводка обращений за неделю','TICKET_OVERVIEW','PDF','COMPLETED','{"period":"7d"}',NULL,NULL,1,now()-interval '2 hours',now()-interval '1 hour 58 minutes',now()-interval '1 hour 58 minutes',ARRAY['admin']),
('c0000000-0000-4000-8000-000000000002','$dispatcherId','Контроль SLA за смену','SLA_SUMMARY','XLSX','COMPLETED','{"shift":"current"}',NULL,NULL,1,now()-interval '1 hour',now()-interval '58 minutes',now()-interval '58 minutes',ARRAY['dispatcher','admin']),
('c0000000-0000-4000-8000-000000000003','$adminId','Распределение обращений по инфраструктуре','TICKET_BREAKDOWN','CSV','FAILED','{}',NULL,'Тестовая ошибка генерации для проверки интерфейса',2,now()-interval '30 minutes',now()-interval '25 minutes',NULL,ARRAY['admin'])
ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status,error=EXCLUDED.error,attempts=EXCLUDED.attempts,updated_at=EXCLUDED.updated_at,completed_at=EXCLUDED.completed_at;
"@

Invoke-SeedSql "postgres-asset" "asset" "asset" @"
INSERT INTO assets(id,external_id,department_id,type,name,address,district,municipality,geometry,status,model,serial_number,installation_year,service_life_years,owner,service_organization,contractor,inspection_interval_days,response_norm_minutes,repair_norm_minutes,criticality,risk_score,risk_level,next_inspection_at) VALUES
('d0000000-0000-4000-8000-000000000001','DEMO-LIGHT-124','$depRoads','STREET_LIGHT','Опора освещения №124','Тверская улица, 12','Тверской','ЦАО',ST_SetSRID(ST_MakePoint(37.6070,55.7622),4326),'ACTIVE','ГС-LED-120','SL-2021-124',2021,20,'Город Москва','Моссвет','СветТехСервис',90,60,480,0.65,0.18,'LOW',now()+interval '18 days'),
('d0000000-0000-4000-8000-000000000002','DEMO-HYDRANT-77','$depUtilities','FIRE_HYDRANT','Пожарный гидрант №77','Большая Дмитровка, 18','Тверской','ЦАО',ST_SetSRID(ST_MakePoint(37.6136,55.7611),4326),'DEGRADED','ПГ-150','HG-2014-077',2014,25,'Город Москва','Мосводоканал','ГидроСервис',180,30,240,0.9,0.72,'HIGH',now()-interval '3 days'),
('d0000000-0000-4000-8000-000000000003','DEMO-SIGN-12','$depRoads','ROAD_SIGN','Дорожный знак 3.27','Страстной бульвар, 6','Тверской','ЦАО',ST_SetSRID(ST_MakePoint(37.6076,55.7650),4326),'UNDER_REPAIR','ГОСТ 52290','RS-2019-012',2019,12,'Город Москва','ЦОДД','ДорЗнак',365,120,720,0.45,0.41,'MEDIUM',now()+interval '120 days')
ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,address=EXCLUDED.address,status=EXCLUDED.status,criticality=EXCLUDED.criticality,risk_score=EXCLUDED.risk_score,risk_level=EXCLUDED.risk_level,updated_at=now();
INSERT INTO asset_incidents(id,asset_id,ticket_id,failure_type,description,source,priority,repeated,occurred_at) VALUES
('d1000000-0000-4000-8000-000000000001','d0000000-0000-4000-8000-000000000002','$ticketProgress','LEAK','Падение давления и течь возле колодца','WEB','EMERGENCY',FALSE,now()-interval '3 hours')
ON CONFLICT (id) DO UPDATE SET description=EXCLUDED.description,occurred_at=EXCLUDED.occurred_at;
INSERT INTO asset_inspections(id,asset_id,inspector_user_id,kind,result,defect_found,condition_score,recommendation,inspected_at) VALUES
('d2000000-0000-4000-8000-000000000001','d0000000-0000-4000-8000-000000000001','$worker1Id','Плановый осмотр','Опора устойчива, светильник исправен',FALSE,0.92,'Следующий осмотр по графику',now()-interval '14 days'),
('d2000000-0000-4000-8000-000000000002','d0000000-0000-4000-8000-000000000002','$worker2Id','Аварийный осмотр','Обнаружена коррозия соединения',TRUE,0.42,'Заменить соединительный узел',now()-interval '2 hours')
ON CONFLICT (id) DO UPDATE SET result=EXCLUDED.result,condition_score=EXCLUDED.condition_score,inspected_at=EXCLUDED.inspected_at;
INSERT INTO asset_repairs(id,asset_id,incident_id,ticket_id,brigade_id,description,replaced_components,duration_minutes,completed_at) VALUES
('d3000000-0000-4000-8000-000000000001','d0000000-0000-4000-8000-000000000003',NULL,'$ticketDone','$brigadeRoad','Восстановлено крепление дорожного знака','Крепёжный комплект',75,now()-interval '1 day')
ON CONFLICT (id) DO UPDATE SET description=EXCLUDED.description,completed_at=EXCLUDED.completed_at;
INSERT INTO maintenance_plans(id,asset_id,kind,interval_days,next_due_at,active) VALUES
('d4000000-0000-4000-8000-000000000001','d0000000-0000-4000-8000-000000000001','Плановый осмотр',90,now()+interval '18 days',TRUE),
('d4000000-0000-4000-8000-000000000002','d0000000-0000-4000-8000-000000000002','Проверка давления',30,now()+interval '5 days',TRUE)
ON CONFLICT (id) DO UPDATE SET next_due_at=EXCLUDED.next_due_at,active=TRUE;
INSERT INTO failure_predictions(id,asset_id,risk_score,risk_level,failure_probability_90d,factors,recommended_action,calculated_at) VALUES
('d5000000-0000-4000-8000-000000000001','d0000000-0000-4000-8000-000000000002',0.72,'HIGH',0.64,'{"age":0.35,"recent_incident":0.9,"condition":0.58}','Выполнить замену соединительного узла в течение 5 дней',now())
ON CONFLICT (id) DO UPDATE SET risk_score=EXCLUDED.risk_score,risk_level=EXCLUDED.risk_level,factors=EXCLUDED.factors,recommended_action=EXCLUDED.recommended_action,calculated_at=now();
"@

Invoke-SeedSql "postgres-location" "location" "location" @"
DELETE FROM position_history
WHERE id IN (
'e0000000-0000-4000-8000-000000000001',
'e0000000-0000-4000-8000-000000000002',
'e0000000-0000-4000-8000-000000000003'
);
INSERT INTO position_history(id,event_id,device_id,vehicle_id,brigade_id,sequence,latitude,longitude,speed_kmh,heading,accuracy_meters,simulated,recorded_at) VALUES
('e0000000-0000-4000-8000-000000000001','e1000000-0000-4000-8000-000000000001','demo-road-1','e2000000-0000-4000-8000-000000000001','$brigadeRoad',1,55.7548,37.6045,26,35,4,TRUE,now()-interval '1 minute'),
('e0000000-0000-4000-8000-000000000002','e1000000-0000-4000-8000-000000000002','demo-road-2','e2000000-0000-4000-8000-000000000002','$brigadeRoad',1,55.7550,37.6048,25,35,4,TRUE,now()-interval '1 minute'),
('e0000000-0000-4000-8000-000000000003','e1000000-0000-4000-8000-000000000003','demo-utility-1','e2000000-0000-4000-8000-000000000003','$brigadeUtility',1,55.7587,37.6200,18,290,5,TRUE,now()-interval '30 seconds');
"@

$clickhouseSql = @"
INSERT INTO analytics.domain_events(topic,event_id,event_type,entity_id,ticket_id,department_id,category_id,brigade_id,user_id,priority,status,latitude,longitude,payload,occurred_at,version) VALUES
('tickets.events.v1','demo-analytics-created-1','ticket.created','$ticketProgress','$ticketProgress','$depUtilities','$catWater','$brigadeUtility','$residentId','EMERGENCY','IN_PROGRESS',55.7611,37.6136,'{}',now64(3)-INTERVAL 3 HOUR,1),
('tickets.events.v1','demo-analytics-created-2','ticket.created','$ticketAssigned','$ticketAssigned','$depRoads','$catLight','$brigadeRoad','$residentId','HIGH','ASSIGNED',55.7650,37.6076,'{}',now64(3)-INTERVAL 2 HOUR,1),
('tickets.events.v1','demo-analytics-created-3','ticket.created','$ticketNew','$ticketNew','$depRoads','$catRoad','','$residentId','MEDIUM','NEW',55.7622,37.6070,'{}',now64(3)-INTERVAL 35 MINUTE,1),
('tickets.events.v1','demo-analytics-done-1','ticket.completed','$ticketDone','$ticketDone','$depRoads','$catRoad','$brigadeRoad','$residentId','HIGH','DONE',55.7665,37.6178,'{}',now64(3)-INTERVAL 1 DAY,2);
"@
if ($Target -eq "Kubernetes") {
    $analyticsSeedCount = kubectl exec -n $Namespace clickhouse-0 -- clickhouse-client --query "SELECT count() FROM analytics.domain_events WHERE event_id LIKE 'demo-analytics-%'"
}
else {
    $analyticsSeedCount = docker compose exec -T clickhouse clickhouse-client --query "SELECT count() FROM analytics.domain_events WHERE event_id LIKE 'demo-analytics-%'"
}
if ($LASTEXITCODE -ne 0) { throw "Could not inspect ClickHouse seed" }
if ([int]$analyticsSeedCount -eq 0) {
    if ($Target -eq "Kubernetes") {
        $clickhouseSql | kubectl exec -i -n $Namespace clickhouse-0 -- clickhouse-client --multiquery
    }
    else {
        $clickhouseSql | docker compose exec -T clickhouse clickhouse-client --multiquery
    }
    if ($LASTEXITCODE -ne 0) { throw "Seed failed for ClickHouse" }
}

Write-Host "Demo data seeded successfully."
Write-Host "Admin:      demo.admin@city.local / $Password"
Write-Host "Dispatcher: demo.dispatcher@city.local / $Password"
Write-Host "Worker:     demo.worker1@city.local / $Password"
Write-Host "Resident:   demo.user@city.local / $Password"
