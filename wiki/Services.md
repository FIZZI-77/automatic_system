# Сервисы

| Компонент | Ответственность |
|---|---|
| [API Gateway](API-Gateway) | Внешний HTTP API, auth middleware, transport mapping. |
| [Auth](Auth-Service) | Accounts, sessions, JWT, password/email flows. |
| [Profile](Profile-Service) | Personal/work profiles, certifications, skills. |
| [Department](Department-Service) | Department directory and lifecycle. |
| [Brigade](Brigade-Service) | Crews, members, skills, schedules, zones, readiness. |
| [Ticket](Ticket-Service) | Ticket aggregate, status/history, categories, work reports. |
| [Dispatch](Dispatch-Service) | Manual/automatic assignment workflow. |
| [Location](Location-Service) | Current GPS, history, nearby search, geozones. |
| [Routing](Routing-Service) | Routes, ETA/distance, candidate ranking. |
| [Asset](Asset-Service) | City assets, incidents, repairs, inspections, risk. |
| [File](File-Service) | File metadata and S3 presigned access. |
| [SLA](SLA-Service) | Response/resolution deadlines and breach detection. |
| [Notification](Notification-Service) | Durable user notifications and delivery channels. |
| [Audit](Audit-Service) | Immutable event audit log. |
| [Analytics](Analytics-Service) | ClickHouse event projection and metrics. |
| [Report](Report-Service) | PDF/XLSX/CSV jobs and completion documents. |
| [Frontend](Frontend) | Role-based web application. |
| [Transponder Simulator](Transponder-Simulator) | GPS telemetry simulator. |
