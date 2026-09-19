# Локальная разработка

## Требования

Для Kubernetes local flow документация предполагает:

- Docker Desktop с Kubernetes;
- `kubectl`;
- PowerShell;
- Docker Engine.

Проверка:

```powershell
docker info
kubectl cluster-info
kubectl get nodes
```

## Простой локальный Kubernetes

```powershell
.\k8s\scripts\apply.ps1
```

Flow создаёт local runtime secrets, infrastructure, migrations и Helm application release.

## Локальный отказоустойчивый контур

```powershell
.\k8s\scripts\start-local-ha.ps1
```

Используется для проверки HA-oriented topology, Istio и более полного infrastructure flow.

## Клиентское приложение

```powershell
cd Frontend
Copy-Item .env.example .env.local
npm install
npm run dev
```

Gateway URL задаётся environment variables.

## Демонстрационные данные

```powershell
powershell -ExecutionPolicy Bypass -File scripts/seed-demo-data.ps1
```

Seed script описан как идемпотентный для фиксированных demo records.

## Сквозная проверка

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run-e2e.ps1
```

Для `local-ha` есть отдельный `k8s/scripts/run-local-ha-e2e.ps1`.

## Перед изменением инфраструктуры

1. Выполнить рендеринг Kustomize.
2. Выполнить рендеринг и проверку Helm.
3. Проверить namespaces/selectors/images/secrets.
4. Проверить backward-compatible migrations.
5. Применить в local/local-ha.
6. Проверить events/readiness/metrics/traces.
7. Только затем переносить immutable tags в production flow.

### Источники
- [Deployment guide](https://github.com/FIZZI-77/automatic_system/blob/test/k8s/docs/deployment.md)
- [Frontend README](https://github.com/FIZZI-77/automatic_system/blob/test/Frontend/README.md)
