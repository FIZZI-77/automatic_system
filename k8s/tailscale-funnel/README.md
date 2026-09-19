# Tailscale Funnel

Funnel публикует frontend, REST API и WebSocket-трафик через входной шлюз
Istio по стабильному HTTPS-адресу узла `*.ts.net`. Покупка домена не нужна.
На рабочей машине должны быть установлены Tailscale и выполнен вход в tailnet.

Запуск из PowerShell с правами администратора:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\k8s\scripts\setup-tailscale-funnel.ps1
```

Скрипт включает Funnel к `http://127.0.0.1:80`, проверяет состояние Funnel и
локальные маршруты frontend, health и подтверждения почты, сохраняет адрес в
`.runtime/tailscale-funnel-url.txt` и синхронизирует `FRONTEND_BASE_URL` в
Auth Service.

Проверка состояния и отключение:

```powershell
& "$env:ProgramFiles\Tailscale\tailscale.exe" funnel status
& "$env:ProgramFiles\Tailscale\tailscale.exe" funnel reset
```

Funnel подходит для разработки и демонстрации. Доступность рабочей машины и
локального Kubernetes остаётся обязательной.
