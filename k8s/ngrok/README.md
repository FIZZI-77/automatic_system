# ngrok Tunnel

Туннель публикует единый HTTPS URL для Frontend, REST API и WebSocket через
Istio ingress. Бесплатный аккаунт ngrok и authtoken обязательны.

Запуск:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\k8s\scripts\setup-ngrok-tunnel.ps1
```

Authtoken вводится скрыто и сохраняется только в Secret `ngrok-authtoken`.
Текущий URL записывается в `.runtime/ngrok-url.txt`. Фоновый watcher следит за
перезапусками агента и обновляет `FRONTEND_BASE_URL` Auth Service.

Проверка:

```powershell
kubectl -n automatic-system get deployment,pod -l app.kubernetes.io/name=ngrok-tunnel
kubectl -n automatic-system logs deployment/ngrok-tunnel --tail=100
Get-Content .\.runtime\ngrok-url.txt
```

