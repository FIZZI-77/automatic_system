# CI/CD setup

Новый workflow заменяет старый `.github/workflows/ci.yml`.

## Branch mapping

- `pull_request -> main/master`: только CI, Docker images собираются, но не публикуются и deploy не выполняется.
- `feature/**`: CI + build/push GHCR + deploy в `development`.
- `main` или `master`: CI + build/push GHCR + deploy в `production`.

В текущем GitHub-репозитории на момент подготовки workflow существует `main`, а `master` не найден.
Workflow оставляет поддержку обоих имён, поэтому после переименования branch ничего менять не придётся.

## Что workflow теперь проверяет

- gofmt
- go vet
- `go test -race`
- Docker Compose config
- `local`, `dev`, `prod` Kustomize overlays
- client-side Kubernetes validation
- отсутствие `:dev`/`:latest` для собственных production application images
- сборку всех application images
- сборку всех migrator images
- ClickHouse init image

Старый CI проверял только часть Go-модулей и собирал только часть image matrix.
Новый workflow покрывает сервисы, которые уже присутствуют в актуальном `k8s`.

## GitHub Environments

Создай два GitHub Environment:

- `development`
- `production`

Для `production` рекомендуется включить Required reviewers.

В каждом Environment должны быть secrets:

### Required

`KUBECONFIG_B64`
: base64 содержимое kubeconfig нужного кластера.

`RUNTIME_ENV_B64`
: base64 содержимое env-файла в формате `KEY=value`, из которого создаётся `runtime-secrets`.

`JWT_PRIVATE_KEY_B64`
: base64 PEM private key для `jwt-private-key`.

`JWT_PUBLIC_KEY_B64`
: base64 PEM public key для `jwt-public-key`.

### Optional for private GHCR packages

`GHCR_PULL_USERNAME`
: GitHub user / machine user.

`GHCR_PULL_TOKEN`
: PAT с `read:packages`.

Если GHCR packages public, эти два secret не нужны.

## PowerShell: как получить Base64

Kubeconfig:

```powershell
[Convert]::ToBase64String(
  [IO.File]::ReadAllBytes("$HOME\.kube\config")
)
```

runtime.env:

```powershell
[Convert]::ToBase64String(
  [IO.File]::ReadAllBytes(".\runtime.env")
)
```

JWT private:

```powershell
[Convert]::ToBase64String(
  [IO.File]::ReadAllBytes(".\private.pem")
)
```

JWT public:

```powershell
[Convert]::ToBase64String(
  [IO.File]::ReadAllBytes(".\public.pem")
)
```

## GHCR permissions

Workflow использует:

```yaml
permissions:
  contents: read
  packages: write
```

и `GITHUB_TOKEN` для публикации packages из Actions.

Имена packages согласованы с prod/dev overlays:

```text
ghcr.io/fizzi-77/automatic-system-api-gateway
ghcr.io/fizzi-77/automatic-system-auth
...
ghcr.io/fizzi-77/automatic-system-location
...
```

Каждый push получает immutable tag:

```text
sha-<12 символов commit SHA>
```

Дополнительно публикуется branch tag для удобства просмотра, но Kubernetes overlays используют только immutable SHA.

## Порядок deploy

Deploy выполняется фазами:

1. namespace;
2. secrets;
3. infra;
4. ожидание Ready;
5. удаление старых migration Jobs;
6. создание migration Jobs с новым image tag;
7. ожидание `Complete`;
8. apps;
9. ожидание rollout;
10. для production — NetworkPolicy.

Это сделано специально: обычный `kubectl apply -k overlays/...` одновременно запускает infra, migrations и приложения,
а Kubernetes Job нельзя просто обновить новым Pod template после выполнения — template Job immutable.

## Важный момент по production promotion

Сейчас `main/master` build заново публикует image для SHA production commit.

Это безопасная первая версия CI/CD, но следующий уровень зрелости — promotion by digest:
feature build -> проверенный digest -> prod использует ТОТ ЖЕ digest без rebuild.

Это можно добавить после того, как dev/prod pipeline стабильно заработает.

## Проверка workflow до push

После замены файлов:

```powershell
git diff -- .github\workflows\ci.yml
kubectl kustomize .\k8s\overlays\dev > $null
kubectl kustomize .\k8s\overlays\prod > $null
```

После push открой Actions и проверь matrix jobs.

## Рекомендуемая branch protection

Для `main`/`master`:

- Require pull request before merging
- Require status checks:
  - Go jobs
  - Validate Docker Compose
  - Validate Kubernetes overlays
  - image build jobs
- Require branch to be up to date
- Block force push

Для production GitHub Environment:

- Required reviewers
- Prevent self-review (если доступно на плане)
