# Архитектура Automatic City Services

Откройте [интерактивную карту](diagrams.html) в браузере из локальной копии
репозитория. Для работы схем достаточно браузера с JavaScript.

| Схема | Что можно посмотреть |
|---|---|
| [Архитектура](diagrams.html#architecture) | Весь прикладной контур, входы, 15 Go-сервисов за шлюзом, Kafka, хранилища и внешние интеграции. Нажмите на компонент, чтобы увидеть его прямые связи. |
| [Kafka](diagrams.html#kafka) | Выберите предметный, retry- или DLQ-топик. Схема покажет издателей, читателей и группы. |
| [Топология local-ha](local-ha.html) | Одна схема Kubernetes с отдельными pod, точками подключения, физическими хранилищами, наблюдаемостью и доставкой. Колесо или щипок меняет масштаб, перетаскивание двигает схему. |

В детальных схемах раскрывается список связей со ссылками на исходники.
Те же связи описаны в [таблицах взаимодействий](code-interactions.md),
которые можно читать прямо на GitHub.

После изменения вызовов, топиков или конфигурации обновите
[данные схем](connections.js) и соответствующие таблицы. Устройство кластера
описано в [документации Kubernetes](../../k8s/docs/deployment.md).

## Топология local-ha

[Открыть схему в браузере](local-ha.html). Она работает из локальной копии
без подключения к кластеру. «Вся схема» возвращает общий вид, «1:1» показывает
фактический размер. Стрелки на клавиатуре двигают полотно, `+` и `−` меняют
масштаб, `0` возвращает общий вид.

Схема показывает состояние по манифестам на коммите `a74467c`. В нём
75 постоянных pod основной конфигурации, включая 33 прикладных экземпляра:
один Frontend, два API Gateway и по два у каждого из 15 Go-сервисов.
Filebeat и Node Exporter создают по одному pod на подходящий узел.
Фактические имена pod Deployment, количество узлов, текущие роли Patroni
и Redis и временные реплики во время rollout определяет работающий кластер.
Дополнительные установки помечены пунктиром. Для istiod и ingress показана
минимальная конфигурация HPA из Istio 1.30.3.

### Источники

- Прикладные экземпляры и порты. [Helm values](../../k8s/helm/applications/values.yaml) · [Переопределения local-ha](../../k8s/helm/applications/values-local-ha.yaml) · [Конфигурация Flux](../../k8s/flux/clusters/local-ha/applications-release.yaml)
- Хранилища, брокеры и наблюдаемость. [Инфраструктура local-ha](../../k8s/overlays/local-ha/kustomization.yaml) · [Overlay support](../../k8s/overlays/local-ha/support/kustomization.yaml) · [PostgreSQL HA](../../k8s/docs/postgres-ha.md)
- Вход, маршруты и телеметрия. [Istio Operator](../../k8s/mesh/istio-operator.yaml) · [Ingress](../../k8s/mesh/ingress/routes.yaml) · [Istio 1.30.3 discovery](https://github.com/istio/istio/blob/1.30.3/manifests/charts/istio-control/istio-discovery/values.yaml) · [Istio 1.30.3 ingress](https://github.com/istio/istio/blob/1.30.3/manifests/charts/gateways/istio-ingress/values.yaml) · [Точки вызова в коде](code-interactions.md)
- Симуляторы подключаются отдельно. В их overlay сейчас задан адрес
  `location-service:8080`, а Helm публикует телеметрию на
  `location-service-http:8080`. На схеме показано подключение после выбора
  этого HTTP Service. [Overlay симуляторов](../../k8s/optional/transponders/kustomization.yaml) · [Helm Location](../../k8s/helm/applications/templates/services/location.yaml)
