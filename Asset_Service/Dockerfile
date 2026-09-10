# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS builder

WORKDIR /src/Asset_Service

# Сначала только файлы зависимостей.
COPY Asset_Service/go.mod Asset_Service/go.sum* ./

# Кэш Go modules между Docker builds.
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Теперь исходники репозитория.
WORKDIR /src
COPY . .

WORKDIR /src/Asset_Service

# Отдельный cache компилятора Go.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /asset-service ./src/cmd/server


FROM alpine:3.22

RUN apk add --no-cache ca-certificates

COPY --from=builder /asset-service /usr/local/bin/asset-service
COPY --from=builder /src/Asset_Service/config.yaml /config.yaml

ENV CONFIG_FILE=/config.yaml

EXPOSE 50065

ENTRYPOINT ["/usr/local/bin/asset-service"]