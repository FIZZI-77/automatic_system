FROM golang:1.25-alpine AS build

WORKDIR /app

# Установка необходимых инструментов
RUN echo "http://nl.alpinelinux.org/alpine/v3.21/main" > /etc/apk/repositories && \
    echo "http://nl.alpinelinux.org/alpine/v3.21/community" >> /etc/apk/repositories && \
    apk add --no-cache ca-certificates bash git

COPY go.mod go.sum ./

# Загрузка всех зависимостей с проверкой
RUN go mod download && \
    go mod verify

# Копирование всего кода
COPY . .

# Дополнительная загрузка недостающих зависимостей
RUN go get -d ./... && \
    go mod tidy

# Сборка приложения
RUN go build -o server ./src/cmd/server

FROM alpine:3.21

WORKDIR /app

RUN echo "http://nl.alpinelinux.org/alpine/v3.21/main" > /etc/apk/repositories && \
    echo "http://nl.alpinelinux.org/alpine/v3.21/community" >> /etc/apk/repositories && \
    apk add --no-cache ca-certificates

COPY --from=build /app/server .
COPY --from=build /app/.env .

ENV PATH="/root/go/bin:/usr/local/go/bin:${PATH}"



CMD ["./server"]