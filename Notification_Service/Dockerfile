FROM golang:1.25-alpine AS build
WORKDIR /src/Notification_Service
COPY Notification_Service/go.mod Notification_Service/go.sum* ./
RUN go mod download
COPY Notification_Service ./
RUN CGO_ENABLED=0 go build -o /notification-service ./src/cmd/server
FROM alpine:3.22
RUN adduser -D -u 10001 app && apk add --no-cache ca-certificates
COPY --from=build /notification-service /usr/local/bin/notification-service
COPY --from=build /src/Notification_Service/config.yaml /config.yaml
ENV CONFIG_FILE=/config.yaml
USER app
ENTRYPOINT ["notification-service"]
