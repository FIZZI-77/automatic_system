FROM golang:1.25-alpine AS builder
WORKDIR /src/Analytics_Service
COPY Analytics_Service/go.mod Analytics_Service/go.sum ./
RUN go mod download && go mod verify
COPY Analytics_Service .
RUN CGO_ENABLED=0 go build -o /analytics-service ./src/cmd/server
FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=builder /analytics-service /usr/local/bin/analytics-service
COPY --from=builder /src/Analytics_Service/config.yaml /config.yaml
ENV CONFIG_FILE=/config.yaml
EXPOSE 50063
ENTRYPOINT ["analytics-service"]
