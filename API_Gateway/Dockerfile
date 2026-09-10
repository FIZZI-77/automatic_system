FROM golang:1.25-alpine AS builder

WORKDIR /workspace

COPY API_Gateway /gateway

WORKDIR /gateway

RUN go mod download && go mod verify
RUN CGO_ENABLED=0 go build -o /api-gateway ./src/cmd/server

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app -u 10001 app

WORKDIR /app

COPY --from=builder /api-gateway /app/api-gateway
COPY --from=builder /gateway/config.yaml /app/config.yaml

EXPOSE 8081

USER 10001:10001
CMD ["/app/api-gateway"]
