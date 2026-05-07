FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY API_Gateway ./API_Gateway
COPY Auth_Service ./Auth_Service

WORKDIR /app/API_Gateway

RUN go mod download

RUN go build -o /api-gateway ./src/cmd/server

FROM alpine:3.20

WORKDIR /app

COPY --from=builder /api-gateway /app/api-gateway

EXPOSE 8081

CMD ["/app/api-gateway"]