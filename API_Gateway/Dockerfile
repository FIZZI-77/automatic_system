FROM golang:1.25-alpine AS builder

WORKDIR /app

WORKDIR /app/API_Gateway

COPY API_Gateway/go.mod API_Gateway/go.sum ./
RUN go mod download && go mod verify

COPY API_Gateway ./

RUN go mod tidy
RUN go build -o /api-gateway ./src/cmd/server

FROM alpine:3.20

WORKDIR /app

COPY --from=builder /api-gateway /app/api-gateway

EXPOSE 8081

CMD ["/app/api-gateway"]
