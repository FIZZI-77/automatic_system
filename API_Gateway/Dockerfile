FROM golang:1.25-alpine AS builder

WORKDIR /workspace

COPY API_Gateway /gateway

WORKDIR /gateway

RUN go mod download && go mod verify
RUN CGO_ENABLED=0 go build -o /api-gateway ./src/cmd/server

FROM alpine:3.20

WORKDIR /app

COPY --from=builder /api-gateway /app/api-gateway

EXPOSE 8081

CMD ["/app/api-gateway"]
