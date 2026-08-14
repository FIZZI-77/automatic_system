FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY Report_Service/go.mod Report_Service/go.sum* ./Report_Service/
COPY . .
WORKDIR /src/Report_Service
RUN go mod download && CGO_ENABLED=0 go build -o /report-service ./src/cmd/server
FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=builder /report-service /usr/local/bin/report-service
COPY --from=builder /src/Report_Service/config.yaml /config.yaml
ENV CONFIG_FILE=/config.yaml
EXPOSE 50064
ENTRYPOINT ["report-service"]
