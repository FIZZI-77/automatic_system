FROM golang:1.25-alpine AS build
WORKDIR /src
COPY SLA_Service/go.mod SLA_Service/go.sum* ./SLA_Service/
WORKDIR /src/SLA_Service
RUN go mod download
WORKDIR /src
COPY SLA_Service ./SLA_Service
WORKDIR /src/SLA_Service
RUN CGO_ENABLED=0 go build -o /sla-service ./src/cmd/server
FROM alpine:3.22
RUN adduser -D -u 10001 app
COPY --from=build /sla-service /usr/local/bin/sla-service
COPY --from=build /src/SLA_Service/config.yaml /config.yaml
ENV CONFIG_FILE=/config.yaml
USER app
ENTRYPOINT ["sla-service"]
