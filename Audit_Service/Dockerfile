FROM golang:1.25-alpine AS builder
WORKDIR /src/Audit_Service
COPY Audit_Service/go.mod Audit_Service/go.sum ./
RUN go mod download && go mod verify
COPY Audit_Service .
RUN CGO_ENABLED=0 go build -o /audit-service ./src/cmd/server

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=builder /audit-service /usr/local/bin/audit-service
COPY --from=builder /src/Audit_Service/config.yaml /config.yaml
ENV CONFIG_FILE=/config.yaml
EXPOSE 50062
ENTRYPOINT ["audit-service"]
