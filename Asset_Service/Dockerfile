FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY Asset_Service/go.mod Asset_Service/go.sum* ./Asset_Service/
COPY . .
WORKDIR /src/Asset_Service
RUN go mod download && CGO_ENABLED=0 go build -o /asset-service ./src/cmd/server
FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=builder /asset-service /usr/local/bin/asset-service
COPY --from=builder /src/Asset_Service/config.yaml /config.yaml
ENV CONFIG_FILE=/config.yaml
EXPOSE 50065
ENTRYPOINT ["asset-service"]
