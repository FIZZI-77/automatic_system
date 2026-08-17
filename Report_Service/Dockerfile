FROM golang:1.25-alpine AS builder
ENV GOWORK=off
WORKDIR /src
COPY Report_Service/go.mod Report_Service/go.sum* ./Report_Service/
WORKDIR /src/Report_Service
RUN --mount=type=cache,target=/go/pkg/mod go mod download
WORKDIR /src
COPY . .
WORKDIR /src/Report_Service
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -o /report-service ./src/cmd/server
FROM alpine:3.22
RUN apk add --no-cache ca-certificates font-dejavu
COPY --from=builder /report-service /usr/local/bin/report-service
COPY --from=builder /src/Report_Service/config.yaml /config.yaml
ENV CONFIG_FILE=/config.yaml
EXPOSE 50064 8084
ENTRYPOINT ["report-service"]
