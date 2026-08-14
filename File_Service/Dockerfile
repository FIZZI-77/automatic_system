FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /file-service ./src/cmd/server

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /file-service /usr/local/bin/file-service
COPY --from=build /src/config.yaml /config.yaml
ENV CONFIG_FILE=/config.yaml
ENTRYPOINT ["file-service"]
