FROM golang:1.25-alpine AS build
WORKDIR /workspace
COPY --from=service . /service
WORKDIR /service
RUN CGO_ENABLED=0 go build -o /location ./src/cmd/server

FROM alpine:3.22
RUN adduser -D -H location
USER location
COPY --from=build /location /location
COPY --from=build /service/config.yaml /config.yaml
EXPOSE 50056 8080
ENTRYPOINT ["/location"]
