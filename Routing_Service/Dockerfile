FROM golang:1.25-alpine AS build
WORKDIR /workspace
COPY --from=service . /service
WORKDIR /service
RUN CGO_ENABLED=0 go build -o /routing ./src/cmd/server

FROM alpine:3.22
RUN adduser -D -H routing
USER routing
COPY --from=build /routing /routing
COPY --from=build /service/config.yaml /config.yaml
EXPOSE 50057
ENTRYPOINT ["/routing"]
