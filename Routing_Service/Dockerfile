FROM golang:1.25-alpine AS build
WORKDIR /workspace
COPY --from=contracts . /contracts
COPY --from=service . /service
WORKDIR /service
RUN go mod edit -replace github.com/FIZZI-77/automatic-system-contracts=/contracts && CGO_ENABLED=0 go build -o /routing ./src/cmd/server

FROM alpine:3.22
RUN adduser -D -H routing
USER routing
COPY --from=build /routing /routing
EXPOSE 50057
ENTRYPOINT ["/routing"]
