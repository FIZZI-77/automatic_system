FROM golang:1.25-alpine AS build
WORKDIR /src
COPY Dispatch_Service/go.mod Dispatch_Service/go.sum ./
RUN go mod download
COPY Dispatch_Service/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /dispatch ./src/cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /dispatch /dispatch
COPY --from=build /src/config.yaml /config.yaml
EXPOSE 50058
ENV CONFIG_FILE=/config.yaml
ENTRYPOINT ["/dispatch"]
