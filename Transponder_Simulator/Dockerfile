FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -o /out/transponder-simulator ./cmd/simulator

FROM alpine:3.22
WORKDIR /app
COPY --from=build /out/transponder-simulator ./transponder-simulator
COPY routes ./routes
USER 65532:65532
ENTRYPOINT ["./transponder-simulator"]
