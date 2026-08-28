FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY cmd ./cmd
COPY internal ./internal
COPY config.yaml ./config.yaml

RUN go build -trimpath -o /out/transponder-simulator ./cmd/simulator

FROM alpine:3.22
WORKDIR /app
COPY --from=build /out/transponder-simulator ./transponder-simulator
COPY routes ./routes
COPY --from=build /src/config.yaml ./config.yaml
USER 65532:65532
ENTRYPOINT ["./transponder-simulator"]
