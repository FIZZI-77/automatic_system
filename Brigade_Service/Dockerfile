FROM golang:1.25-alpine AS build

WORKDIR /app

RUN apk add --no-cache ca-certificates bash git

COPY go.mod go.sum ./

RUN go mod download && \
    go mod verify

COPY . .

RUN go mod tidy
RUN go build -o server ./src/cmd/server

FROM alpine:3.21

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=build /app/server .
COPY --from=build /app/config.yaml .
CMD ["./server"]
