
FROM golang:1.25-alpine AS build

WORKDIR /app

RUN apk add --no-cache bash git

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY . .

RUN go build -o server ./src/cmd/server


FROM alpine:latest

WORKDIR /app

COPY --from=build /app/server .
COPY --from=build /app/config.yaml .

ENV PATH="/root/go/bin:/usr/local/go/bin:${PATH}"

CMD ["./server"]
