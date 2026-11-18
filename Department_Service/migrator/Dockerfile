FROM golang:1.25-alpine

RUN apk add --no-cache git
RUN go install github.com/pressly/goose/v3/cmd/goose@v3.27.1

WORKDIR /migrations

CMD ["goose", "up"]
