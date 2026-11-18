FROM golang:1.25-alpine

RUN apk add --no-cache bash git curl

RUN go install github.com/pressly/goose/v3/cmd/goose@v3.27.1

ENV PATH="/root/go/bin:${PATH}"

WORKDIR /migrations
