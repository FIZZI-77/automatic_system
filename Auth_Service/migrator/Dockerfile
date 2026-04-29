FROM golang:1.25-alpine

RUN apk add --no-cache bash git curl

RUN go install github.com/pressly/goose/v3/cmd/goose@latest

ENV PATH="/root/go/bin:${PATH}"

WORKDIR /migrations

