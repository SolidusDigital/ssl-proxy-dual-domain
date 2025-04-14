FROM golang:1.18.3-alpine
WORKDIR /go/src/github.com/suyashkumar/ssl-proxy
RUN apk add --no-cache make git zip
COPY . .
RUN make release
