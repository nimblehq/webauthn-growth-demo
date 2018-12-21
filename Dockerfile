FROM golang:1.10.3-alpine

WORKDIR /go/src/app

RUN apk update && \
    apk upgrade && \
    apk add git

EXPOSE 8080

COPY . .
RUN go get -v ./...

ENTRYPOINT ["app"]