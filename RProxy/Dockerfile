FROM golang as build
RUN mkdir $GOPATH/proxy
WORKDIR /go/src
ADD ./ /go/src
RUN go mod init rproxy
RUN go get
RUN go build -o bin/rproxy

FROM debian
RUN mkdir -p /home/proxy && mkdir -p /usr/bin/ && mkdir -p /etc/rproxy/certs
WORKDIR /home/proxy
RUN apt-get update && apt-get upgrade
RUN apt-get install openssl libssl-dev -y
RUN openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout /etc/rproxy/certs/server.key \
                -out /etc/rproxy/certs/server.crt -subj "/C=/ST=/L=/O=/OU=/CN="
COPY --from=build  /go/src/bin/rproxy /usr/bin/rproxy
ENTRYPOINT [ "/usr/bin/rproxy" ]
