FROM golang as build
RUN mkdir $GOPATH/proxy
WORKDIR /go/src
ADD ./ /go/src
RUN go mod init fproxy
RUN go get
RUN go build -o bin/fproxy

FROM debian
RUN mkdir -p /home/proxy && mkdir -p /usr/bin/ && mkdir -p /etc/fproxy/certs
WORKDIR /home/proxy
RUN apt-get update && apt-get upgrade
RUN apt-get install openssl libssl-dev -y
RUN openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout /etc/fproxy/certs/server.key \
                -out /etc/fproxy/certs/server.crt -subj "/C=/ST=/L=/O=/OU=/CN="
COPY --from=build  /go/src/bin/fproxy /usr/bin/fproxy
ENTRYPOINT [ "/usr/bin/fproxy" ]
