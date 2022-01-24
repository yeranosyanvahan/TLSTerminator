FROM golang as build
RUN mkdir $GOPATH/proxy
WORKDIR /go/src
ADD ./ /go/src
RUN go mod init tlsterm
RUN go get
RUN go build -o bin/tlsterm

FROM debian
RUN mkdir -p /home/proxy && mkdir -p /usr/bin/ && mkdir -p /etc/tlsterm/certs
WORKDIR /home/proxy
RUN apt-get update && apt-get upgrade -y
RUN apt-get install openssl libssl-dev -y
ADD ./before_run.sh /home/proxy
COPY --from=build  /go/src/bin/tlsterm /usr/bin/tlsterm
ENTRYPOINT [ "/home/proxy/before_run.sh", "&&", "/usr/bin/" ]
