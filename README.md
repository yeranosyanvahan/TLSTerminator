# TLSTerminator

This is the simplest TLS Termination and Origination Proxy for encrypting EVERY network connection with TLS offloading.
It requires 2 proxies to be set up: one on the client side and the other is supposed to go on a server.

It is now in development.
The way it works is pretty simple.


On server side create a **docker-compose.yaml** file

## Getting Started
The best way to getting started is through docker [docker and docker-compose](https://docs.docker.com/engine/install/)

Create ```docker-compose.yaml``` file

    version: '3'
    services:
     rproxy:
      image: yeranosyanvahan/rproxy:0.1.0
      ports:
       - 234:234
      volumes:
       - ./rproxy.ini:/etc/rproxy/rproxy.ini
      links:
       - mysql

     mysql: # or any other application
      image: mysql:5.7
      environment:
       - MYSQL_ALLOW_EMPTY_PASSWORD=1

Also you need to specify configuration
To do that Create ```rproxy.ini``` file in the same location

    SSLCertificateFile="/etc/rproxy/certs/server.crt"
    SSLCertificateKeyFile="/etc/rproxy/certs/server.key"
    Listen=234
    [mysql5.7]
    Redirect="mysql:3306"

Finally Run ```docker-compose up``` command

Voila, you can access your mysql database from 234 port securely
However, you need to specify mysql5.7 as the hostname you are trying to connect to

### Client Side
For client proxy it is basically the same procedure.

    SSLCertificateFile="/etc/fproxy/certs/server.crt"
    SSLCertificateKeyFile="/etc/fproxy/certs/server.key"
    Listen: 345
    Redirect="rproxy:234"

You need to point redirect to the rproxy server.
And here is the ```docker-compose.yaml``` File

    version: '3'
    services:
     fproxy:
      image: yeranosyanvahan/fproxy:0.1.0
      volumes:
       - ./rproxy.ini:/etc/fproxy/fproxy.ini
      links:
       - application

     application: # your application
      image: yourimage
      environment:
       - MYSQL_HOST=fproxy
       - MYSQL_PORT=345

### Who is this for?
This respository is for people who want to access multiple instances of the database from the same endpoint.
For example if you have 10 databases you can setup proxy to get all the database from single database:234 endpoint
