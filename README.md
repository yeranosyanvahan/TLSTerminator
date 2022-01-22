# TLSTerminator

This is the simplest TLS Termination and Origination Proxy for encrypting EVERY network connection with TLS offloading.
It requires 2 proxies to be set up: one on the client side and the other is supposed to go on a server.

It is now in development.
The way it works is pretty simple


On server side create a **docker-compose.yaml** file 

## Getting Started
The best way to getting started is through docker [docker and docker-compose](https://docs.docker.com/engine/install/)

Create ```docker-compose.yaml``` file

    version: '3'
    services:
     rproxy:
      image: yeranosyanvahan/rproxy
      ports:
       - 234:234 
      volumes:
       - ./rproxy.ini:/etc/rproxy/rproxy.ini
      links:
       - mysql

     mysql: # or any other application
      image: mysql
      environment:
       - MYSQL_ALLOW_EMPTY_PASSWORD=1
       
Also you need to specify configuration
To do that Create ```rproxy.ini``` file in the same location

    SSLCertificateFile="/etc/rproxy/certs/server.crt"
    SSLCertificateKeyFile="/etc/rproxy/certs/server.key"
    Redirect="mysql:3306"
    Listen=234
Finally Run ```docker-compose up``` command

Voila, you can access your mysql database from 234 port securely


The client proxy is note implemented yet.

