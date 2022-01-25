# TLSTerminator

This is the simplest TLS Termination and Origination Proxy for encrypting network sockets with TLS offloading.
Generally, for unsecure applications there needs to be 2 proxies: one for encrypting(TLS Origination) and one for decypting(TLS TERMINATION).

The way it works is pretty simple.
## Getting Started
### TLS Origination Server
The best way to getting started is through docker [docker and docker-compose](https://docs.docker.com/engine/install/)

Create ```docker-compose.yaml``` file

    version: '3'
    services:
     tlsterminator:
      image: yeranosyanvahan/tlsterminator:latest
      volumes:
       - ./tlsterm.ini:/etc/tlsterm/tlsterm.ini
      links:
       - application
     application: # your application
      image: yourimage
      environment:
       - MYSQL_HOST=tlsterminator

Every time the container runs a new certificate and private key are generated in /etc/tlsterm/certs/ directory.
You MUST explicitly tell where are they located.
To do that Create ```tlsterm.ini``` file in the same location

    TLSIN=false
    TLSOUT=true
    
    SSLCRTOUTFILE="/etc/tlsterm/certs/server.crt"
    SSLKEYOUTFILE="/etc/tlsterm/certs/server.key"
    
    [:3306]
    Redirect="mysql@tlsterm.hostname:345"

You can write the IP address instead of tlsterm.hostname too
Finally Run ```docker-compose up``` command

Voila, you can access your mysql database from 345 port securely.
To do that you may need tlsterminator TLS Termination Server.

### TLS Termination Server
And here is the ```docker-compose.yaml``` File


    version: '3'
    services:
     tlsterminator:
      image: yeranosyanvahan/tlsterminator:latest
      ports:
       - 345:345
      volumes:
       - ./tlsterm.ini:/etc/tlsterm/tlsterm.ini
      links:
       - mysql

     mysql: # or any unsecure application
      image: mysql:5.7
      environment:
       - MYSQL_ALLOW_EMPTY_PASSWORD=1

For client proxy it is basically the same procedure.
You need to point redirect to the tlsterm proxy server.

    TLSIN=true
    TLSOUT=false

    SSLCRTINFILE="/etc/tlsterm/certs/server.crt"
    SSLKEYINFILE="/etc/tlsterm/certs/server.key"
    
    [mysql:345]
    Redirect="mysql:3306"

### Who is this for?
This respository is for people who want to access multiple instances of the database from the same endpoint.
For example if you have 10 databases you can setup proxy to get all the database from single :345 endpoint
