#!/bin/bash

openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout /etc/tlsterm/certs/server.key -out /etc/tlsterm/certs/server.crt -subj "/C=/ST=/L=/O=/OU=/CN="
/usr/bin/tlsterm
