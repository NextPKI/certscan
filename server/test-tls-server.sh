#!/bin/sh
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
    -keyout key.pem -out cert.pem \
    -subj "/C=DE/ST=Hessen/L=Frankfurt/O=TestCompany/OU=IT/CN=localhost"
openssl s_server -accept 4433 -cert cert.pem -key key.pem
